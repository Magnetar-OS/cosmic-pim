// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0
//
// Derived from `apps/desktop/src-tauri/src/atomic_write.rs` in the Anasa
// project (https://github.com/entro314-labs/anasa), MIT licensed. The original
// copyright and permission notice are retained in the NOTICE file at the root
// of this repository, as that licence requires. Do not remove it.

//! Crash-safe file replacement: temp file → `fsync` → atomic `rename` → `fsync`
//! the directory, with an optional optimistic-concurrency guard.
//!
//! A plain `fs::write` to the target leaves a window in which a crash, a full
//! disk, or a battery dying mid-write truncates the file to a partial document.
//! For a `.ics` that is not a cosmetic problem: a half-written VEVENT is an
//! unparseable file, and the event is gone from the user's calendar.
//!
//! Three properties, each of which fixes a distinct failure:
//!
//! 1. **Temp-then-rename** — a reader (vdirsyncer, khal, our own watcher) sees
//!    either the old file or the complete new one, never a torn write. The temp
//!    lives in the *same directory* as the target so the rename is guaranteed
//!    intra-filesystem, and therefore atomic; a temp in `$TMPDIR` could land on
//!    a different mount where `rename` degrades to copy-then-delete.
//!
//! 2. **`fsync` the file, then `fsync` the directory** — this is the part the
//!    donor implementation was missing. `sync_all` on the temp gets the *data*
//!    to the platter, but the rename itself is a directory-metadata operation
//!    that lives in its own journal. Without the second sync, a power loss just
//!    after a successful `rename` can leave the directory entry pointing at the
//!    old inode, or at nothing — the classic "fsync the file, lose the name"
//!    bug. Both syncs are needed for the write to actually be durable.
//!
//! 3. **Optimistic concurrency** — when the caller passes the `(size, mtime)`
//!    it read the file at, the target is re-`stat`ed immediately before the
//!    rename and the write is refused if it drifted. This turns a silent
//!    last-writer-wins clobber (us overwriting a change vdirsyncer pulled down
//!    between our read and our write) into an explicit [`Error::ModifiedSince`]
//!    the caller can reconcile. The incoming content is preserved as a sibling
//!    conflict copy, so *neither* version is lost.
//!
//! Point 3 is what makes this a prerequisite for CalDAV sync rather than a
//! nice-to-have: the sync engine and the editor write the same files, and
//! "whoever called `write` last wins" silently destroys the loser's edit.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The `(size, mtime)` a caller read a file at, used as a concurrency token.
///
/// `mtime` is whole seconds since the Unix epoch. Second resolution is
/// deliberate: it is the coarsest thing every filesystem we care about agrees
/// on, and pairing it with `size` makes an undetected collision require a
/// same-second edit that also preserves the byte count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileState {
    /// File length in bytes at read time.
    pub size: u64,
    /// Last-modified time, whole Unix seconds, at read time.
    pub mtime: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Io(#[from] std::io::Error),

    /// The target changed on disk between the caller's read and this write.
    ///
    /// The target is left untouched. The content this call was asked to write
    /// has been preserved at `conflict`, so the caller can diff, merge, or
    /// discard rather than having silently lost one side.
    #[error(
        "{target} changed on disk since it was read; the incoming version was kept as {conflict}"
    )]
    ModifiedSince { target: PathBuf, conflict: PathBuf },

    #[error("atomic write target has no parent directory: {0}")]
    NoParent(PathBuf),

    #[error("atomic write target has no file name: {0}")]
    NoFileName(PathBuf),
}

/// Current `(size, mtime)` of `path`, or `None` if it does not exist.
///
/// A missing file is not an error: callers legitimately write files they expect
/// to be absent. `Err` is reserved for a real `stat` failure on a path that is
/// there.
pub fn state_of(path: &Path) -> Result<Option<FileState>, Error> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };

    Ok(Some(FileState {
        size: metadata.len(),
        // A file whose mtime predates the epoch or overflows i64 is not worth
        // failing a write over; it just cannot participate in the concurrency
        // check, and 0 will simply never match a later real stat.
        mtime: metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .unwrap_or(0),
    }))
}

/// Sibling temp path for `target`: `<dir>/.<name>.tmp`.
///
/// The leading dot matters beyond tidiness: the vdir watcher skips
/// `.*.tmp`, so staging a write here does not wake the UI for a file that is
/// about to be renamed away.
fn temp_path_for(target: &Path) -> Result<PathBuf, Error> {
    let parent = target
        .parent()
        .ok_or_else(|| Error::NoParent(target.to_path_buf()))?;
    let name = target
        .file_name()
        .ok_or_else(|| Error::NoFileName(target.to_path_buf()))?;
    Ok(parent.join(format!(".{}.tmp", name.to_string_lossy())))
}

/// Sibling conflict path for `target`: `<name>.<unix-seconds>.conflict`.
///
/// The original extension is deliberately **not** re-appended. Anasa's version
/// preserves it (`note.md.conflict-…-1718700000.md`) so the orphan still opens
/// as markdown, but in a vdir that would be actively harmful: a file ending
/// `.ics` is read back as an event by `store::vdir::read_collection` and would
/// resurrect the losing version as a duplicate on the user's calendar. Ending
/// in `.conflict` keeps the bytes recoverable while staying invisible to both
/// the collection reader and the watcher.
fn conflict_path_for(target: &Path) -> Result<PathBuf, Error> {
    let parent = target
        .parent()
        .ok_or_else(|| Error::NoParent(target.to_path_buf()))?;
    let name = target
        .file_name()
        .ok_or_else(|| Error::NoFileName(target.to_path_buf()))?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();

    // A second write in the same second must not overwrite the first conflict
    // copy — that would lose exactly what this mechanism exists to preserve.
    let mut candidate = parent.join(format!("{}.{stamp}.conflict", name.to_string_lossy()));
    let mut n = 2;
    while candidate.exists() {
        candidate = parent.join(format!("{}.{stamp}-{n}.conflict", name.to_string_lossy()));
        n += 1;
    }
    Ok(candidate)
}

/// `fsync` a directory so a rename within it is durable.
///
/// Best-effort by design: some filesystems (and every Windows build) reject
/// opening a directory for sync, and failing an otherwise-successful write over
/// it would be worse than the durability we are trying to buy.
fn sync_dir(dir: &Path) {
    if let Ok(handle) = fs::File::open(dir) {
        let _ = handle.sync_all();
    }
}

/// Writes `contents` to `target`, atomically and durably.
///
/// When `expected` is `Some`, the target's `(size, mtime)` must still match it
/// immediately before the rename; on divergence the incoming `contents` are
/// preserved in a sibling `.conflict` file and [`Error::ModifiedSince`] is
/// returned with `target` left exactly as the other writer left it.
///
/// Returns the file's state after the write, so a caller holding a concurrency
/// token can refresh it without a second `stat`.
pub fn write(
    target: &Path,
    contents: &str,
    expected: Option<FileState>,
) -> Result<FileState, Error> {
    write_bytes(target, contents.as_bytes(), expected)
}

/// [`write`] for content that is not text.
///
/// The iCalendar and vCard writers hand this a `&str` because their formats are
/// defined over characters. A stored mail message is not: RFC 5322 is a byte
/// format, bodies arrive in every legacy charset there has ever been, and 8-bit
/// MIME is not required to be valid UTF-8 anywhere. Routing those bytes through
/// a `&str` would mean either a lossy conversion — silently corrupting the
/// message *and* invalidating its DKIM signature — or refusing to store mail
/// that every other client handles.
pub fn write_bytes(
    target: &Path,
    contents: &[u8],
    expected: Option<FileState>,
) -> Result<FileState, Error> {
    let parent = target
        .parent()
        .ok_or_else(|| Error::NoParent(target.to_path_buf()))?;
    if !parent.exists() {
        fs::create_dir_all(parent)?;
    }

    let temp_path = temp_path_for(target)?;

    // Write and flush the temp file to stable storage before it is a candidate
    // for the rename. `fs::write` alone would only reach the page cache.
    {
        let mut file = fs::File::create(&temp_path)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }

    // The concurrency check happens as late as possible — after the expensive
    // write, immediately before the swap — to make the TOCTOU window as small
    // as it can be without filesystem locking.
    if let Some(expected_state) = expected
        && state_of(target)? != Some(expected_state)
    {
        let conflict = conflict_path_for(target)?;
        // The temp already holds the incoming bytes, fsynced. Promote it rather
        // than re-writing, so the conflict copy costs nothing extra.
        if let Err(why) = fs::rename(&temp_path, &conflict) {
            let _ = fs::remove_file(&temp_path);
            return Err(Error::Io(std::io::Error::other(format!(
                "{} changed on disk and the incoming version could not be preserved as {}: {why}",
                target.display(),
                conflict.display()
            ))));
        }
        sync_dir(parent);
        tracing::warn!(
            target = %target.display(),
            conflict = %conflict.display(),
            "write conflict: target changed on disk, incoming version preserved"
        );
        return Err(Error::ModifiedSince {
            target: target.to_path_buf(),
            conflict,
        });
    }

    fs::rename(&temp_path, target).inspect_err(|_| {
        // Best-effort cleanup so a failed rename does not strand the temp file
        // in the collection.
        let _ = fs::remove_file(&temp_path);
    })?;

    // Without this the rename can be lost on power failure even though the file
    // contents were synced — see the module docs.
    sync_dir(parent);

    state_of(target)?.ok_or_else(|| {
        Error::Io(std::io::Error::other(
            "file vanished immediately after a successful atomic write",
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn writes_a_new_file_and_reports_its_state() {
        let d = dir();
        let target = d.path().join("event.ics");

        let state = write(&target, "hello", None).expect("write");

        assert_eq!(fs::read_to_string(&target).unwrap(), "hello");
        assert_eq!(state.size, 5);
    }

    #[test]
    fn leaves_no_temp_file_behind() {
        let d = dir();
        let target = d.path().join("event.ics");
        write(&target, "hello", None).unwrap();

        let strays: Vec<_> = fs::read_dir(d.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(strays.is_empty(), "temp file left behind: {strays:?}");
    }

    #[test]
    fn overwrites_when_the_expected_state_still_matches() {
        let d = dir();
        let target = d.path().join("event.ics");

        let first = write(&target, "v1", None).expect("v1");
        let second = write(&target, "v2-longer", Some(first)).expect("v2");

        assert_eq!(fs::read_to_string(&target).unwrap(), "v2-longer");
        assert_eq!(second.size, "v2-longer".len() as u64);
    }

    #[test]
    fn refuses_to_clobber_a_drifted_file_and_keeps_both_versions() {
        let d = dir();
        let target = d.path().join("event.ics");
        let snapshot = write(&target, "ours", None).expect("initial");

        // Simulate vdirsyncer pulling down a server-side change between our
        // read and our write.
        fs::write(&target, "theirs-from-the-server").unwrap();

        let result = write(&target, "ours-edited", Some(snapshot));

        let Err(Error::ModifiedSince { conflict, .. }) = result else {
            panic!("expected ModifiedSince, got {result:?}");
        };
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "theirs-from-the-server",
            "the external change was clobbered"
        );
        assert_eq!(
            fs::read_to_string(&conflict).unwrap(),
            "ours-edited",
            "the incoming edit was lost"
        );
    }

    #[test]
    fn a_conflict_copy_is_not_mistaken_for_calendar_data() {
        let d = dir();
        let target = d.path().join("event.ics");
        let snapshot = write(&target, "ours", None).unwrap();
        fs::write(&target, "theirs").unwrap();

        let Err(Error::ModifiedSince { conflict, .. }) =
            write(&target, "ours-edited", Some(snapshot))
        else {
            panic!("expected a conflict");
        };

        // This is the property that keeps a conflict copy from resurfacing as a
        // duplicate event: `read_collection` only reads `*.ics`.
        let name = conflict.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            !name.ends_with(".ics"),
            "conflict copy would be read back as an event: {name}"
        );
        assert!(name.ends_with(".conflict"), "unexpected name: {name}");
    }

    #[test]
    fn two_conflicts_in_the_same_second_do_not_overwrite_each_other() {
        let d = dir();
        let target = d.path().join("event.ics");

        let mut conflicts = Vec::new();
        for incoming in ["first-loser", "second-loser"] {
            let snapshot = write(&target, "base", None).unwrap();
            fs::write(&target, "external").unwrap();
            let Err(Error::ModifiedSince { conflict, .. }) =
                write(&target, incoming, Some(snapshot))
            else {
                panic!("expected a conflict");
            };
            conflicts.push((conflict, incoming));
        }

        assert_ne!(conflicts[0].0, conflicts[1].0, "same-second collision");
        for (path, expected) in conflicts {
            assert_eq!(fs::read_to_string(&path).unwrap(), expected);
        }
    }

    #[test]
    fn writing_a_fresh_file_with_an_expectation_of_absence_succeeds() {
        let d = dir();
        let target = d.path().join("new.ics");
        // `expected: None` means "no opinion", which must not be confused with
        // "expected to be absent" — the latter has no representation and the
        // write simply proceeds.
        assert!(write(&target, "x", None).is_ok());
    }

    #[test]
    fn state_of_a_missing_file_is_none_not_an_error() {
        let d = dir();
        assert!(state_of(&d.path().join("nope.ics")).unwrap().is_none());
    }

    #[test]
    fn creates_missing_parent_directories() {
        let d = dir();
        let target = d.path().join("nested/deeper/event.ics");
        write(&target, "x", None).expect("should create parents");
        assert_eq!(fs::read_to_string(&target).unwrap(), "x");
    }
}
