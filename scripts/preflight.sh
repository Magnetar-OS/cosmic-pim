#!/usr/bin/env bash
# Checks that read files rather than building them, kept in one place because
# CI and the justfile both need them and two copies of a rule drift.
#
# Each prints what it compared rather than a verdict: a check that says only
# PASS cannot be audited, and one that says only FAIL reads as a finding about
# the repository when the checker itself is broken. Both happened while these
# were being written.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

# The path sweep runs first. It is the only check that can explain a missing
# input, and the others read files — so with it last, deleting
# rust-toolchain.toml produced `grep: No such file or directory` and exit 2
# instead of naming the file. An early check crashing hides the later one
# that had the answer.
# A file a build or a workflow names by *path* has two ways to be wrong, and
# they need opposite checks.
#
# Present but not committed: the tree satisfies the reference for everyone on
# this machine and for nobody who clones. That shape kept a sibling
# repository's HEAD from compiling for twenty commits.
#
# Named but absent: a rename or a deletion nothing else reaches. The first
# draft of this check skipped absent paths, on the reasoning that one is
# "either generated or already a loud failure" — which was a comment asserting
# a property rather than a check establishing one, in a script written to stop
# exactly that. It is false for the interesting case: `dovecot.conf` is named
# by one CI job, opened by no build and no test, so its deletion is silent
# until that job runs on a push.
# Leading dot allowed, and a shell-variable prefix stripped: without the
# first, `.github/workflows/ci.yml` arrives as `github/...`; without the
# second, ci.yml's `$PWD/crates/...` arrives as `PWD/crates/...`. Both then
# match nothing in the repository and are silently skipped — which is how
# widening this pattern quietly dropped the coverage the narrow version had.
referenced=$(grep -ohE '\$?[A-Za-z0-9_.][A-Za-z0-9_./-]*\.(toml|sh|conf|yml|yaml|json|lock|md|rs)' \
    .github/workflows/ci.yml justfile scripts/preflight.sh 2>/dev/null \
    | sed -e 's|^\$||' -e 's|^PWD/||' -e 's|^\./||' | sort -u)

# Which of those are repository paths at all. A name is one if git knows it or
# the working tree has it; anything else — /etc/dovecot/dovecot.conf inside a
# container, /tmp/radicale.conf a CI step writes — is neither, and skipping it
# needs no exception list. That union is also what makes deletion visible: a
# path git knows and the tree lacks has been removed, which the earlier
# version could not distinguish from a path that was never ours.
untracked=""
absent=""
for path in $referenced; do
    tracked=no
    # Index, or HEAD. A `git rm`'d file is in neither the index nor the tree,
    # and without asking HEAD it stops looking like a repository path at all
    # — so the check would skip the very case it exists for: a file removed
    # while configuration still names it.
    git ls-files --error-unmatch "$path" >/dev/null 2>&1 && tracked=yes
    git cat-file -e "HEAD:$path" 2>/dev/null && tracked=yes
    if [ "$tracked" = yes ] && [ ! -e "$path" ]; then
        absent="$absent $path"
    elif [ "$tracked" = no ] && [ -e "$path" ] && git check-ignore -q "$path"; then
        : # ignored build output that happens to match, not a reference
    elif [ "$tracked" = no ] && [ -e "$path" ]; then
        untracked="$untracked $path"
    fi
done
# The membership rule above — ours if git knows it, HEAD has it, or the tree
# does — is what lets this run without an exception list for generated files
# like .cargo/config.toml. Its price is that a path *never created* satisfies
# none of the three and is therefore skipped, so a typo in a `run:` line
# passes silently. Demonstrated by misspelling this script's own name in the
# CI step and watching the run succeed.
#
# The example is described rather than written out, because this file is one
# of the files scanned: spelling the typo here made it a referenced path and
# the check failed on a clean checkout, reporting a file that existed only in
# a comment about it not existing.
#
# Closed for the directories that are ours by construction. Nothing generates
# anything under scripts/ or .github/, so a name there that does not exist is
# a mistake rather than an artefact, and requiring existence needs no list.
# Elsewhere the membership rule still applies, and the hole with it.
for path in $referenced; do
    case "$path" in
        scripts/*|.github/*)
            [ -e "$path" ] || absent="$absent $path" ;;
    esac
done
# `echo` on an empty string still emits a newline, so a naive dedup turns
# "nothing absent" into a single space, which every `-n` test then calls
# non-empty. That reported a failure with an empty list under it.
absent=$(printf '%s' "$absent" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ' || true)

echo "referenced paths checked: $(echo "$referenced" | wc -w)"
if [ -n "$(printf %s "$untracked" | tr -d "[:space:]")" ]; then
    echo "  named by committed configuration but not committed:" >&2
    for path in $untracked; do echo "    $path" >&2; done
    echo "  they resolve here and nowhere else." >&2
    fail=1
fi
if [ -n "$(printf %s "$absent" | tr -d "[:space:]")" ]; then
    echo "  named by committed configuration and no longer present:" >&2
    for path in $absent; do echo "    $path" >&2; done
    echo "  nothing else reaches them, so nothing else would notice." >&2
    fail=1
fi

# `rust-version` is a *minimum*, so a manifest asking for less than the pinned
# channel builds silently, and that is exactly what raising the channel and
# forgetting the manifest produces. Cargo refuses only the opposite, rarer
# direction.
if [ ! -e rust-toolchain.toml ] || [ ! -e Cargo.toml ]; then
    echo "toolchain pin: skipped, an input is missing (named above)"
else
pinned=$(grep -oP 'channel\s*=\s*"\K[^"]+' rust-toolchain.toml)
declared=$(grep -oP '^rust-version\s*=\s*"\K[^"]+' Cargo.toml)
echo "toolchain pin: rust-toolchain.toml=$pinned Cargo.toml=$declared"
if [ "$pinned" != "$declared" ]; then
    echo "  raise both together" >&2
    fail=1
fi
fi

# `--locked` catches a stale lockfile and cannot catch an over-full one. An
# entry with no `source` is resolved from a local path; a path reaching
# outside this repository resolves on the machine that committed it and fails
# in CI, which checks out this repository alone. The allowed set is derived
# from the workspace rather than written down, so it stays true when a crate
# is added and fails when a *repository* is.
if [ ! -e Cargo.lock ]; then
    echo "lockfile: skipped, Cargo.lock is missing (named above)"
else
allowed=$(grep -h '^name = ' crates/*/Cargo.toml | tr -d '"' | awk '{print $3}' | sort)
sourceless=$(awk '/^\[\[package\]\]/{n="";s=0} /^name = /{n=$3} /^source = /{s=1} /^$/{if(n!=""&&!s) print n; n=""}' Cargo.lock | tr -d '"' | sort)
echo "lockfile path crates: $(echo "$sourceless" | tr '\n' ' ')"
unexpected=$(comm -13 <(echo "$allowed") <(echo "$sourceless") || true)
if [ -n "$unexpected" ]; then
    echo "  Cargo.lock names path crates this repository does not contain:" >&2
    echo "$unexpected" | sed 's/^/    /' >&2
    echo "  CI checks out only this repository, so it cannot fetch them." >&2
    fail=1
fi
fi

exit "$fail"
