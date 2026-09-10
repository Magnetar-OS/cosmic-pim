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

# `rust-version` is a *minimum*, so a manifest asking for less than the pinned
# channel builds silently, and that is exactly what raising the channel and
# forgetting the manifest produces. Cargo refuses only the opposite, rarer
# direction.
pinned=$(grep -oP 'channel\s*=\s*"\K[^"]+' rust-toolchain.toml)
declared=$(grep -oP '^rust-version\s*=\s*"\K[^"]+' Cargo.toml)
echo "toolchain pin: rust-toolchain.toml=$pinned Cargo.toml=$declared"
if [ "$pinned" != "$declared" ]; then
    echo "  raise both together" >&2
    fail=1
fi

# `--locked` catches a stale lockfile and cannot catch an over-full one. An
# entry with no `source` is resolved from a local path; a path reaching
# outside this repository resolves on the machine that committed it and fails
# in CI, which checks out this repository alone. The allowed set is derived
# from the workspace rather than written down, so it stays true when a crate
# is added and fails when a *repository* is.
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
referenced=$(grep -ohE '(\./)?(scripts|crates|\.github)/[A-Za-z0-9_./-]+' \
    .github/workflows/ci.yml justfile scripts/preflight.sh 2>/dev/null \
    | sed 's|^\./||' | sort -u)
untracked=""
absent=""
for path in $referenced; do
    if [ ! -e "$path" ]; then
        absent="$absent $path"
    elif ! git ls-files --error-unmatch "$path" >/dev/null 2>&1; then
        untracked="$untracked $path"
    fi
done
echo "referenced paths checked: $(echo "$referenced" | wc -l)"
if [ -n "$untracked" ]; then
    echo "  named by committed configuration but not committed:" >&2
    for path in $untracked; do echo "    $path" >&2; done
    echo "  they resolve here and nowhere else." >&2
    fail=1
fi
if [ -n "$absent" ]; then
    echo "  named by committed configuration and not present:" >&2
    for path in $absent; do echo "    $path" >&2; done
    echo "  nothing else reaches them, so nothing else would notice." >&2
    fail=1
fi

exit "$fail"
