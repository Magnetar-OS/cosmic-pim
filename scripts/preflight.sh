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

exit "$fail"
