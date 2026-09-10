#!/usr/bin/env bash
# Proves preflight's checks can fail, by planting each failure and requiring
# the matching complaint.
#
# The checks themselves were verified once, by hand, in a conversation. That
# is a practice, and a practice is deletable exactly when nothing fails
# without it — which is the argument every check in preflight was written
# from, unapplied to the checks themselves until now.
#
# Three controls, and none implies the next. A positive control proves the
# harness can pass; a negative control proves it can fail; a provenance
# control proves it is exercising the code you think it is. The third is not
# covered by the second: neutering a check inside the extracted tree disables
# whichever copy was placed there, so it reports success whether that copy
# came from the working tree or from HEAD. A sibling repository built this matrix, saw six green rows, then
# neutered a check on purpose and watched all six stay green — the harness
# had been testing the committed script while the author edited the working
# copy. Right answer, wrong reason, and invisible to a baseline row because
# the baseline was also right for the wrong reason.
#
# So: the tree comes from HEAD and is pristine, the script under test is the
# *working copy*, and every row asserts the expected complaint rather than a
# non-zero exit. Exit status alone cannot tell one failing check from
# another, which is how a row passes for something unrelated.
set -euo pipefail
cd "$(dirname "$0")/.."

repo=$(pwd)
under_test="$repo/scripts/preflight.sh"
work=$(mktemp -d)
trap 'git worktree remove --force "$work/tree" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT

git worktree add -q --detach "$work/tree" HEAD
cd "$work/tree"

fresh() {
    git reset -q --hard HEAD
    git clean -qfd
    cp "$under_test" scripts/preflight.sh
    # The script under test must be the one on disk in the repository, not
    # the one in HEAD. Compared against the literal path rather than the
    # variable, because the variable is what a rewiring would change — and a
    # rewiring is invisible to every row, including the neutering control
    # below, which disables the copy *after* it has been placed and so passes
    # either way. Verified by introducing the confound deliberately: without
    # this line the whole matrix stayed green.
    if ! cmp -s scripts/preflight.sh "$repo/scripts/preflight.sh"; then
        echo "FAIL  harness is not testing the working copy of preflight.sh" >&2
        exit 1
    fi
}

# A row: name, expected substring (empty = must pass), then the planting.
row() {
    local name="$1" expect="$2"; shift 2
    fresh
    "$@" >/dev/null 2>&1 || true
    local out rc=0
    out=$(./scripts/preflight.sh 2>&1) || rc=$?
    if [ -z "$expect" ]; then
        if [ "$rc" -ne 0 ]; then
            echo "FAIL  $name: expected a clean pass, got:"; echo "$out" | sed 's/^/        /'
            return 1
        fi
    elif [ "$rc" -eq 0 ]; then
        echo "FAIL  $name: preflight passed; it should have complained"; return 1
    elif ! printf '%s' "$out" | grep -q -- "$expect"; then
        echo "FAIL  $name: failed, but not about \"$expect\":"; echo "$out" | sed 's/^/        /'
        return 1
    fi
    echo "ok    $name"
}

# Absent paths are assembled here rather than written as literals: preflight
# scans scripts/*.sh, so a literal absent path in this file would become a
# path preflight demands, and the suite would fail on a clean checkout.
typo() { sed -i "s|preflight$(printf .)sh|prefli$(printf gth).sh|" .github/workflows/ci.yml; }
plant_untracked() {
    printf 'x\n' > "scripts/plant$(printf ed).sh"
    sed -i "s|run: ./scripts/preflight.sh|run: ./scripts/preflight.sh ./scripts/plant$(printf ed).sh|" \
        .github/workflows/ci.yml
}

failed=0

# Positive control first: if a pristine tree does not pass, no row below it
# means anything.
row "baseline is clean"            ""                              true || failed=1
row "toolchain pin drift"          "raise both together"           sed -i 's/^rust-version = .*/rust-version = "1.0.0"/' Cargo.toml || failed=1
row "lockfile names a foreign crate" "cannot fetch"                bash -c 'printf "\n[[package]]\nname = \"from-another-repo\"\nversion = \"0.1.0\"\n\n" >> Cargo.lock' || failed=1
row "referenced file deleted"      "no longer present"             rm crates/cosmic-pim-mail/tests/dovecot.conf || failed=1
row "referenced file git rm'd"     "no longer present"             git rm -q crates/cosmic-pim-mail/tests/dovecot.conf || failed=1
row "referenced file never made"   "no longer present"             typo || failed=1
row "referenced file uncommitted"  "not committed"                 plant_untracked || failed=1

# Negative control: a check that cannot fail must be caught failing to fail.
# Neuter the toolchain comparison in the copy under test and require the row
# that depends on it to notice. Without this, a harness testing the wrong
# copy of the script reports every row green.
fresh
sed -i 's/if \[ "$pinned" != "$declared" \]; then/if false; then/' scripts/preflight.sh
sed -i 's/^rust-version = .*/rust-version = "1.0.0"/' Cargo.toml
if ./scripts/preflight.sh >/dev/null 2>&1; then
    echo "ok    negative control: a neutered check stops complaining"
else
    echo "FAIL  negative control: preflight still failed with the check disabled —"
    echo "      the harness is not running the script it thinks it is"
    failed=1
fi

exit "$failed"
