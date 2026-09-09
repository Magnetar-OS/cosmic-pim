# The conventional COSMIC build entry point (cosmic-conventions.md, "The
# justfile"), trimmed to what a library workspace has: no binary, no desktop
# entry, no icons, so no install/uninstall — the applications that link these
# crates install themselves. The vendoring recipes stay, because a distro
# packager building Slate offline still needs this workspace's dependencies in
# the tarball.

export NAME := 'cosmic-pim'

cargo-target-dir := env('CARGO_TARGET_DIR', 'target')

default: build-release

clean:
    cargo clean

clean-vendor:
    rm -rf .cargo vendor vendor.tar

clean-dist: clean clean-vendor

build-debug *args:
    cargo build --workspace --locked {{args}}

build-release *args: (build-debug '--release' args)

build-vendored *args: vendor-extract (build-release '--frozen --offline' args)

# The toolchain pin and the manifest's `rust-version` must agree, and cargo
# only notices one direction of drift — a manifest asking for *more* than the
# pinned channel is refused, one asking for less builds silently. Raising the
# channel and forgetting the manifest is the likely mistake and the silent
# one, so it is checked here as well as in CI: a contributor who runs
# `just check` should not have to push to find out.
toolchain-pin:
    #!/usr/bin/env bash
    set -euo pipefail
    pinned=$(grep -oP 'channel\s*=\s*"\K[^"]+' rust-toolchain.toml)
    declared=$(grep -oP '^rust-version\s*=\s*"\K[^"]+' Cargo.toml)
    if [ "$pinned" != "$declared" ]; then
        echo "rust-toolchain.toml pins $pinned but Cargo.toml declares $declared; raise both together" >&2
        exit 1
    fi
    echo "toolchain pin and manifest agree: $pinned"

# Pedantic as warnings, not denials — the ecosystem standard. The workspace's
# own clippy::all=warn lint table is what the build actually gates on.
check *args: toolchain-pin
    cargo clippy --workspace --all-targets --locked {{args}} -- -W clippy::pedantic

test *args:
    cargo test --workspace --locked {{args}}

# For offline distribution builds. SOURCE_DATE_EPOCH keeps the tarball
# reproducible.
vendor:
    #!/usr/bin/env bash
    mkdir -p .cargo
    cargo vendor --sync Cargo.toml | head -n -1 > .cargo/config.toml
    echo 'directory = "vendor"' >> .cargo/config.toml
    tar pcf vendor.tar --numeric-owner --owner=0 --group=0 \
        --mtime="@${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}" vendor
    rm -rf vendor

vendor-extract:
    rm -rf vendor
    tar pxf vendor.tar
