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

# Pedantic as warnings, not denials — the ecosystem standard. The workspace's
# own clippy::all=warn lint table is what the build actually gates on.
check *args:
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
