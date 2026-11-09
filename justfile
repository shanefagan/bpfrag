# SPDX-License-Identifier: MIT
#
# Building, testing and packaging bpfrag. CI runs these same recipes, so
# what passes here is what passes there.
#
#   just               list the recipes
#   just pre-commit    format, clippy and unit tests (no root)
#   just ci            everything CI's test job runs (uses sudo)
#
# Nothing here is needed to build bpfrag: it's a plain cargo project
# (`cargo build --release`), and `just install` is the list of files a
# package needs. Each recipe is a few commands that can be run by hand.

bin := "target/release/bpfrag"
version := `sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1`
msrv := `sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml | head -n1`
# Root in a container, sudo on a desktop or a CI runner.
sudo := if `id -u` == "0" { "" } else { "sudo" }

# Where `just install` puts things; DESTDIR and PREFIX as with make.
destdir := env_var_or_default("DESTDIR", "")
prefix := env_var_or_default("PREFIX", "/usr")
sysconfdir := env_var_or_default("SYSCONFDIR", "/etc")
unitdir := env_var_or_default("UNITDIR", "/usr/lib/systemd/system")
dbusdir := env_var_or_default("DBUSDIR", "/usr/share/dbus-1/system.d")

# List the recipes
default:
    @just --list --unsorted

# ---- build and test: CI's test job runs these, in this order ------------

# Check formatting
fmt-check:
    cargo fmt --check

# Clippy, with warnings as errors
lint:
    cargo clippy --locked --all-targets -- -D warnings

# Unit tests (no root)
test:
    cargo test --locked

# Build the release binary
build:
    cargo build --locked --release

# What this machine and kernel support; informational, never fails (root)
check-system: build
    -{{ sudo }} {{ bin }} --check

# Packet vectors through both tc programs on this kernel (root)
selftest: build
    {{ sudo }} {{ bin }} --selftest

# The selftest with many more random packets (a failure prints the seed that repeats it)
fuzz packets="200000" seed="": build
    {{ sudo }} env BPFRAG_FUZZ_PACKETS={{ packets }} {{ if seed != "" { "BPFRAG_FUZZ_SEED=" + seed } else { "" } }} {{ bin }} --selftest

# Network namespace, fake game, noise, crash recovery, D-Bus (root)
e2e: build
    {{ sudo }} tests/rig/e2e.sh {{ bin }}

# The same with only the systemd unit's capabilities (root)
e2e-unit: build
    {{ sudo }} tests/rig/e2e.sh tests/rig/unit-caps.sh

# Everything CI's test job runs
ci: fmt-check lint test build check-system selftest e2e e2e-unit

# Format, clippy and unit tests: quick, no root, before committing
pre-commit: fmt-check lint test

# Format the code
fmt:
    cargo fmt

# Check it builds with the oldest supported Rust (rust-version in Cargo.toml)
msrv toolchain=msrv:
    cargo +{{ toolchain }} check --locked --all-targets

# ---- install ---------------------------------------------------------------

# Install the binary, unit, man page, D-Bus policy and (if absent) config (asks first; --yes skips)
[confirm]
install:
    @test -x {{ bin }} || { echo "{{ bin }} not built: run 'just build' first (not as root)"; exit 1; }
    install -Dm755 {{ bin }} "{{ destdir }}{{ prefix }}/bin/bpfrag"
    install -Dm644 dist/bpfrag.service "{{ destdir }}{{ unitdir }}/bpfrag.service"
    install -Dm644 dist/bpfrag.8 "{{ destdir }}{{ prefix }}/share/man/man8/bpfrag.8"
    install -Dm644 dist/com.performativenonsense.Bpfrag1.conf "{{ destdir }}{{ dbusdir }}/com.performativenonsense.Bpfrag1.conf"
    test -e "{{ destdir }}{{ sysconfdir }}/default/bpfrag" || install -Dm644 dist/bpfrag.default "{{ destdir }}{{ sysconfdir }}/default/bpfrag"
    test -e "{{ destdir }}{{ sysconfdir }}/bpfrag/bpfrag.toml" || install -Dm644 dist/bpfrag.toml "{{ destdir }}{{ sysconfdir }}/bpfrag/bpfrag.toml"
    @echo
    @echo "Installed. Next: sudo systemctl daemon-reload && sudo systemctl reload dbus && sudo systemctl enable --now bpfrag"

# Stop the service and remove what `just install` put in place, not the config (asks first)
[confirm]
uninstall:
    -systemctl disable --now bpfrag 2>/dev/null
    rm -f "{{ destdir }}{{ prefix }}/bin/bpfrag" "{{ destdir }}{{ unitdir }}/bpfrag.service" \
        "{{ destdir }}{{ prefix }}/share/man/man8/bpfrag.8" \
        "{{ destdir }}{{ dbusdir }}/com.performativenonsense.Bpfrag1.conf"
    @echo "Left {{ sysconfdir }}/default/bpfrag and {{ sysconfdir }}/bpfrag/ in place."

# ---- packages: CI's deb and rpm jobs run these -----------------------------

# Debian/Ubuntu package in target/debian/ (needs cargo-deb)
deb:
    cargo deb --locked

# lintian on the .deb
deb-lint:
    lintian --suppress-tags initial-upload-closes-no-bugs target/debian/*.deb

# Install the .deb, run it, remove and purge it (root; for a container or VM)
deb-smoke:
    {{ sudo }} apt-get install -y ./target/debian/*.deb
    bpfrag --version
    bpfrag --dump-config >/dev/null
    {{ sudo }} apt-get remove -y bpfrag
    {{ sudo }} apt-get purge -y bpfrag
    test ! -e /etc/bpfrag

# The binary, unit, man page, configs and licences, for any glibc distro
tarball: build
    #!/bin/sh
    set -eu
    d=bpfrag-{{ version }}-$(uname -m)-linux
    rm -rf "target/$d"
    mkdir -p "target/$d"
    cp {{ bin }} dist/bpfrag.service dist/bpfrag.8 dist/bpfrag.toml dist/bpfrag.default \
        dist/com.performativenonsense.Bpfrag1.conf README.md LICENSE LICENSE-GPL-2.0 "target/$d/"
    tar -C target -czf "target/$d.tar.gz" "$d"
    echo "target/$d.tar.gz"

# Fedora .src.rpm and .rpm in target/rpm/, built offline from committed files
rpm:
    packaging/rpm/build.sh

# Only the .src.rpm, for COPR or mock
srpm:
    packaging/rpm/build.sh --srpm

# rpmlint on the packages
rpm-lint:
    rpmlint -r packaging/rpm/bpfrag.rpmlintrc target/rpm/RPMS/*/*.rpm target/rpm/SRPMS/*.rpm

# Install the .rpm, run it, remove it (root; for a container or VM)
rpm-smoke:
    {{ sudo }} dnf -y install target/rpm/RPMS/*/bpfrag-[0-9]*.rpm
    bpfrag --version
    bpfrag --dump-config >/dev/null
    {{ sudo }} dnf -y remove bpfrag

# ---- releases --------------------------------------------------------------

# Set a new version everywhere it's recorded, e.g. just bump 1.2.3 "What changed"
bump new *note:
    packaging/bump-version.sh {{ new }} {{ quote(note) }}

# Fail unless TAG is v<the version in Cargo.toml> (CI's release job)
check-tag tag:
    @test "{{ tag }}" = "v{{ version }}" || { echo "tag {{ tag }}, but Cargo.toml says {{ version }}: run 'just bump'"; exit 1; }

# Remove build output
clean:
    cargo clean
