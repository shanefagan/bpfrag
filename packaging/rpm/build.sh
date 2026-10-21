#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Make the two tarballs bpfrag.spec builds from, then run rpmbuild.
#
#   packaging/rpm/build.sh          # .src.rpm and .rpm, in target/rpm/
#   packaging/rpm/build.sh --srpm   # .src.rpm only, for COPR or mock
#
# Like the PKGBUILD, this packages committed changes only (git archive HEAD).
set -eu

mode=-ba
case "${1:-}" in
    --srpm) mode=-bs ;;
    "") ;;
    *) echo "usage: $0 [--srpm]" >&2; exit 2 ;;
esac

cd "$(dirname "$0")/../.."
name=bpfrag
ver=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
spec=packaging/rpm/$name.spec
if ! grep -Eq "^Version:[[:space:]]+$ver\$" "$spec"; then
    echo "$spec: Version does not match Cargo.toml ($ver)" >&2
    exit 1
fi

top=$PWD/target/rpm
rm -rf "$top"
mkdir -p "$top/SOURCES" "$top/work"

git archive --format=tar.gz --prefix="$name-$ver/" \
    -o "$top/SOURCES/$name-$ver.tar.gz" HEAD

# Vendor from the archived tree so the crates match its Cargo.lock.
tar -xzf "$top/SOURCES/$name-$ver.tar.gz" -C "$top/work"
(cd "$top/work/$name-$ver" && cargo vendor --locked --quiet vendor >/dev/null)
tar -cJf "$top/SOURCES/$name-$ver-vendor.tar.xz" -C "$top/work/$name-$ver" vendor
rm -rf "$top/work"

rpmbuild "$mode" \
    --define "_topdir $top" \
    --define "_sourcedir $top/SOURCES" \
    "$spec"

find "$top/SRPMS" "$top/RPMS" -name '*.rpm' 2>/dev/null
