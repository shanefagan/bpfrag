#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Set a new version everywhere it is recorded:
#
#   packaging/bump-version.sh 0.2.0 "Per-match network health report"
#   git commit -am "Release 0.2.0"
#   git tag -a v0.2.0 -m "bpfrag 0.2.0"
#   git push origin main v0.2.0      # CI builds the packages and the release
#
# Updates Cargo.toml and Cargo.lock, the RPM spec (Version, Release,
# %changelog), the Debian changelog and the man page header. A unit test
# fails if any of them disagree, and CI refuses a tag that doesn't match.
set -eu

[ $# -ge 1 ] || { echo "usage: $0 NEW_VERSION [CHANGE]" >&2; exit 2; }
new=$1
note=${2:-New release.}
case $new in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "version must look like 1.2.3" >&2; exit 2 ;;
esac
case $new in *[!0-9.]*) echo "version must look like 1.2.3" >&2; exit 2 ;; esac

cd "$(dirname "$0")/.."
maint=${MAINTAINER:-"Shane Fagan <mail@shanefagan.com>"}
old=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
[ "$old" != "$new" ] || { echo "already at $new" >&2; exit 1; }

# Cargo.toml: the first top-level `version =` is the package's.
sed -i "0,/^version = \"$old\"/s//version = \"$new\"/" Cargo.toml
# Cargo.lock: the version line right after our own name.
awk -v new="$new" '
    prev == "name = \"bpfrag\"" && /^version = / { $0 = "version = \"" new "\"" }
    { print; prev = $0 }
' Cargo.lock > Cargo.lock.tmp && mv Cargo.lock.tmp Cargo.lock

spec=packaging/rpm/bpfrag.spec
sed -i -e "s/^\(Version:[[:space:]]*\).*/\1$new/" \
       -e "s/^\(Release:[[:space:]]*\).*/\11%{?dist}/" "$spec"
entry="* $(LC_ALL=C date +'%a %b %d %Y') $maint - $new-1\\
- $note"
sed -i "/^%changelog/a\\
$entry\\
" "$spec"

deb=packaging/debian/changelog
{
    printf 'bpfrag (%s-1) unstable; urgency=medium\n\n  * %s\n\n -- %s  %s\n\n' \
        "$new" "$note" "$maint" "$(LC_ALL=C date -R)"
    cat "$deb"
} > "$deb.tmp" && mv "$deb.tmp" "$deb"

sed -i "1s/^\.TH BPFRAG 8 \"[^\"]*\" \"bpfrag [^\"]*\"/.TH BPFRAG 8 \"$(date +%Y-%m)\" \"bpfrag $new\"/" dist/bpfrag.8

echo "bpfrag $old -> $new. Next:"
echo "  git commit -am \"Release $new\" && git tag -a v$new -m \"bpfrag $new\""
echo "  git push origin main v$new"
