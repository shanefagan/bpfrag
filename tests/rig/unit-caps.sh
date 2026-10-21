#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Run bpfrag with only the capabilities dist/bpfrag.service leaves it, to
# check the unit's CapabilityBoundingSet is enough:
#
#   sudo tests/rig/e2e.sh tests/rig/unit-caps.sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
caps=$(sed -n 's/^CapabilityBoundingSet=//p' "$HERE/../../dist/bpfrag.service" |
    tr 'A-Z ' 'a-z,' | sed 's/cap_/+/g')
exec setpriv --bounding-set "-all,$caps" --inh-caps=-all -- \
    "${BPFRAG:-$HERE/../../target/release/bpfrag}" "$@"
