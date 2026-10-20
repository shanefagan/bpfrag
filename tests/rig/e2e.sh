#!/bin/bash
# SPDX-License-Identifier: MIT
#
# End-to-end test on a real kernel. Needs root. Builds a throwaway network
# namespace "bpfrag-srv" (10.99.0.2) behind veth "bpfrag0", an echo server
# in it, then plays a fake Steam game plus Discord/Firefox/daemon-shaped
# noise at it and checks bpfrag's reactions. Cleans everything up after.
#
#   sudo tests/rig/e2e.sh [path/to/bpfrag]
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
B=$(realpath "${1:-$HERE/../../target/release/bpfrag}")
W=$(mktemp -d /tmp/bpfrag-e2e.XXXXXX)
PASS=0; FAIL=0
ok()   { echo "  PASS $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $*"; FAIL=$((FAIL+1)); }
KEYS="net.core.rmem_max net.core.wmem_max net.core.busy_poll net.core.busy_read net.core.netdev_budget net.core.netdev_max_backlog net.ipv4.udp_mem vm.dirty_bytes vm.dirty_ratio vm.dirty_background_bytes vm.dirty_background_ratio"
snap() { for k in $KEYS; do echo "$k = $(sysctl -n $k 2>&1 | tr '\t' ' ')"; done; }
same() { snap > $W/now; if diff -q $W/base $W/now >/dev/null; then ok "$1: settings identical to baseline"; else bad "$1"; diff $W/base $W/now; fi; }

cleanup() {
  pkill -f "^[^ ]*(fakeshooter|Discord|firefox|randomd) $W/" 2>/dev/null
  [ -n "${SRV:-}" ] && kill $SRV 2>/dev/null
  [ -n "${D:-}" ] && kill -INT $D 2>/dev/null && wait $D 2>/dev/null
  ip netns del bpfrag-srv 2>/dev/null; ip link del bpfrag0 2>/dev/null
  "$B" -c $W/cfg.toml --restore >/dev/null 2>&1
  # W always comes from mktemp; refuse anything else
  case "$W" in
    /tmp/bpfrag-e2e.*) [ -n "${KEEP:-}" ] && echo "kept $W" || rm -rf -- "/tmp/${W#/tmp/}" ;;
  esac
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
cp "$HERE/client.py" "$HERE/server.py" $W/
mkdir -p $W/steamapps/common/FakeShooter $W/apps
ln -s "$(command -v python3)" $W/steamapps/common/FakeShooter/fakeshooter
for n in Discord firefox randomd; do ln -s "$(command -v python3)" $W/apps/$n; done
ln -s "$(command -v sleep)" $W/apps/bpftune
cat > $W/cfg.toml <<EOT
[general]
run_dir = "$W/run"
[dscp]
interfaces = ["bpfrag0"]
[detect]
linger_secs = 6
dwell_secs = 3
EOT
ip netns add bpfrag-srv
ip link add bpfrag0 type veth peer name bpfrag1
ip link set bpfrag1 netns bpfrag-srv
ip addr add 10.99.0.1/24 dev bpfrag0; ip link set bpfrag0 up
ip -n bpfrag-srv addr add 10.99.0.2/24 dev bpfrag1; ip -n bpfrag-srv link set bpfrag1 up
HAVE_V6=; if [ -e /proc/net/if_inet6 ]; then
  HAVE_V6=1
  ip -6 addr add fd00:99::1/64 dev bpfrag0 nodad
  ip -n bpfrag-srv -6 addr add fd00:99::2/64 dev bpfrag1 nodad
fi
ip netns exec bpfrag-srv python3 $W/server.py & SRV=$!
snap > $W/base
game() { SteamAppId=4242 $W/steamapps/common/FakeShooter/fakeshooter $W/client.py "$@" & G=$!; }

echo "== 0. BPF selftest: packet vectors through the DSCP marker"
"$B" -c $W/cfg.toml --selftest > $W/selftest.log 2>&1 && ok "selftest ($(tail -1 $W/selftest.log))" || { bad "selftest"; cat $W/selftest.log; }

echo "== 1. noise is ignored, the game is detected, tiers follow the tick rate"
"$B" -c $W/cfg.toml > $W/d.log 2>&1 & D=$!; sleep 1.5
$W/apps/Discord $W/client.py 50 120 & N1=$!
$W/apps/firefox $W/client.py 300 1300 & N2=$!
$W/apps/randomd $W/client.py 40 100 & N3=$!
sleep 6
grep -q "Match detected" $W/d.log && bad "noise started a match" || ok "noise alone starts nothing"
grep -q "Ignoring game-like UDP from Discord" $W/d.log && ok "Discord rejected by deny list" || bad "Discord not rejected"
echo 64 > $W/rate; game 64 180 $W/rate; sleep 6
grep -q "Match detected: fakeshooter.*COMPETITIVE" $W/d.log && ok "fake Steam game -> COMPETITIVE" || bad "game not detected"
[ "$(sysctl -n net.core.busy_poll)" = 50 ] && ok "busy_poll=50" || bad "busy_poll not set"
[ "$(sysctl -n vm.dirty_bytes)" -gt 0 ] && ok "writeback tightened" || echo "  skip writeback already tight"
errs() { ip netns exec bpfrag-srv nstat -az IpExtInCsumErrors IpInHdrErrors 2>/dev/null | awk '/^Ip/{n+=$2} END{print n+0}'; }
E0=$(errs)
ip netns exec bpfrag-srv timeout 4 tcpdump -n -i bpfrag1 -c 150 -w $W/v4.pcap 'udp and dst port 27015 and src 10.99.0.1' 2>/dev/null
E1=$(errs)
SUM=$(python3 "$HERE/pcap_check.py" $W/v4.pcap)
echo "$SUM" | grep -q "ipv4 dscp=32 csum=ok" && ok "game packets marked CS4" || bad "DSCP: $SUM"
echo "$SUM" | grep -q "csum=BAD" && bad "rewritten packets have bad IPv4 header checksums" || ok "IPv4 header checksums valid after rewrite"
[ $((E1 - E0)) = 0 ] && ok "server kernel saw no IP checksum/header errors" || bad "server IP errors: $((E1 - E0))"
RX=$("$B" -c $W/cfg.toml --monitor 0 | awk '$2=="fakeshooter"{split($4,a,"/"); print a[2]}' | head -1)
[ "${RX:-0}" -gt 0 ] && ok "server echoed marked packets back (rx ${RX}/s)" || bad "no echoes: marked packets dropped?"
echo 150 > $W/rate; sleep 10
grep -q "COMPETITIVE -> INTENSE" $W/d.log && ok "rate increase -> INTENSE" || bad "no INTENSE"
"$B" -c $W/cfg.toml --waybar | grep -q '"text":"INTENSE"' && ok "waybar shows the match" || bad "waybar: $("$B" -c $W/cfg.toml --waybar)"
kill $G; sleep 2
grep -q "GG" $W/d.log && ok "game exit ends the match immediately" || bad "no GG"
"$B" -c $W/cfg.toml --waybar | grep -q '"alt":"idle".*Last match: fakeshooter INTENSE' && ok "waybar idle with last match" || bad "waybar idle: $("$B" -c $W/cfg.toml --waybar)"
same "after game exit"
kill $N1 $N2 $N3

echo "== 2. a value changed by someone else mid-match is left alone"
echo 64 > $W/rate; game 64 180 $W/rate; sleep 6; sysctl -qw net.core.busy_poll=99; kill $G; sleep 2
[ "$(sysctl -n net.core.busy_poll)" = 99 ] && ok "busy_poll=99 kept" || bad "clobbered busy_poll"
sysctl -qw net.core.busy_poll=0

echo "== 3. with bpftune running its sysctls are left to it"
$W/apps/bpftune 600 & BTP=$!; sleep 0.5; R0=$(sysctl -n net.core.rmem_max)
game 64 180 $W/rate; sleep 6
[ "$(sysctl -n net.core.rmem_max)" = "$R0" ] && ok "rmem_max untouched" || bad "wrote rmem_max under bpftune"
[ "$(sysctl -n net.core.busy_poll)" = 50 ] && ok "latency knobs still applied" || bad "busy_poll missing"
kill $G $BTP; sleep 2; same "after bpftune match"
kill -INT $D; wait $D; D=

echo "== 4. kill -9 mid-match, then --restore"
"$B" -c $W/cfg.toml > $W/d4.log 2>&1 & D=$!; sleep 1; game 64 180; sleep 6
kill -9 $D; wait $D 2>/dev/null; D=
tc filter show dev bpfrag0 egress | grep -q bpfrag && bad "tc left attached" || ok "tcx link died with the daemon"
"$B" -c $W/cfg.toml --restore >/dev/null 2>&1; same "after --restore"; kill $G

echo "== 5. IPv6: traffic class rewritten"
if [ -z "$HAVE_V6" ]; then echo "  skip IPv6 disabled on this host (the selftest covered the IPv6 rewrite)"; else
"$B" -c $W/cfg.toml > $W/d6.log 2>&1 & D=$!; sleep 1
DEST=fd00:99::2 SteamAppId=4242 $W/steamapps/common/FakeShooter/fakeshooter $W/client.py 64 180 & G=$!; sleep 6
ip netns exec bpfrag-srv timeout 4 tcpdump -n -i bpfrag1 -c 100 -w $W/v6.pcap 'ip6 and udp and dst port 27015' 2>/dev/null
SUM6=$(python3 "$HERE/pcap_check.py" $W/v6.pcap)
echo "$SUM6" | grep -q "ipv6 dscp=32" && ok "IPv6 game packets carry CS4 traffic class" || bad "IPv6: $SUM6"
kill $G; kill -INT $D; wait $D; D=
fi

echo "== 6. network path changes mid-match are followed"
# No fixed interface list: bpfrag uses the default-route interfaces. A
# high-metric default route via the test veth appears mid-match (think
# docking or a VPN coming up); within ~5s bpfrag should start marking there.
sed '/^\[dscp\]/,/^interfaces/d' $W/cfg.toml > $W/cfg-auto.toml
"$B" -c $W/cfg-auto.toml > $W/d7.log 2>&1 & D=$!; sleep 1
game 64 180; sleep 6
grep -q "Match detected" $W/d7.log && ok "match detected (auto interfaces)" || bad "no match"
ip route add default via 10.99.0.2 dev bpfrag0 metric 4242
sleep 7
grep -q "network path changed" $W/d7.log && ok "path change noticed" || bad "path change not noticed"
ip netns exec bpfrag-srv timeout 4 tcpdump -n -i bpfrag1 -c 60 -w $W/v4b.pcap 'udp and dst port 27015 and src 10.99.0.1' 2>/dev/null
python3 "$HERE/pcap_check.py" $W/v4b.pcap | grep -q "ipv4 dscp=32 csum=ok" && ok "marking follows the game onto the new path" || bad "not marked after path change"
ip route del default via 10.99.0.2 dev bpfrag0 metric 4242
kill $G; kill -INT $D; wait $D; D=
same "after path-change match"

echo "== 7. --dry-run changes nothing"
"$B" -c $W/cfg.toml --dry-run > $W/d5.log 2>&1 & D=$!; sleep 1; game 64 180; sleep 6
grep -q "would set" $W/d5.log && ok "dry run logs intended changes" || bad "dry run silent"
same "dry run"; kill $G

echo; echo "passed $PASS, failed $FAIL"
[ $FAIL = 0 ]
