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
  pkill -f "^[^ ]*(fakeshooter|fakemmo|Discord|firefox|randomd|steam|obs) $W/" 2>/dev/null
  [ -n "${SRV:-}" ] && kill $SRV 2>/dev/null
  [ -n "${D:-}" ] && kill -INT $D 2>/dev/null && wait $D 2>/dev/null
  [ -n "${MONP:-}" ] && kill $MONP 2>/dev/null
  [ -n "${BUSD:-}" ] && kill $BUSD 2>/dev/null
  umount "$W/run8" 2>/dev/null
  ip netns del bpfrag-srv 2>/dev/null; ip link del bpfrag0 2>/dev/null
  ip link del bpfrag-ingress 2>/dev/null; ip link del bpfrag-egress 2>/dev/null
  "$B" -c $W/cfg.toml --restore >/dev/null 2>&1
  # W always comes from mktemp; refuse anything else
  case "$W" in
    /tmp/bpfrag-e2e.*) [ -n "${KEEP:-}" ] && echo "kept $W" || rm -rf -- "/tmp/${W#/tmp/}" ;;
  esac
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
cp "$HERE/client.py" "$HERE/server.py" "$HERE/bulk.py" "$HERE/tcpgame.py" $W/
mkdir -p $W/steamapps/common/FakeShooter $W/steamapps/common/FakeMMO $W/apps
ln -s "$(command -v python3)" $W/steamapps/common/FakeShooter/fakeshooter
ln -s "$(command -v python3)" $W/steamapps/common/FakeMMO/fakemmo
for n in Discord firefox randomd steam obs; do ln -s "$(command -v python3)" $W/apps/$n; done
ln -s "$(command -v sleep)" $W/apps/bpftune
# D-Bus stays off here: a test instance must never speak on the machine's
# real system bus. Section 12 gives it a private one.
cat > $W/cfg.toml <<EOT
[general]
run_dir = "$W/run"
state_dir = "$W/state"
dbus = false
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
ip -n bpfrag-srv addr add 10.99.0.3/24 dev bpfrag1   # a second game server
HAVE_V6=; if [ -e /proc/net/if_inet6 ]; then
  HAVE_V6=1
  ip -6 addr add fd00:99::1/64 dev bpfrag0 nodad
  ip -n bpfrag-srv -6 addr add fd00:99::2/64 dev bpfrag1 nodad
fi
ip netns exec bpfrag-srv python3 $W/server.py & SRV=$!
snap > $W/base
game() { SteamAppId=4242 $W/steamapps/common/FakeShooter/fakeshooter $W/client.py "$@" & G=$!; }
# Classic tc filters redirecting through IFB devices, the way desktop CAKE
# setups shape downloads. bpfrag's tcx programs run first and must pass
# packets on to them, not end the chain.
tc qdisc add dev bpfrag0 clsact
for dir in ingress egress; do
  ip link add bpfrag-$dir type ifb && ip link set bpfrag-$dir up
  tc filter add dev bpfrag0 $dir protocol ip prio 1 u32 match u32 0 0 \
    action mirred egress redirect dev bpfrag-$dir
done
tcpkts() { cat /sys/class/net/bpfrag-$1/statistics/rx_packets 2>/dev/null || echo 0; }

echo "== 0. BPF selftest: packet vectors through the DSCP marker"
"$B" -c $W/cfg.toml --selftest > $W/selftest.log 2>&1 && ok "selftest ($(tail -1 $W/selftest.log))" || { bad "selftest"; cat $W/selftest.log; }

echo "== 1. noise is ignored, the game is detected, tiers follow the tick rate"
"$B" -c $W/cfg.toml > $W/d.log 2>&1 & D=$!; sleep 1.5
$W/apps/Discord $W/client.py 50 120 & N1=$!
$W/apps/firefox $W/client.py 300 1300 & N2=$!
$W/apps/randomd $W/client.py 40 100 & N3=$!
sleep 6
grep -q "Match detected" $W/d.log && bad "noise started a match" || ok "noise alone starts nothing"
"$B" -c $W/cfg.toml --monitor 0 | grep -q "Discord .*not a game: deny list 'discord'" && ok "Discord rejected by deny list" || bad "Discord not rejected"
grep -q "Ignoring game-like UDP from Discord" $W/d.log && bad "deny-list rejection logged at info" || ok "deny-list rejection kept out of the info log"
grep -q "Ignoring game-like UDP from randomd.*no game signals" $W/d.log && ok "unrecognised process logged once at info" || bad "randomd not logged"
echo 64 > $W/rate; game 64 180 $W/rate; sleep 6
grep -q "Match detected: fakeshooter.*COMPETITIVE" $W/d.log && ok "fake Steam game -> COMPETITIVE" || bad "game not detected"
[ "$(sysctl -n net.core.busy_poll)" = 50 ] && ok "busy_poll=50" || bad "busy_poll not set"
[ "$(sysctl -n vm.dirty_bytes)" -gt 0 ] && ok "writeback tightened" || echo "  skip writeback already tight"
I0=$(tcpkts ingress); O0=$(tcpkts egress); sleep 1; I1=$(tcpkts ingress); O1=$(tcpkts egress)
[ $((I1 - I0)) -gt 20 ] && ok "classic ingress redirect to IFB still runs under the meter" || bad "ingress IFB starved: $I0 -> $I1"
[ $((O1 - O0)) -gt 20 ] && ok "classic egress redirect to IFB still runs under the marker" || bad "egress IFB starved: $O0 -> $O1"
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
# 64 echoes a second arrive about 15.6 ms apart
CONN=$("$B" -c $W/cfg.toml --monitor 0 | grep 'connection:')
echo "$CONN" | grep -q 'packet gaps half ≤1[5-8] ms' && ok "packet gaps measured on the game's flow" || bad "gaps: $CONN"
echo 150 > $W/rate; sleep 10
grep -q "COMPETITIVE -> INTENSE" $W/d.log && ok "rate increase -> INTENSE" || bad "no INTENSE"
"$B" -c $W/cfg.toml --waybar | grep -q '"text":"INTENSE"' && ok "waybar shows the match" || bad "waybar: $("$B" -c $W/cfg.toml --waybar)"
kill $G; sleep 2
grep -q "Match ended" $W/d.log && ok "game exit ends the match immediately" || bad "match did not end"
grep -q "fakeshooter: packet gaps half" $W/d.log && ok "match health logged when it ends" || bad "no health line at match end"
"$B" -c $W/cfg.toml --waybar | grep -q '"alt":"idle".*Last match: fakeshooter INTENSE' && ok "waybar idle with last match" || bad "waybar idle: $("$B" -c $W/cfg.toml --waybar)"
same "after game exit"
kill $N1 $N2 $N3

echo "== 2. a value changed by someone else mid-match is left alone"
echo 64 > $W/rate; game 64 180 $W/rate; sleep 6; sysctl -qw net.core.busy_poll=99
# a tier change re-applies the profile (intense wants busy_poll=75)
echo 150 > $W/rate; sleep 8
[ "$(grep -c "COMPETITIVE -> INTENSE" $W/d.log)" -ge 2 ] && ok "tier changed mid-match" || bad "no tier change: $(tail -3 $W/d.log)"
[ "$(sysctl -n net.core.busy_poll)" = 99 ] && ok "busy_poll=99 kept through the tier change" || bad "tier change clobbered busy_poll ($(sysctl -n net.core.busy_poll))"
grep -q "net.core.busy_poll was changed by someone else during the match (now 99)" $W/d.log && ok "and logged" || bad "not logged"
[ "$(sysctl -n net.core.busy_read)" = 75 ] && ok "the rest of the intense profile applied" || bad "busy_read $(sysctl -n net.core.busy_read)"
kill $G; sleep 2; echo 64 > $W/rate
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
# The game keeps running: its packets must now leave unmarked.
ip netns exec bpfrag-srv timeout 4 tcpdump -n -i bpfrag1 -c 30 -w $W/v4k.pcap 'udp and dst port 27015 and src 10.99.0.1' 2>/dev/null
SUMK=$(python3 "$HERE/pcap_check.py" $W/v4k.pcap)
echo "$SUMK" | grep -q "ipv4 dscp=0 " && ! echo "$SUMK" | grep -q "dscp=32" && ok "tcx link died with the daemon (packets unmarked)" || bad "still marking after kill -9: $SUMK"
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
# The meter starts on the default-route interface, which doesn't carry the
# game here, so it sees the game nowhere: two more seconds, then the rate
# alone decides, as before.
game 64 180; sleep 9
grep -q "Match detected" $W/d7.log && ok "match detected (auto interfaces)" || bad "no match"
ip route add default via 10.99.0.2 dev bpfrag0 metric 4242
sleep 7
grep -q "network path changed" $W/d7.log && ok "path change noticed" || bad "path change not noticed"
grep -q "game traffic leaves via bpfrag0" $W/d7.log && ok "per-interface settings follow the game's egress" || bad "egress not followed"
ip netns exec bpfrag-srv timeout 4 tcpdump -n -i bpfrag1 -c 60 -w $W/v4b.pcap 'udp and dst port 27015 and src 10.99.0.1' 2>/dev/null
python3 "$HERE/pcap_check.py" $W/v4b.pcap | grep -q "ipv4 dscp=32 csum=ok" && ok "marking follows the game onto the new path" || bad "not marked after path change"
ip route del default via 10.99.0.2 dev bpfrag0 metric 4242
kill $G; kill -INT $D; wait $D; D=
same "after path-change match"

echo "== 6b. stalls: a mid-match hiccup counts, a lobby doesn't"
# Two real hiccups (the client frozen for ~300 ms), then a lobby: a few
# seconds of one packet a second, the way games idle between rounds.
"$B" -c $W/cfg.toml > $W/d6b.log 2>&1 & D=$!; sleep 1
echo 64 > $W/rate6b; game 64 180 $W/rate6b; sleep 6
for i in 1 2; do kill -STOP $G; sleep 0.3; kill -CONT $G; sleep 2; done
echo 1 > $W/rate6b; sleep 4; echo 64 > $W/rate6b; sleep 4
kill $G; sleep 2
H=$(grep "fakeshooter: packet gaps" $W/d6b.log); echo "  ($H)"
echo "$H" | grep -q ", 2 stalls (100 ms+)" && ok "two hiccups, two stalls; the lobby isn't one" || bad "stalls: $H"
echo "$H" | grep -Eq "longest (2[5-9][0-9]|3[0-9][0-9]|4[0-4][0-9]) ms" && ok "longest gap is the hiccup, not a keepalive" || bad "longest: $H"
kill -INT $D; wait $D; D=
same "after stall match"

echo "== 6c. two matches in one game session are two matches"
# Match, then menus (a packet a second with a burst every fourth second,
# like relay pings), then another match, all in one game process.
"$B" -c $W/cfg.toml > $W/d6c.log 2>&1 & D=$!; sleep 1
echo 64 > $W/rate6c; game 64 180 $W/rate6c; sleep 6
for i in $(seq 1 4); do echo 1 > $W/rate6c; sleep 3; echo 40 > $W/rate6c; sleep 1; done
# The second match is detected once the detector's 8-second history holds
# game traffic again plus 3 steady seconds: about 11 s, longer on a slow
# runner, so wait for it rather than guessing.
echo 64 > $W/rate6c
for i in $(seq 1 30); do
  [ "$(grep -c 'Match detected: fakeshooter' $W/d6c.log)" -ge 2 ] && break
  sleep 1
done
sleep 3
kill $G; sleep 2; kill -INT $D; wait $D; D=
N=$(grep -c "Match detected: fakeshooter" $W/d6c.log)
[ "$N" = 2 ] && ok "menus between matches end the first match" || bad "$N matches: $(grep -E 'Match (detected|ended)' $W/d6c.log)"
grep -q "Match ended after .*(netcode quiet" $W/d6c.log && ok "first match ended on the quiet menus" || bad "no quiet end: $(grep 'Match ended' $W/d6c.log)"
[ "$(grep -c 'fakeshooter: packet gaps' $W/d6c.log)" = 2 ] && ok "a health line for each match" || bad "health lines: $(grep -c 'fakeshooter: packet gaps' $W/d6c.log)"
same "after two matches"

echo "== 7. --dry-run changes nothing"
# A match starts a second or so after the game is seen (where its traffic
# comes from is checked first), and the gaps need a few seconds of it.
"$B" -c $W/cfg.toml --dry-run > $W/d5.log 2>&1 & D=$!; sleep 1; game 64 180; sleep 8
grep -q "would set" $W/d5.log && ok "dry run logs intended changes" || bad "dry run silent"
"$B" -c $W/cfg.toml --monitor 0 | grep -q 'connection: packet gaps half' && ok "dry run still measures the connection" || bad "dry run: no gap measurement"
same "dry run"; kill $G; kill -INT $D; wait $D; D=

echo "== 8. if the journal can't be written, nothing is changed"
mkdir -p $W/run8
sed "s#^run_dir = .*#run_dir = \"$W/run8\"#" $W/cfg.toml > $W/cfg8.toml
"$B" -c $W/cfg8.toml > $W/d8.log 2>&1 & D=$!; sleep 1
if mount --bind $W/run8 $W/run8 && mount -o remount,ro,bind $W/run8; then
  game 64 180; sleep 6
  grep -q "Match detected" $W/d8.log && ok "match still detected" || bad "no match with a read-only run dir"
  grep -q "could not write restore journal" $W/d8.log && ok "journal failure reported" || bad "journal failure not reported"
  same "mid-match with no journal"
  kill $G; umount $W/run8
else
  echo "  skip cannot make a read-only bind mount here"
fi
kill -INT $D; wait $D; D=

echo "== 9. bulk transfers during a match"
# "steam" downloads and "obs" uploads, both well over the rate; only the
# Steam-like download is bulk (OBS is on the never list).
cat $W/cfg.toml > $W/cfg9.toml
printf '[bulk]\nenabled = true\nmin_mbps = 2\nsecs = 2\nrelease_secs = 3\n' >> $W/cfg9.toml
"$B" -c $W/cfg9.toml > $W/d9.log 2>&1 & D=$!; sleep 1
game 64 180; sleep 5
$W/apps/steam $W/bulk.py down 10 40100 & BS=$!
$W/apps/obs $W/bulk.py up 10 40200 & BO=$!
sleep 5
grep -q "Bulk transfer during the match: steam" $W/d9.log && ok "a download during the match is bulk" || bad "steam not seen as bulk"
grep -q "Bulk transfer during the match: obs" $W/d9.log && bad "OBS upload treated as bulk" || ok "OBS upload left alone"
cap() { ip netns exec bpfrag-srv timeout 4 tcpdump -n -i bpfrag1 -c 40 -w $W/$1.pcap "$2" 2>/dev/null; python3 "$HERE/pcap_check.py" $W/$1.pcap; }
SB=$(cap bulk-acks 'tcp and src 10.99.0.1 and src port 40100')
echo "$SB" | grep -q "ipv4 dscp=1 csum=ok" && ! echo "$SB" | grep -q "dscp=0" && ok "the download's outgoing packets are marked LE" || bad "steam egress: $SB"
SO=$(cap obs-up 'tcp and src 10.99.0.1 and src port 40200')
echo "$SO" | grep -q "ipv4 dscp=0 csum=ok" && ! echo "$SO" | grep -q "dscp=1 " && ok "OBS's upload is not marked" || bad "obs egress: $SO"
# What a desktop CAKE would see: the download after the redirect to its IFB.
capi() { timeout 4 tcpdump -n -i bpfrag-ingress -c 40 -w $W/$1.pcap "$2" 2>/dev/null; python3 "$HERE/pcap_check.py" $W/$1.pcap; }
SI=$(capi bulk-down 'tcp and src 10.99.0.2 and dst port 40100')
echo "$SI" | grep -q "ipv4 dscp=1 csum=ok" && ! echo "$SI" | grep -q "dscp=0" && ok "the download reaches the IFB marked LE (before CAKE)" || bad "steam ingress: $SI"
SJ=$(capi obs-acks 'tcp and src 10.99.0.2 and dst port 40200')
echo "$SJ" | grep -q "ipv4 dscp=0 csum=ok" && ok "OBS's incoming packets are not marked" || bad "obs ingress: $SJ"
SG=$(cap game-bulk 'udp and dst port 27015 and src 10.99.0.1')
echo "$SG" | grep -q "ipv4 dscp=32" && ok "the game keeps CS4 alongside bulk traffic" || bad "game: $SG"
# (the rig's own server is a local process too, so it can show up as well)
"$B" -c $W/cfg9.toml --monitor 0 | grep -q "bulk: .*steam .*marked LE" && ok "monitor shows the bulk transfer" || bad "monitor: $("$B" -c $W/cfg9.toml --monitor 0 | grep bulk)"
kill $BS; sleep 5
grep -q "steam is no longer moving bulk data" $W/d9.log && ok "bulk released when the download stops" || bad "bulk not released"
$W/apps/steam $W/bulk.py up 0.5 40101 & BS=$!; sleep 1
SR=$(cap bulk-released 'tcp and src 10.99.0.1 and src port 40101')
echo "$SR" | grep -q "dscp=1 " && bad "still demoting after release: $SR" || ok "nothing demoted once released"
kill $BS $G; sleep 2
grep -q "fakeshooter: packet gaps.*; bulk: .*steam [0-9]* MB.* marked LE" $W/d9.log && ok "match summary says how much bulk was demoted" || bad "summary: $(grep 'fakeshooter: packet' $W/d9.log)"
kill $BO; kill -INT $D; wait $D; D=
same "after bulk match"

echo "== 10. bulk with --dry-run: reported, never marked"
"$B" -c $W/cfg9.toml --dry-run > $W/d10.log 2>&1 & D=$!; sleep 1
game 64 180; sleep 5
$W/apps/steam $W/bulk.py down 10 40102 & BS=$!; sleep 5
grep -q "Bulk transfer during the match: steam.*dry run: would mark LE" $W/d10.log && ok "dry run reports what it would demote" || bad "dry run bulk: $(grep -i bulk $W/d10.log)"
SD=$(cap dry-acks 'tcp and src 10.99.0.1 and src port 40102')
SE=$(capi dry-down 'tcp and src 10.99.0.2 and dst port 40102')
echo "$SD $SE" | grep -q "dscp=1 " && bad "dry run marked packets: $SD / $SE" || ok "dry run marks nothing in either direction"
kill $BS $G; kill -INT $D; wait $D; D=

echo "== 11. A/B experiment: the drawn arm decides, and is reported"
# keep = 0 always draws "off", keep = 1 always "on": deterministic arms.
for keep in 0 1; do
  { cat $W/cfg.toml; printf '[experiment]\nsetting = "busy_polling"\nkeep = %s\n' $keep; } > $W/cfg11.toml
  "$B" -c $W/cfg11.toml > $W/d11.log 2>&1 & D=$!; sleep 1
  game 64 180; sleep 6
  BP=$(sysctl -n net.core.busy_poll); BR=$(sysctl -n net.core.busy_read)
  MON=$("$B" -c $W/cfg11.toml --monitor 0)
  kill $G; sleep 2; kill -INT $D; wait $D; D=
  if [ $keep = 0 ]; then
    grep -q "Experiment: busy_polling off for this match" $W/d11.log && ok "arm logged when the match starts" || bad "no arm: $(grep -i experiment $W/d11.log)"
    [ "$BP" = 0 ] && [ "$BR" = 0 ] && ok "off arm: busy polling left at the default" || bad "off arm set busy_poll=$BP busy_read=$BR"
    grep -q "net.core.netdev_budget=" $W/d11.log && ok "off arm: the other settings still applied" || bad "off arm changed nothing else: $(grep profile: $W/d11.log)"
    echo "$MON" | grep -q "experiment: busy_polling off" && ok "--monitor shows the arm" || bad "monitor: $MON"
    grep -q "fakeshooter: packet gaps.*; experiment: busy_polling off" $W/d11.log && ok "match summary ends with the arm" || bad "summary: $(grep 'fakeshooter: packet' $W/d11.log)"
    grep "fakeshooter: packet gaps" $W/d11.log | grep -q "busy-polled" && bad "busy-polled count shown with busy polling off: $(grep 'fakeshooter: packet' $W/d11.log)" || ok "off arm: no busy-polled count (busy polling never on)"
  else
    [ "$BP" = 50 ] && ok "on arm: busy_poll=50 as usual" || bad "on arm busy_poll=$BP"
    grep -Eq "fakeshooter: packet gaps.*; busy-polled packets: [0-9]+;" $W/d11.log && ok "on arm: the summary counts busy-polled packets" || bad "busy-polled: $(grep 'fakeshooter: packet' $W/d11.log)"
  fi
done
same "after experiments"
python3 "$HERE/../../docs/scripts/matches.py" - < $W/d11.log | grep -q ",busy_polling,on," && ok "matches.py reads the arm" || bad "matches.py: $(python3 "$HERE/../../docs/scripts/matches.py" - < $W/d11.log)"

echo "== 11b. the experiment's all-off arm changes nothing and still measures"
{ cat $W/cfg.toml; printf '[experiment]\nsetting = "all"\nkeep = 0\n' ; } > $W/cfg11b.toml
"$B" -c $W/cfg11b.toml > $W/d11b.log 2>&1 & D=$!; sleep 1
game 64 180; sleep 9
same "during an all-off match"
kill $G; sleep 2; kill -INT $D; wait $D; D=
grep -q "Experiment: all off for this match" $W/d11b.log && ok "all-off arm drawn and logged" || bad "arm: $(grep -i experiment $W/d11b.log)"
grep -Eq "already tuned|no game traffic seen" $W/d11b.log && bad "misleading log lines: $(grep -E 'already tuned|no game traffic seen' $W/d11b.log)" || ok "no 'already tuned' or path messages when nothing is applied"
grep -q "fakeshooter: packet gaps half.*experiment: all off" $W/d11b.log && ok "the all-off match is still measured" || bad "summary: $(grep 'fakeshooter: packet' $W/d11b.log)"

echo "== 11c. a random experiment: one setting per day, kept across restarts"
# A one-setting pool makes the pick predictable; keep = 0 makes every
# match its "off" match.
{ cat $W/cfg.toml; printf '[experiment]\nsetting = "random"\npool = ["backlog"]\nkeep = 0\n'; } > $W/cfg11c.toml
"$B" -c $W/cfg11c.toml > $W/d11c.log 2>&1 & D=$!; sleep 1
grep -q "Experiment for today: backlog, switched off in 100% of matches (picked at random from the configured pool: backlog)" $W/d11c.log && ok "today's setting picked at start" || bad "pick: $(grep -i experiment $W/d11c.log)"
grep -q '"setting":"backlog"' $W/state/experiment.json 2>/dev/null && ok "the pick is saved in the state directory" || bad "state: $(cat $W/state/experiment.json 2>&1)"
kill -INT $D; wait $D
"$B" -c $W/cfg11c.toml > $W/d11c2.log 2>&1 & D=$!; sleep 1
grep -q "Experiment for today: backlog, .*(picked earlier today)" $W/d11c2.log && ok "a restart keeps today's pick" || bad "restart: $(grep -i experiment $W/d11c2.log)"
BL=$(sysctl -n net.core.netdev_max_backlog)
game 64 180; sleep 6
grep -q "Experiment: backlog off for this match" $W/d11c2.log && ok "matches draw arms for today's setting" || bad "arm: $(grep -i 'experiment' $W/d11c2.log)"
[ "$(sysctl -n net.core.netdev_max_backlog)" = "$BL" ] && ok "off arm: backlog left alone" || bad "backlog changed to $(sysctl -n net.core.netdev_max_backlog)"
[ "$(sysctl -n net.core.busy_poll)" = 50 ] && ok "off arm: the other settings still applied" || bad "busy_poll $(sysctl -n net.core.busy_poll)"
kill $G; sleep 2; kill -INT $D; wait $D; D=
"$B" -c $W/cfg11c.toml --check 2>/dev/null | grep -q "experiment .*random, one setting per day (now: backlog)" && ok "--check shows today's pick" || bad "check: $("$B" -c $W/cfg11c.toml --check 2>&1 | grep -i experiment)"
same "after random experiment"

echo "== 11d. games that talk TCP: observed, never tuned"
{ sed 's/^\[detect\]$/[detect]\ntcp = "observe"/' $W/cfg.toml; } > $W/cfg11d.toml
"$B" -c $W/cfg11d.toml > $W/d11d.log 2>&1 & D=$!; sleep 1
SteamAppId=4243 $W/steamapps/common/FakeMMO/fakemmo $W/tcpgame.py 20 & TG=$!
$W/apps/randomd $W/tcpgame.py 20 & TN=$!
sleep 14
grep -q "TCP game seen: fakemmo (pid $TG) at ~2[0-9] sends/s and ~2[0-9] receives/s \[Steam app 4243\]; observing only" $W/d11d.log && ok "a TCP game is seen at its message rate" || bad "seen: $(grep -i 'tcp game' $W/d11d.log)"
grep -q "TCP game seen: randomd" $W/d11d.log && bad "a non-game was reported" || ok "TCP from a non-game process isn't reported"
grep -q "Match detected" $W/d11d.log && bad "a TCP game started a match" || ok "nothing tuned for it"
same "while a TCP game is observed"
kill $TG $TN; sleep 2
grep -q "TCP game session: fakemmo for [0-9]*s: typically 2[0-9] sends/s and 2[0-9] receives/s, 9[0-9] and 9[0-9] bytes each" $W/d11d.log && ok "its session is summed up when it exits" || bad "summary: $(grep -i 'tcp game' $W/d11d.log)"
kill -INT $D; wait $D; D=

echo "== 11e. BPFRAG_OBSERVE: a tagged process's UDP and TCP are logged"
# randomd is no game by any signal and tcp is off: the tag alone gets its
# traffic logged. /proc is listed every 5 s, and a session is reported
# after 10 s of traffic.
"$B" -c $W/cfg.toml > $W/d11e.log 2>&1 & D=$!; sleep 1
BPFRAG_OBSERVE=1 $W/apps/randomd $W/tcpgame.py 20 & TT=$!
BPFRAG_OBSERVE=1 $W/apps/randomd $W/client.py 30 120 & TU=$!
BPFRAG_OBSERVE=0 $W/apps/randomd $W/tcpgame.py 20 & TN=$!
sleep 22
grep -q "Observing randomd (pid $TT): TCP at ~2[0-9] sends/s and ~2[0-9] receives/s \[BPFRAG_OBSERVE=1\]" $W/d11e.log && ok "a tagged process's TCP is logged with tcp off" || bad "tcp: $(grep -i observ $W/d11e.log)"
grep -q "Observing randomd (pid $TU): UDP at ~[23][0-9] sends/s and ~[23][0-9] receives/s" $W/d11e.log && ok "a tagged process's UDP is logged" || bad "udp: $(grep -i observ $W/d11e.log)"
grep -q "pid $TN" $W/d11e.log && bad "an untagged process was logged" || ok "BPFRAG_OBSERVE=0 isn't a tag"
grep -q "Match detected" $W/d11e.log && bad "the tag started a match" || ok "the tag changes nothing else (no match for a non-game)"
"$B" -c $W/cfg.toml --monitor 0 2>&1 | grep -A3 "Observing (BPFRAG_OBSERVE=1)" | grep -q "randomd (pid $TT): TCP" && ok "--monitor lists what is being observed" || bad "monitor: $("$B" -c $W/cfg.toml --monitor 0 2>&1 | grep -A3 -i observ)"
"$B" -c $W/cfg.toml --classify $TT 2>&1 | grep -q "tagged BPFRAG_OBSERVE=1" && ok "--classify shows the tag" || bad "classify: $("$B" -c $W/cfg.toml --classify $TT 2>&1)"
same "while tagged processes are observed"
kill $TT $TU $TN; sleep 2
grep -q "Observed randomd (pid $TT): TCP for [0-9]*s: typically 2[0-9] sends/s and 2[0-9] receives/s, 9[0-9] and 9[0-9] bytes each" $W/d11e.log && ok "its TCP session is summed up when it exits" || bad "tcp summary: $(grep -i observed $W/d11e.log)"
grep -q "Observed randomd (pid $TU): UDP for [0-9]*s: typically [23][0-9] sends/s and [23][0-9] receives/s, 120 and 120 bytes each" $W/d11e.log && ok "its UDP session is summed up when it exits" || bad "udp summary: $(grep -i observed $W/d11e.log)"
kill -INT $D; wait $D; D=

echo "== 11f. the game's server: followed, changes logged, a timeline written"
{ cat $W/cfg.toml; printf '[capture]\ntimeline = true\nkeep = 3\n'; } > $W/cfg11f.toml
"$B" -c $W/cfg11f.toml > $W/d11f.log 2>&1 & D=$!; sleep 1
# The same socket moves to a second server after 10 s without a pause,
# like back-to-back games.
export DEST2=10.99.0.3 SWITCH_AFTER=10; game 64 180; unset DEST2 SWITCH_AFTER
sleep 18
grep -Eq "fakeshooter: receiving from server A:27015 on local port [0-9]+ \(~[0-9]+ pkt/s\)" $W/d11f.log && ok "the first server is logged" || bad "first: $(grep -i server $W/d11f.log)"
grep -Eq "fakeshooter: server changed from A:27015 \(now ~[0-9]+ pkt/s\) to B:27015 on local port [0-9]+" $W/d11f.log && ok "the move to a new server is logged" || bad "change: $(grep -i server $W/d11f.log)"
grep -q "10\.99\.0\.[23]" $W/d11f.log && bad "server addresses logged at info: $(grep '10\.99' $W/d11f.log)" || ok "no server addresses at info"
grep -q "Match ended" $W/d11f.log && bad "the match ended at the server change" || ok "still one match (no quiet spell to end it)"
kill $G; sleep 2; kill -INT $D; wait $D; D=
grep -q "fakeshooter: packet gaps.*; the game's server changed once" $W/d11f.log && ok "the summary counts the server change" || bad "summary: $(grep 'fakeshooter: packet' $W/d11f.log)"
CSV=$(ls $W/run/captures/*_fakeshooter.csv 2>/dev/null | head -1)
if [ -n "$CSV" ]; then
  ok "a timeline was written ($(basename "$CSV"))"
  grep -q "fakeshooter: timeline written to $CSV" $W/d11f.log && ok "its path is logged" || bad "path: $(grep timeline $W/d11f.log)"
  head -1 "$CSV" | grep -q "^# bpfrag .*fakeshooter (pid $G) \[Steam app 4242\]; experiment: none" && ok "timeline header names the game" || bad "header: $(head -1 "$CSV")"
  sed -n 2p "$CSV" | grep -q "^t,unix,tier,udp_tx_pps,udp_rx_pps," && ok "timeline columns" || bad "columns: $(sed -n 2p "$CSV")"
  [ "$(grep -vc '^#' "$CSV")" -ge 15 ] && ok "about a row a second" || bad "rows: $(grep -vc '^#' "$CSV")"
  awk -F, 'NR > 2 && $10 == "B:27015" && $4 >= 50' "$CSV" | grep -q . && ok "rows name the new server, with the game's rates" || bad "rows: $(tail -3 "$CSV")"
  grep -q "server A:27015 -> B:27015" "$CSV" && grep -q "match ended (game exited)" "$CSV" && ok "server change and match end are events" || bad "events: $(cut -d, -f18- "$CSV" | sort -u)"
  grep -q "10\.99\." "$CSV" && bad "addresses in the timeline" || ok "no addresses in the timeline"
else
  bad "no timeline in $W/run/captures: $(ls -la $W/run/captures 2>&1)"
fi

echo "== 11g. a game talking to itself (a menu server) isn't a match; its games are"
{ cat $W/cfg.toml; printf '[capture]\ntimeline = true\n'; } > $W/cfg11g.toml
rm -rf $W/run/captures
"$B" -c $W/cfg11g.toml > $W/d11g.log 2>&1 & D=$!; sleep 1
# Its own server on 127.0.0.1 (as Deadlock's menu), then a game on the real
# server, the menu again, and the next game.
export PHASES="local:12,remote:22,local:30,remote:30"; game 64 180; unset PHASES
sleep 10
grep -q "fakeshooter (pid $G): its traffic stays on this machine" $W/d11g.log && ok "traffic over loopback is recognised as the game talking to itself" || bad "local: $(cat $W/d11g.log)"
grep -q "Match detected" $W/d11g.log && bad "a match started on loopback traffic" || ok "no match while the game talks to itself"
same "while the game talks to itself"
"$B" -c $W/cfg11g.toml --monitor 0 2>&1 | grep -q "fakeshooter (pid $G) is running, its traffic staying on this machine" && ok "--monitor says why nothing is tuned" || bad "monitor: $("$B" -c $W/cfg11g.toml --monitor 0 2>&1 | head -6)"
sleep 11   # 21 s in: on the real server since 12
[ "$(grep -c 'Match detected: fakeshooter' $W/d11g.log)" = 1 ] && ok "traffic from outside starts the match" || bad "starts: $(grep -i 'match\|stays' $W/d11g.log)"
[ "$(sysctl -n net.core.busy_poll)" = 50 ] && ok "tuned during the game, at the game's tier (not the menu's)" || bad "busy_poll $(sysctl -n net.core.busy_poll): $(grep 'Match detected' $W/d11g.log)"
sleep 37   # 58 s in: back on its own server since 34
grep -q "Match ended after [0-9]*s (its traffic stayed on this machine for 6s: a menu or a local server); settings restored" $W/d11g.log && ok "back to the menu ends the match" || bad "end: $(grep -i 'match' $W/d11g.log)"
same "in the menu between games"
sleep 12   # 70 s in: the next game since 64
[ "$(grep -c 'Match detected: fakeshooter' $W/d11g.log)" = 2 ] && ok "the next game is a match of its own" || bad "starts: $(grep -i 'match' $W/d11g.log)"
kill $G; sleep 2; kill -INT $D; wait $D; D=
[ "$(ls $W/run/captures/*_fakeshooter.csv 2>/dev/null | wc -l)" = 2 ] && ok "a timeline per game, in the run directory" || bad "timelines: $(ls -la $W/run/captures 2>&1)"
same "after the menu server"

echo "== 12. D-Bus: read-only interface, readable by anyone"
if command -v dbus-daemon >/dev/null && command -v dbus-monitor >/dev/null && command -v busctl >/dev/null; then
  # A private bus with the system bus's default policy plus ours. The
  # abstract socket needs no directory a non-root user can reach.
  ADDR="unix:abstract=bpfrag-e2e-$$"
  cat > $W/bus.conf <<EOT
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <listen>$ADDR</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow user="*"/>
    <deny own="*"/>
    <deny send_type="method_call"/>
    <allow send_type="signal"/>
    <allow send_requested_reply="true" send_type="method_return"/>
    <allow send_requested_reply="true" send_type="error"/>
    <allow receive_type="method_call"/>
    <allow receive_type="method_return"/>
    <allow receive_type="error"/>
    <allow receive_type="signal"/>
    <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus"/>
    <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus.Introspectable"/>
  </policy>
  <policy user="root">
    <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus.Monitoring"/>
  </policy>
  <include>$HERE/../../dist/com.performativenonsense.Bpfrag1.conf</include>
</busconfig>
EOT
  dbus-daemon --nofork --config-file=$W/bus.conf > $W/busd.log 2>&1 & BUSD=$!; sleep 0.5
  OBJ="com.performativenonsense.Bpfrag1 /com/performativenonsense/Bpfrag1"
  IFC=com.performativenonsense.Bpfrag1
  # An unprivileged reader.
  asuser() { setpriv --reuid=65534 --regid=65534 --clear-groups busctl --address=$ADDR "$@"; }
  sed 's/^dbus = false$/dbus = true/' $W/cfg.toml > $W/cfg12.toml
  DBUS_SYSTEM_BUS_ADDRESS=$ADDR "$B" -c $W/cfg12.toml > $W/d12.log 2>&1 & D=$!; sleep 1
  grep -q "D-Bus: publishing com.performativenonsense.Bpfrag1" $W/d12.log && ok "name owned on the bus" || bad "not published: $(grep D-Bus $W/d12.log)"
  [ "$(asuser get-property $OBJ $IFC InMatch 2>&1)" = "b false" ] && ok "another user reads InMatch=false before a match" || bad "idle read: $(asuser get-property $OBJ $IFC InMatch 2>&1)"
  dbus-monitor --address $ADDR "type='signal',interface='$IFC'" "type='signal',member='PropertiesChanged'" > $W/mon.log 2>&1 & MONP=$!; sleep 0.5
  echo 64 > $W/rate; game 64 180 $W/rate; sleep 6
  INTRO=$(asuser introspect $OBJ 2>&1)
  echo "$INTRO" | grep -q '^\.InMatch .* true' && echo "$INTRO" | grep -q '^\.Tier .*"competitive"' && ok "another user sees the match (InMatch, Tier)" || bad "introspect: $INTRO"
  echo "$INTRO" | grep -q '^\.Reason .*"Steam app 4242"' && ok "Reason says why it's a game" || bad "Reason: $(echo "$INTRO" | grep Reason)"
  [ "$(asuser get-property $OBJ $IFC State 2>&1)" = 's "match"' ] && ok "State=match" || bad "State: $(asuser get-property $OBJ $IFC State 2>&1)"
  [ "$(asuser get-property $OBJ $IFC AppId 2>&1)" = "u 4242" ] && ok "AppId is the Steam app id" || bad "AppId: $(asuser get-property $OBJ $IFC AppId 2>&1)"
  STARTED=$(asuser get-property $OBJ $IFC MatchStartedAt 2>&1 | awk '{print $2}')
  SINCE=$(asuser get-property $OBJ $IFC MatchSince 2>&1 | awk '{print $2}')
  NOWMS=$(date +%s%3N)
  [ -n "$STARTED" ] && [ "$STARTED" -gt $((NOWMS - 15000)) ] && [ "$STARTED" -lt $((SINCE * 1000)) ] && ok "MatchStartedAt is when the traffic began, before MatchSince ($(( SINCE * 1000 - STARTED )) ms)" || bad "MatchStartedAt $STARTED, MatchSince $SINCE, now $NOWMS"
  asuser get-property $OBJ $IFC Applied 2>&1 | grep -q '"net.core.busy_poll" "50"' && ok "Applied lists the settings changed" || bad "Applied: $(asuser get-property $OBJ $IFC Applied 2>&1)"
  asuser set-property $OBJ $IFC Tier s intense > $W/set.out 2>&1 && bad "another user could Set a property" || ok "another user can't Set (policy: $(head -c 60 $W/set.out))"
  busctl --address=$ADDR set-property $OBJ $IFC Tier s intense > $W/set0.out 2>&1 && bad "root could Set a property" || ok "root can't Set either"
  asuser call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus RequestName su $IFC 4 > $W/own.out 2>&1 && bad "another user could own the name: $(cat $W/own.out)" || ok "another user can't take the name"
  echo 150 > $W/rate; sleep 10
  kill $G; sleep 2
  [ "$(asuser get-property $OBJ $IFC InMatch 2>&1)" = "b false" ] && ok "InMatch=false after the match" || bad "after: $(asuser get-property $OBJ $IFC InMatch 2>&1)"
  grep -q "member=MatchStarted" $W/mon.log && ok "MatchStarted signal" || bad "no MatchStarted"
  grep -A4 "member=TierChanged" $W/mon.log | grep -q 'string "intense"' && ok "TierChanged to intense" || bad "no TierChanged"
  grep -A4 "member=MatchEnded" $W/mon.log | grep -q 'string "game exited"' && ok "MatchEnded says the game exited" || bad "MatchEnded: $(grep -A8 member=MatchEnded $W/mon.log)"
  grep -A60 "member=MatchEnded" $W/mon.log | grep -q 'string "gap_p50_ms"' && ok "MatchEnded carries the match health" || bad "no health in MatchEnded"
  grep -q "member=PropertiesChanged" $W/mon.log && ok "PropertiesChanged signals" || bad "no PropertiesChanged"
  [ "$(asuser get-property $OBJ $IFC State 2>&1)" = 's "idle"' ] && ok "State=idle after the match" || bad "State after: $(asuser get-property $OBJ $IFC State 2>&1)"
  grep -A1 "member=StateChanged" $W/mon.log | grep -q 'string "match"' && grep -A30 "member=StateChanged" $W/mon.log | grep -q 'string "at_ms"' && ok "StateChanged to match, with at_ms" || bad "StateChanged match: $(grep -A20 member=StateChanged $W/mon.log | head -40)"
  grep -A40 "member=StateChanged" $W/mon.log | grep -q 'string "match_ended_at_ms"' && ok "StateChanged back to idle says when the match ended" || bad "StateChanged idle: $(grep -A40 member=StateChanged $W/mon.log | tail -40)"
  # Shutting down mid-match ends the match for listeners too.
  game 64 180; sleep 6; kill -INT $D; wait $D; D=; sleep 0.5; kill $G
  grep -A4 "member=MatchEnded" $W/mon.log | grep -q 'string "bpfrag stopped"' && ok "stopping bpfrag mid-match sends MatchEnded" || bad "no MatchEnded on shutdown"
  grep -A40 "member=StateChanged" $W/mon.log | grep -A1 'string "end_reason"' | grep -q 'bpfrag stopped' && ok "and StateChanged to idle" || bad "no StateChanged on shutdown"
  kill $MONP; MONP=
  # No bus at all: logged, and the daemon carries on.
  DBUS_SYSTEM_BUS_ADDRESS="unix:abstract=bpfrag-e2e-none-$$" "$B" -c $W/cfg12.toml > $W/d12b.log 2>&1 & D=$!; sleep 1
  game 64 180; sleep 6; kill $G; sleep 2; kill -INT $D; wait $D; D=
  grep -q "D-Bus: system bus not available" $W/d12b.log && grep -q "Match detected" $W/d12b.log && ok "no bus: logged, matches still handled" || bad "no bus: $(head -5 $W/d12b.log)"
  kill $BUSD; BUSD=
  same "after D-Bus"
else
  echo "  skip D-Bus: needs dbus-daemon, dbus-monitor and busctl"
fi

echo; echo "passed $PASS, failed $FAIL"
[ $FAIL = 0 ]
