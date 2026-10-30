# Findings

What has been observed, measured or found wrong, newest first, with
enough detail to check it. [knobs.md](knobs.md) has the reasoning behind
each setting; this page is the evidence. Add results with the protocol in
[measuring.md](measuring.md), and record "no difference" results too:
they're what justifies dropping a setting. Results from other people come
in through the "Share match data" issue form.

## Match comparisons

None yet. Each entry should give the setup (`bpfrag --report` covers it),
the two conditions, the number of matches on each side, and the medians.

| Date | Setup | A vs B | Matches A / B | 99% gap (median) A / B | Longest (median) A / B | Stalls (median) A / B | Conclusion |
|---|---|---|---|---|---|---|---|
| | | | | | | | |

## Single matches

Matches worth recording that aren't a comparison yet: they show what a
setup looks like and set a baseline for one.

**2026-10-28: Deadlock on Ethernet with an unmarked torrent download.**
CachyOS, kernel 7.3, wired (`eno1`), bpfrag 0.3.0 tuning at INTENSE most of
the match, bpftune running. ktorrent moved 4.8 GB during a 38-minute match
(about 17 Mbit/s on average), with `[bulk]` off so it wasn't marked. Packet
gaps: half ≤14 ms, 99% ≤18 ms, longest 95 ms, 0 stalls. Socket buffer
drops: 2921, machine-wide; 0.3.0 couldn't say whose (probably ktorrent's
uTP sockets). The line is about 950 Mbit/s down and 100 Mbit/s up, through
a UniFi gateway and switches on default settings (no Smart Queues), so
nothing on the path shaped traffic or looked at DSCP, and the download
used under 2% of the line. With no queue anywhere there was nothing to
protect the game from: a clean match here says the line has headroom,
not that demotion is unnecessary. A useful test on this line would load
the 100 Mbit/s upload (seeding with no upload limit), where a queue can
form, and read the game's ping or net graph alongside bpfrag's numbers:
the arrival meter only sees incoming packets.

### Back-to-back games

**2026-10-29: five or six Deadlock Street Brawl games became one match.**
bpfrag 0.7.2, wired. Played one after another without closing the game,
they were logged as one match of 1h49m. Between games the traffic never
dropped under about 75 packets a second, so the quiet check (10 packets a
second or fewer for 15 seconds) never fired, and the game only exited at
the end. The games are still visible in the tier-change lines: each seems
to end with a few seconds of equal traffic both ways, about 105 packets a
second each way (tx 99 to 110, rx 101 to 111), where play has the game
sending 32 or 64. That pattern turned up six times, the last 6 seconds
before the game exited, giving games of 13 to 22 minutes, which fits
Street Brawl. The same pattern appears twice in a 54-minute "match" on
2026-10-28, which was probably several games too. What would mark the
boundary reliably is [experiment 22](experiments.md#22-back-to-back-games).

**2026-10-30: the "end-of-game pattern" is Deadlock's menu talking to
itself.** A timeline (bpfrag with `[capture] timeline`) of a 44-minute
session: two games, on servers A and B (the second on a new local
socket), and between and around them, 128 packets a second each way,
equal to the packet, for 15 seconds before the first game, 75 seconds
between the two, and 11 minutes after the second until the game was
closed. None of it arrived on the network card: the arrival meter on
`eno1` saw nothing, so it went over loopback, the game sending to and
receiving from a server of its own (for its menu). Counted as UDP like
any other, that looked like an INTENSE match, so bpfrag kept the match
going, tuned, through the menu, and two games became one. 0.8.0 only
counts traffic that reaches the network ([detection.md](detection.md)).
The same timeline showed the gap figures following the wrong socket in a
merged session: they tracked the socket with the most packets over the
whole session, so the second game's gaps weren't measured; they now
cover every socket carrying the match. A second timeline that morning
(one game) showed the same: 62 seconds of local traffic before the game,
19 minutes on server A, 26 seconds of local traffic before the game was
closed. Both show how a Deadlock game ends on the wire: for about 15
seconds the server sends more and larger packets (up to 165 a second,
about 1 KB each, 2 ms apart; end-of-game data, probably), then 32
updates a second instead of 64 for about 10 seconds, then the switch to
loopback.

The same session had busy polling on throughout (`[experiment]`
`busy_polling`, "on" arm): 160,405 busy-polled packets, about 24 a
second, machine-wide. So busy polling does run on this machine during
matches, but the count can't say whose packets they were
([experiment 1](experiments.md#1-does-busy-polling-reach-the-game)).

**2026-10-30: the first matches on 0.8.0, and what a Deadlock bot match
looks like.** A bot match at 13:55 (14m39s) was detected from its
traffic from outside and nothing else: no tuning in the menu before or
after, one match, no server changes, ended when the game was closed.
Bot matches are a different kind of traffic from matches against
people, and both belong in the data:

| | Against people (10:07, game 1) | Bot match (13:55) |
|---|---|---|
| Game sends | 64 a second (32 while dead) | 32 a second throughout |
| Server sends | about 64 a second, 200–400 bytes | about 64 a second, ~1 KB, in pairs about 2 ms apart, a pair every ~31 ms |
| Packet gaps, half / 99% | ≤14–16 ms / ≤31 ms | ≤3 ms / ≤33 ms |
| Seconds with a gap of 40 ms+ | 3 in 19 min | 12 in 14.5 min |
| Typical download | 94 KB/s | 60 KB/s |
| The game's own TCP | 3.5 MB | 2.5 MB |

So the bot server runs at about 32 updates a second, each split over two
packets, and "half ≤3 ms" is the gap inside a pair, not the update rate
([measuring.md](measuring.md#what-the-numbers-measure)). Its one stall
came 8 seconds in, during a second of about 490 packets and 575 KB,
probably the match's data loading. Every Deadlock game so far also
talked TCP throughout, 2.5 to 5.4 MB a game, spread over the match
rather than one download.

Busy polling (on that day) counted about 97 packets a second
machine-wide during the bot match, while the game received about 64,
against 53 a second in the morning session with the game receiving
about 127: the count doesn't follow the game's traffic, so most of it is
probably other programs'.

## Games observed

Games logged with `BPFRAG_OBSERVE=1` or `tcp = "observe"`
([detection.md](detection.md#observing-one-game-bpfrag_observe1)): what
their traffic looks like, before deciding whether and how to detect and
tune them ([experiments.md](experiments.md#20-tcp-games)).

**2026-10-29: Path of Exile 2 talks TCP.** CachyOS, wired, bpfrag 0.7.0,
the game started from Steam (Proton) with `BPFRAG_OBSERVE=1 %command%`,
about a minute and a half in the game, probably logging in and in town.
The game process had one TCP session and no UDP session (one is reported
after 10 seconds of traffic, or a megabyte):

```
Observed Path of Exile 2 (PathOfExileSteam, pid 1329391): TCP for 1m34s: typically 27 sends/s and 30 receives/s, 14 and 68 bytes each, rate variation 0.27, <1 MB in all
```

About 30 small messages a second each way, roughly 0.4 KB/s up and 2 KB/s
down, so the packets are mostly headers. The rate was fairly steady from
second to second (a download is far above 1 on that measure); the first
10 seconds were slower, about 14 sends a second. At that rate the
connection rarely has 4 or more packets in flight, which the kernel calls
a thin stream ([experiments.md](experiments.md#21-thin-stream-tcp-timeouts)).
Nothing was tuned: match detection only looks at UDP. Not known yet:
whether the rate changes in maps and fights, and whether this looks
different enough from other TCP (a browser, a chat client) to detect.

## Open questions

The questions the comparisons above should answer, in rough priority.
[experiments.md](experiments.md) has the longer list, with how to run
each:

1. **Does bulk demotion reduce the 99% gap and stalls during a download,**
   with CAKE on the machine or dscpclassify on the router?
2. **Does Wi-Fi power save cause stalls in real matches** on common
   drivers (iwlwifi, mt7921/mt7925)?
3. **Does busy polling change anything for real games,** native or under
   Proton? If not, it goes: it costs power.
4. **Do socket buffer, backlog or NIC drops ever happen during matches
   with the kernel defaults?** If not, the buffer, backlog and budget
   settings can go. For socket buffers, look at the game's own count
   (0.3.1 and later), not the machine-wide total.
5. **Is CS4 or EF better for the game's packets** with common router QoS
   setups? CAKE diffserv4 treats both as Voice; on Wi-Fi, EF maps to the
   voice category, CS4 to video.
6. **Should the bulk class be CS1 on Wi-Fi?** The kernel sends LE as best
   effort on Wi-Fi and CS1 as background (see [knobs.md](knobs.md#bulk-demotion-dscp-le)).

## Bugs found and what they taught

**0.5.0: a released bulk process could stay demoted** (found in an outside
review). When a process stopped moving bulk data, bpfrag dropped it from
`bulk_tgids` and then swept its flows out of `bulk_flows`; a packet sent in
between could learn a flow after the sweep's snapshot, and that flow stayed
demoted until the match ended. The sweep also cost two syscalls per map
entry, on the daemon's only thread. Fixed in 0.5.1 the way game ports
already worked: a flow is only demoted while its owner is in
`bulk_tgids`, so letting go takes effect at once and nothing is swept.
`--selftest` now re-adds flows after the release and checks they pass
unmarked (the old code demotes them).

**0.5.0: demoting incoming IPv6 bulk traffic left a stale receive checksum**
(found in the same review). On NICs that report `CHECKSUM_COMPLETE` (mostly
server NICs such as Mellanox; igc, r8169 and iwlwifi report
`CHECKSUM_UNNECESSARY`), the NIC's sum covers the IPv6 header, and rewriting
the traffic class without updating it made the kernel re-check those
packets in software and log "hw csum failure" once per boot. The packets
were still accepted (`__skb_checksum_complete()`, `net/core/skbuff.c`).
Fixed in 0.5.1 with `BPF_F_RECOMPUTE_CSUM`. IPv4 was never affected: a
correct header checksum update leaves the header's sum unchanged.

**0.4.0: consecutive matches merged into one.** Two Deadlock matches played
without quitting the game came out as a single 54-minute match, with one
health line and one experiment draw. A match ended after 15 seconds at 10
packets a second or fewer, judged one second at a time; in the menus the
game is mostly silent, but any second with a burst over 10 restarted the
count. Fixed in 0.4.1 by judging quiet on the median of the last five
seconds. Lesson: the same as the stall bug, from the other side; the time
between matches has to be modelled, not ignored.

**0.3.0: lobby keepalives counted as stalls.** A Deadlock session that
covered several matches, 2h28m in all, reported 1671 stalls and a longest
gap of 1000 ms; a 38-minute session that ended with its match reported 0
and 95 ms. Between matches Deadlock sends about one packet a second, and
every one of those 1 s gaps fell in the stall range (100 ms to 2 s). Fixed
in 0.3.1: a stall is the flow going quiet and coming back at game rate,
and a quiet stretch of 2 s or more isn't counted. The e2e rig now plays a
lobby at one packet a second between two real hiccups. Lesson: real
sessions aren't one match; the metric has to survive the time between
them.

**0.3.0: Wi-Fi power save toggled mid-session on a wired desktop.** While
Deadlock loaded or sat between matches for more than 30 s, the game's
egress interface "expired", bpfrag fell back to tuning every interface
and turned `wlan0` power save off, then back on when traffic resumed: 13
changes in one session. Fixed in 0.3.1: silence never moves the path; an
interface drops only when the game's packets go somewhere else.

**0.3.0: socket buffer drops couldn't be attributed.** The same sessions
showed 2921 and 11401 drops with a torrent client running. `RcvbufErrors`
is machine-wide, so they couldn't be pinned on the game. 0.3.1 also reads
the drop count of the game's own sockets.

**0.2.1: bpfrag switched off desktop CAKE's download shaping during
matches.** bpfrag's tc programs returned `TC_ACT_OK`, which for a tcx link
ends the chain, so the classic filter a desktop CAKE setup uses to redirect
downloads to its IFB never ran while a match was on. Found while reviewing
feedback about CAKE. The e2e rig now redirects through IFB devices: with
0.2.0 their packet counters froze as soon as a match started (3937 → 3937),
and with 0.2.1 they keep counting. Lesson: test alongside the QoS setups
people actually run.

**0.1.x: the egress interface flapped on a desktop with Ethernet and
Wi-Fi both up.** During Deadlock matches on a machine with `eno1` and
`wlan0`, per-interface settings toggled on `wlan0` for an hour. bpfrag
decided per packet which interface the game used, and stray packets on
the second link flipped it. Fixed by counting the game's packets per
interface and requiring a 10% share, with a 30 s hold. (The user also fixed
NetworkManager's route priorities.)

**0.1.1: `net.ipv4.udp_mem` values exceeded RAM.** The original profiles
set its hard limit to 32–128 GiB (it's counted in pages). It showed up
in `--monitor` output on a 32 GB machine. Removed: the kernel sizes it from
RAM already.

## Overhead

Measured with `kernel.bpf_stats_enabled` in a cloud VM, under the same load
for both versions: a 64-tick fake game plus 20 Mbit/s TCP each way. These
are averages per program run; bare metal is faster.

| Program | 0.2.0 | 0.3.0 (bulk on) | Notes |
|---|---|---|---|
| send tracepoint, no match | 0.96–0.98 µs | 0.52–0.76 µs | TCP returns early outside a match |
| receive tracepoint, no match | 0.38–0.56 µs | 0.53–0.59 µs | |
| send tracepoint, match + bulk | 0.75–0.86 µs | 1.1–1.3 µs | TCP counted, bulk sockets learned |
| receive tracepoint, match + bulk | 0.50–0.57 µs | 1.0–1.1 µs | |
| DSCP marker (egress, per packet) | 1.1–1.25 µs | 1.0–1.1 µs | |
| arrival meter (ingress, per packet) | 0.72–0.89 µs | 0.95–1.4 µs | TCP parsed, flow lookup while bulk |

A 20 Mbit/s download is about 2,000 packets a second, so the extra cost is
around a millisecond of CPU per second.

## Synthetic tests

The e2e rig (`tests/rig/e2e.sh`) plays a fake 64-tick game against an echo
server in a network namespace. It measures gaps of 15–18 ms, as it should,
and checks every setting changes and comes back. That proves bpfrag does
what it says, not that it helps a real game. The comparisons above are for
that.
