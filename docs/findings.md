# Findings

What has been observed, measured or found wrong, newest first, with
enough detail to check it. [knobs.md](knobs.md) has the reasoning behind
each setting; this page is the evidence. Add results with the protocol in
[measuring.md](measuring.md), and record "no difference" results too:
they're what justifies dropping a setting. Results from other people come
in through the "Share match data" issue form.

## Match comparisons

Each entry gives the setup (`bpfrag --report` covers it), the two
conditions, the number of matches on each side, and the medians.

| Date | Setup | A vs B | Matches A / B | 99% gap (median) A / B | Longest (median) A / B | Stalls (median) A / B | Conclusion |
|---|---|---|---|---|---|---|---|
| 2026-11-02 | CachyOS, wired (`eno1`), bpfrag 0.9.2 tuning, Deadlock, ktorrent seeding and downloading throughout (marked LE) | NIC coalescing on (0–10 µs) / off (NIC default) | 5 / 5 | 32 / 31 ms | 1016 / 573 ms | 2 / 1 | No difference in the gaps (1 ms resolution can't show a microsecond effect, and every stall and long gap was loading or the end screen). Busy polling did far less with coalescing on: 31–37 busy-polled packets a second against 114–192, no overlap (permutation p = 0.047 on medians) |
| 2026-11-03 | CachyOS, wired (`eno1`), bpfrag 0.11.1 tuning, Deadlock, coalescing at 10 µs in both arms, ktorrent seeding lightly (marked LE) | busy polling on (`busy_poll`/`busy_read` 25–50) / off | 3 / 2 | 18 / 17.5 ms | 41 / 38 ms | 0 / 0 | No difference in the gaps (1 ms resolution can't show it). Busy polling was active when on: 21–30 busy-polled packets a second, machine-wide, against 4 and then 0 when off. Too few matches; to be continued with coalescing at the NIC default |

**2026-11-03: sockets keep busy polling after a match.** In the busy
polling experiment, the first "off" match after an "on" one still had 4
busy-polled packets a second, and the next "off" match had none. The
kernel copies `busy_read` into a socket when it's created
(`sock_init_data_uid()`, `net/core/sock.c`), so sockets opened during an
"on" match keep busy-polling after bpfrag restores the sysctl, until
they close. An "off" match straight after an "on" one isn't fully off;
the effect fades as those sockets close. The same session confirmed
0.11.1: every match stayed COMPETITIVE after a short CASUAL start, each
ended 6 seconds after the menu came back, and every stall fell in the
first 25 seconds (loading); during play the longest gaps were 38–41 ms,
and 94 ms once, at a mid-game relay move.

**2026-11-02 evening: six more Deadlock matches** (three on 0.10.0,
three on 0.11.0; experiment: socket buffers). On 0.11.0 the meter counted
64 updates a second where 0.10.0 counted 108–119 packets, and the
per-second half-gap stayed at 16 ms. Two things it got wrong, fixed in
0.11.1: a relay-ping burst (the client pinging two dozen of Steam's
relays at once, 100 more packets a second for two seconds) moved a
64-tick match to INTENSE ten minutes in; and a 12-second menu between two
games, under the 15 seconds that ended a match, made them one 31-minute
match, its "server change" the second game. The relay moved mid-game,
with no break, in four of the six. The second game of that merged match
had the evening's only stall during play: incoming updates fell to 37 in
one second, then a burst of 455 packets in 2 ms gaps caught up, a real
hiccup on the path, not loading or the end screen. On 0.11.0 the health
lines read 99% ≤18 ms, where 0.10.0's read ≤31 ms for the same game: the
32-a-second stretches no longer set the figure. The socket-buffer
experiment (4 matches on, 2 off): the game's own sockets dropped nothing
either way, and the machine-wide drops ran at 1.07–1.14 a second in every
match whichever arm, so whatever overflows isn't the game and isn't
helped by bigger buffers. Not enough matches to call it, but nothing yet
for socket buffers to do here.

**2026-11-02: what that day showed beyond the comparison.** Same setup,
13 matches. Every stall and every longest gap of a second or more fell
in a match's first 50 seconds (loading arrives in bursts) or its last
second (the end screen): none during play, which 0.10.0's play-only
figures now leave out. Deadlock's 99% gap read ≤31–32 ms in every match,
set by stretches of 8–10 s at 32 updates a second (3–5% of the time);
while it sent 64 a second, ≤17 ms. The game's server changed twice
mid-match with no break (a new address and a new local port, the same
rate carrying straight on), most likely Steam's relays changing route:
not two games in one. The tier changed 10 or more times a match between
INTENSE and COMPETITIVE as the incoming rate swung between 50 and 150 a
second; none of 15 changes checked was followed by a stall or a gap
spike within 3 seconds, so re-applying settings didn't cause hiccups
([experiment 4](experiments.md#4-do-tier-changes-cause-hiccups)), but it
was pointless, and from 0.10.0 tiers only go up within a match. Socket
buffer drops ran at 1.03–1.13 a second in every match whatever ktorrent
was doing (1 to 58 Mbit/s), 0 of them the game's: probably a socket some
program never reads, not the torrent client. Two 18–19 second "matches"
when the game started (one second of traffic from outside while its menu
ran over loopback) are fixed in 0.10.0.

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

**2026-11-06: three Deadlock matches from a fresh start, and relay
changes.** bpfrag 0.12.2 tuning, wired, matches against people of 35 to
41 minutes; the busy polling experiment, on in two and off in one. The
game was launched fresh for each, and none started a "match" while it
pinged Steam's relays from the menu: 0.12.2's start rule held. All three
ran at 64 updates a second, 99% gap 17–18 ms over play, no stalls; on
and off look the same, as on 2026-11-03 (five on, three off between the
two days). Deadlock moved relays five times; three of the moves cost one
gap over 63 ms, under 100 ms, two to three seconds before bpfrag logged
the change (it names a server by its packet rate, which takes a moment
to move), and two cost nothing. The 1 ms histogram can't say how much
over 63 ms; from 0.12.3 the timeline gives such a gap's exact length.

**2026-11-05: two clean Deadlock matches, with pauses.** bpfrag 0.12.2
tuning, wired, backlog off in both (no comparison), matches against
people of 41 and 52 minutes. Both ran at 64 updates a second throughout:
99% gap 18 ms, longest 32 ms, no stalls in play; the one stall in each
fell in the opening load, while the game's TCP brought in up to 660 KB a
second. The second match had six long pauses of 20 to 90 seconds.
During a pause the server keeps sending all 64 updates a second, each
tiny (about 10 KB/s in, against 85–110 KB/s in play), unlike death or
the end screen (32 a second), so bpfrag counts a pause as play; the
timing didn't change through any of them. Both matches were in one
session of the game, so the startup case 0.12.2 fixed didn't come up.

**2026-11-04 evening: a bad server, and a false start.** bpfrag 0.12.0,
three Trackmania sessions and four Deadlock matches. In one Trackmania
session the game moved to a server (D:2415, by bpfrag's letters) that
sent about 35 updates a second instead of the usual 90, for six minutes,
with 83 stalls, while the client kept sending its usual 170 a second; the
game bounced between it and another server twice, and every other
server that evening ran clean. That's the server or its route, not this
machine: the kind of stretch the per-match figures exist to catch, but
the end-of-match line only sums it into the match. One Deadlock start
was a 10-second INTENSE "match" with no match: the game, just launched,
pinged three of Steam's relays for two seconds while its menu ran at 128
a second over loopback. 0.12.2 starts a match only when traffic from
outside outweighs the game's own loopback traffic.

**2026-11-04: Trackmania again, and five Deadlock matches on 0.12.0.**
Trackmania (24 minutes, three server changes) loaded a map in bursts: at
one server change the game's own TCP brought in 7.5 MB, then 850 and
680 KB in the next seconds, then 4.7, 28 and 35 MB, with stalls
throughout. 0.12.0 ended a load three seconds after the last megabyte,
so the stall in the 680 KB second counted as play; 0.12.1 keeps a load
going until the game is back at its usual rate. Two stalls remained
while racing, with the game's TCP at its usual 115 KB a second: real
hiccups. One more came as a race started (50 to 90 updates a second,
with a pause in between), as on 2026-11-03. The Deadlock matches (10 to
39 minutes, COMPETITIVE throughout) had every stall in their first 41
seconds; during play the longest gaps were under 64 ms, except at two
mid-game relay moves.

**2026-11-03: Trackmania, an hour of online rooms.** CachyOS, wired,
bpfrag 0.11.1, detected by its Steam app id and tuned at INTENSE: the
client sends about 200 packets a second while racing, the server about
90 (74 updates; half the gaps ≤11 ms, so roughly a 90-a-second server),
dropping to about 50 a second (20 ms gaps) between races. One match from
start to exit, with four server changes, three of them to another port
on the same host (2401, 2402, 2403: moving between rooms) and one to
another host and back. Unlike Deadlock it loads each map mid-session: UDP
stops for 2 to 4 seconds while the game pulls 10 to 65 MB a second over
its own TCP (2.4 GB over the hour). Six of the session's seven stalls
were those loads, and so was its 1.8 s longest gap; from 0.12.0 seconds
with that much of the game's own TCP are left out of the figures, which
on this session would have left one stall: the server going from 50 to
90 updates a second as a race started.

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

**0.10.0: the gap figures still measured the game, not the network**
(found in an outside review of the 2026-11-02 timelines). Gaps were
between packets, so a server splitting updates into 2–3 packets in a
fight halved the half-gap; Deadlock's 32-a-second stretches (dead, end
screen) pinned the 99% figure at 32 ms in any match where they made up
more than 1% of the gaps, so no A/B comparison could see it move; and
0.10.0's end of play was set by the last arrival, which relay pings
after the end screen moved, leaving 5–12 s of end screen in. The tier
had the same root: it counted packets, so Deadlock reached INTENSE only
in big fights. Fixed in 0.11.0: gaps between updates (packets within
4 ms of an update's first are part of it), half and 99% from seconds
at the game's usual rate, play ending five seconds before the last of
them, and the tier from the update rate. The coalescing comparison
above stands: it rests on the busy-polled count, not the gaps.

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
