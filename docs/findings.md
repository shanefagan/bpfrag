# Findings

What bpfrag's measurements have shown so far, on real matches. The
summary comes first; the dated log below it has the detail behind each
point. [knobs.md](knobs.md) has the reasoning behind each setting, and
[measuring.md](measuring.md) the protocol for adding results. "No
difference" results count too: they're what justifies dropping a
setting. Results from other people come in through the "Share match
data" issue form.

Most data so far is one wired CachyOS desktop on a gigabit line, playing
Deadlock, with some Trackmania.

## Summary

### Settings

- **NIC interrupt coalescing:** no difference in the packet gaps over 10
  matches (5 each way), as expected at 1 ms resolution. It does change
  busy polling: with coalescing at 0–10 µs, busy polling handled about a
  quarter as many packets.
- **Busy polling:** no difference in the gaps over 12 Deadlock matches
  (7 on, 5 off). It runs when on (20–30 packets a second, machine-wide). Sockets
  opened during an "on" match keep busy-polling after it, until they
  close, so an "off" match straight after an "on" one isn't fully off.
  Taken out of the profiles in 0.15.0: it costs CPU and power, and
  nothing in the figures paid for it.
- **Receive budget and backlog** (`netdev_budget*`,
  `netdev_max_backlog`): no difference in the gaps, jitter or stalls over
  19 Deadlock matches (2026-11-04 to -10). What made matches differ was the relay they were on.
- **Socket buffers:** the game's own sockets never dropped a packet in
  play, with or without bigger buffers (15 matches, 2026-11-02 to -08).
  The one time they did, 4 packets with the kernel's default buffers,
  Trackmania was closing: it stopped reading its socket for two seconds
  while the server kept sending. The machine-wide count (about one drop a
  second) belongs to something else and didn't change either way.
- **DSCP, bulk demotion, Wi-Fi power save:** not measured yet. On a
  wired line with no queue (as here), there's nothing for them to do.

### Games observed

- **Deadlock** (Valve, through Steam's relays): 64 updates a second
  against people, 32 while the player is dead, on the end screen, or in
  a bot match (where each update comes as two packets 2 ms apart). A
  pause keeps the full 64 a second, each update tiny. The game also
  talks TCP throughout (2.5–5 MB a game), loads over TCP in its first
  minute, runs its menu against a server of its own over loopback, and
  pings Steam's relays for a second or two as it starts. Its relay can
  change mid-game, with no break.
- **Trackmania:** the client sends about 200 packets a second while
  racing and the server about 90, dropping to about 50 between races.
  It stays in one session for an hour, moving between rooms (servers),
  and loads each map mid-session over TCP at 10–65 MB a second, with UDP
  paused for 2–4 seconds.
- **Path of Exile 2** talks only TCP: about 30 small messages a second
  each way, a thin stream. bpfrag doesn't tune TCP games yet
  ([experiment 20](experiments.md#20-tcp-games)).

### Back-to-back games

Deadlock goes from one game to the next without closing; between games
its menu talks to a server of its own over loopback, about 128 packets a
second each way. Counted like any other UDP, that kept a match going
across several games (one 1h49m "match" of five or six games). Since
0.8.0 only traffic from outside counts, and since 0.11.1 a match ends 6
seconds after the traffic moves to loopback, so each game is its own
match. A change of server can't mark the boundary on its own: it also
happens mid-game.

### Where hitches come from

On this line, almost none come from the machine:

- **Loading** (the first minute; Trackmania's maps mid-session) and the
  **end screen**: every stall and long gap before 0.10.0 was one of
  these. The figures now cover play only.
- **Relay changes** (Deadlock): sometimes one gap of 64–100 ms, a couple
  of seconds before bpfrag logs the change; sometimes nothing.
- **A lost connection:** twice in about 40 Deadlock matches, the server
  went silent mid-match; the game sent into nothing for ten seconds, went
  to its menu for five, and came back through a new relay, about 20
  seconds in all. From 0.12.4 the health line counts these.
- **A bad server:** a Trackmania server sent 35 updates a second instead
  of 90, with 83 stalls in six minutes, while every other server that
  evening ran clean.
- **The path:** rare. One stall in a dozen Deadlock matches (updates
  fell to 37 in a second, then a burst caught up), and two while racing
  in Trackmania.

Typical Deadlock play: 99% of gaps within 17–18 ms, longest 25–40 ms,
no stalls.

## Match comparisons

Each entry gives the setup (`bpfrag --report` covers it), the two
conditions, the number of matches on each side, and the medians.

| Date | Setup | A vs B | Matches A / B | 99% gap (median) A / B | Longest (median) A / B | Stalls (median) A / B | Conclusion |
|---|---|---|---|---|---|---|---|
| 2026-11-02 | CachyOS, wired (`eno1`), bpfrag 0.9.2 tuning, Deadlock, ktorrent seeding and downloading throughout (marked LE) | NIC coalescing on (0–10 µs) / off (NIC default) | 5 / 5 | 32 / 31 ms | 1016 / 573 ms | 2 / 1 | No difference in the gaps (1 ms resolution can't show a microsecond effect, and every stall and long gap was loading or the end screen). Busy polling did far less with coalescing on: 31–37 busy-polled packets a second against 114–192, no overlap (permutation p = 0.047 on medians) |
| 2026-11-03 | CachyOS, wired (`eno1`), bpfrag 0.11.1 tuning, Deadlock, coalescing at 10 µs in both arms, ktorrent seeding lightly (marked LE) | busy polling on (`busy_poll`/`busy_read` 25–50) / off | 3 / 2 | 18 / 17.5 ms | 41 / 38 ms | 0 / 0 | No difference in the gaps (1 ms resolution can't show it). Busy polling was active when on: 21–30 busy-polled packets a second, machine-wide, against 4 and then 0 when off |
| 2026-11-06 | CachyOS, wired (`eno1`), bpfrag 0.12.2 tuning, Deadlock, coalescing not recorded | busy polling on / off | 4 / 3 | 18 / 18 ms | 80 / 70 ms (relay changes) | 0 / 0 | No difference. Busy polling ran when on (90,000–300,000 busy-polled packets a match against 50–100 off). With 2026-11-03: 7 on, 5 off, the same gaps either way |
| 2026-11-09 | CachyOS, wired (`eno1`), bpfrag 0.14.0 tuning, Deadlock; figures from the timelines (each match's median of the per-second 99% gap, its longest gap in play) | `netdev_budget`/`netdev_budget_usecs` raised (on) / left at the distribution's (off) | 6 / 3 | 17.5 / 17 ms | 55 / 64 ms | 0 / 0 | No difference. Jitter 580–660 µs on against 480–860 µs off. The one stall (635 ms, an "on" match) was the server catching up, and the uneven match of the evening (an "off" one) was its relay |
| 2026-11-04 to -10 | The same, bpfrag 0.12.0 to 0.14.0 | `netdev_max_backlog` raised to 5000 (on) / left at CachyOS's 4096 (off) | 2 / 8 | 18 / 18 ms | 81 / 62 ms | 0 / 0 | No difference, with too few "on" matches to say more than that. The matches differed by relay: one "off" match on a worse one had 2.5 ms of jitter against 0.7–0.9 ms in the others. Taken out of the random pool in 0.15.0: on a NIC with NAPI and no RPS the queue it sizes isn't used ([knobs.md](knobs.md#netdev_max_backlog)), and here the default was already 4096 |

## Open questions

The questions the comparisons above should answer, in rough priority.
[experiments.md](experiments.md) has the longer list, with how to run
each:

1. **Does bulk demotion reduce the 99% gap and stalls during a download,**
   with CAKE on the machine or dscpclassify on the router?
2. **Does Wi-Fi power save cause stalls in real matches** on common
   drivers (iwlwifi, mt7921/mt7925)?
3. **Does busy polling change anything for real games,** native or under
   Proton? Not in 12 Deadlock matches, so bpfrag stopped setting it after
   0.14.1. Still open for a native game, or one that waits in `epoll`:
   set it in the config and run `setting = "busy_polling"`.
4. **Do socket buffer, backlog or NIC drops ever happen during matches
   with the kernel defaults?** If not, the buffer, backlog and budget
   settings can go. For socket buffers, look at the game's own count,
   not the machine-wide total.
5. **Is CS4 or EF better for the game's packets** with common router QoS
   setups? CAKE diffserv4 treats both as Voice; on Wi-Fi, EF maps to the
   voice category, CS4 to video.
6. **Should the bulk class be CS1 on Wi-Fi?** The kernel sends LE as best
   effort on Wi-Fi and CS1 as background (see [knobs.md](knobs.md#bulk-demotion-dscp-le)).

## Log

Newest first. Versions matter: the gap figures changed meaning in 0.10.0
(play only), 0.11.0 (gaps between updates, at the usual rate) and 0.12.0
(loading left out).

- **2026-11-07 and -08** (0.12.5, Deadlock and Trackmania, socket
  buffers on and off): Deadlock clean (99% 18 ms, no stalls). Trackmania
  changed rooms up to nine times a session; around each change the client
  stops sending while the old room's server trickles in, then the new map
  arrives over TCP. Gaps there counted as stalls when the load hadn't yet
  started by TCP's measure, and a single second at the race's gap in the
  countdown ended a load early; twice a 16-second pause for a map load
  ended the match, and the session went on as a new one ten seconds later.
  0.12.6 tells loading from play by what the game does (sending, TCP,
  sending with nothing back) and doesn't end a match on quiet while the
  game is loading. Two hiccups while racing (185 and 101 ms) were real.
- **2026-11-06 evening** (0.12.2, five Deadlock matches and two
  Trackmania sessions): the 19:42 match lost its server at 19 minutes:
  the game sent for ten seconds with nothing back, went to its menu for
  five, and came back through a new relay 20 seconds after it stopped
  hearing the server. The same happened at 17:12 on 2026-11-04. The
  health line showed two stalls, the longest 2 seconds, as the new flow
  started; the 20 seconds didn't show (the old flow never came back, so
  its gap never ended). 0.12.4 counts such stretches. Both times, about
  two minutes after reconnecting, the game pinged a handful of relays
  for half a minute, sending 80 packets a second instead of 64, and the
  tier went to INTENSE for the rest of the match; 0.12.4 judges the tier
  on the server's traffic only. A 2-minute game at 18:57 (a match that
  ended early) was detected and ended cleanly. Trackmania's stalls were
  all map loads.
- **2026-11-06** (0.12.2, three Deadlock matches, each from a fresh
  launch): no false start from the relay pings in these three. But an
  earlier launch, at 11:18, was a 10-second "match": the game pinged
  relays before its menu server was up, so there was no loopback for them
  to outweigh. From 0.12.5 nothing in a game's first 20 seconds starts a
  match. Clean play (99% 17–18 ms, no stalls). Five relay changes: three
  cost one gap over 63 ms, two cost nothing. From 0.12.3 the timeline
  gives such a gap's exact length.
- **2026-11-05** (0.12.2, two Deadlock matches, 41 and 52 min): clean
  (99% 18 ms, longest 32 ms, no stalls in play). Six pauses of 20–90 s
  in the second: full rate, tiny updates, counted as play.
- **2026-11-04 evening** (0.12.0, three Trackmania sessions, four
  Deadlock): the bad Trackmania server above (D:2415, six minutes). A
  10-second false "match" as Deadlock started, from relay pings while
  its menu ran over loopback; fixed in 0.12.2.
- **2026-11-04** (0.12.0): Trackmania loads a map in bursts, so 0.12.0's
  end of a load (three seconds after the last megabyte) was too early;
  fixed in 0.12.1. Two real stalls while racing. Five Deadlock matches,
  every stall in the first 41 seconds.
- **2026-11-03** (0.11.1): the busy polling comparison above; sockets
  keep busy polling after a match. Trackmania for an hour: six of seven
  stalls were map loads, the seventh a race start (50 to 90 updates a
  second).
- **2026-11-02 evening** (0.10.0 and 0.11.0, six Deadlock matches, socket
  buffer experiment 4 on / 2 off): the game's sockets dropped nothing
  either way. Two bugs fixed in 0.11.1: a burst of relay pings moved a
  64-tick match to INTENSE, and a 12-second menu between games merged
  them. One stall during play from the path.
- **2026-11-02** (0.9.2, 13 matches): the coalescing comparison above.
  Every stall and long gap fell in loading or the end screen. The tier
  changed 10+ times a match with the incoming packet rate; none of 15
  changes checked was followed by a stall, but it was pointless, so from
  0.10.0 tiers only go up within a match.
- **2026-10-30** (0.8.0): Deadlock's "end-of-game pattern" was its menu
  talking to itself over loopback, which is why games merged; 0.8.0
  counts only traffic from outside. First bot match recorded.
- **2026-10-29**: five or six Street Brawl games logged as one 1h49m
  match (0.7.2). Path of Exile 2 observed: TCP only.
- **2026-10-28** (0.3.0): Deadlock during an unmarked 4.8 GB torrent
  download, on a line with no queue: 99% ≤18 ms, longest 95 ms, no
  stalls. A clean match there says the line has headroom, not that
  bulk demotion is unnecessary; loading the 100 Mbit/s upload would
  test that.

## Bugs found and what they taught

- **0.12.0:** a game pinging relays from its menu as it started counted
  as traffic from outside; 0.12.2 needs outside traffic to outweigh
  loopback.
- **0.10.0: the gap figures measured the game, not the network** (found
  in an outside review). Gaps between packets halved when a server split
  updates; Deadlock's 32-a-second stretches pinned the 99% figure at
  32 ms, so no comparison could see it move; and the tier counted
  packets, so Deadlock reached INTENSE only in big fights. Fixed in
  0.11.0 by timing updates, taking the figures at the usual rate, and
  tiering on the update rate.
- **0.5.0: a released bulk process could stay demoted** (outside review):
  a flow learned between the release and the sweep stayed marked. Fixed
  in 0.5.1: a flow is only demoted while its owner is bulk, so nothing
  is swept. `--selftest` checks it.
- **0.5.0: demoting incoming IPv6 bulk traffic left a stale receive
  checksum** on NICs that report `CHECKSUM_COMPLETE`, logging "hw csum
  failure". Fixed in 0.5.1 with `BPF_F_RECOMPUTE_CSUM`.
- **0.4.0: consecutive matches merged:** quiet was judged a second at a
  time, and any burst in the menu restarted the count. Fixed in 0.4.1 by
  judging the median of five seconds. Lesson: the time between matches
  has to be modelled, not ignored.
- **0.3.0: lobby keepalives counted as stalls** (1671 in one session).
  Fixed in 0.3.1: a stall is the flow going quiet and coming back at
  game rate. Same lesson.
- **0.3.0: Wi-Fi power save toggled on a wired desktop** when the game
  went quiet. Fixed in 0.3.1: silence never moves the path.
- **0.3.0: socket buffer drops couldn't be attributed** to the game;
  0.3.1 reads the game's own sockets' count.
- **0.2.1: bpfrag switched off desktop CAKE's download shaping** during
  matches: its tc programs returned `TC_ACT_OK`, ending the tcx chain
  before CAKE's IFB redirect. The e2e rig now redirects through IFB
  devices. Lesson: test alongside the QoS setups people actually run.
- **0.1.x: the game's interface flapped** with Ethernet and Wi-Fi both
  up. Fixed by counting the game's packets per interface, with a 10%
  share and a 30 s hold.
- **0.1.1: `net.ipv4.udp_mem` exceeded RAM** (the original profiles set
  32–128 GiB, in pages). Removed: the kernel sizes it already.

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

The e2e rig (`tests/e2e/`) plays a fake 64-tick game against an echo
server in a network namespace. It measures gaps of 15–18 ms, as it should,
and checks every setting changes and comes back. That proves bpfrag does
what it says, not that it helps a real game. The comparisons above are for
that.
