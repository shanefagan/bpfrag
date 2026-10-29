# Experiments to run

A backlog: things worth testing, why, and what each would take. Most
haven't been run yet. When one is, its result goes in [findings.md](findings.md)
(null results too) and its entry here gets a link to it.

Each entry says:

- **Question:** what we'd learn.
- **Why:** the mechanism, with a source, or "hypothesis" where there's
  no source yet.
- **How:** what to run, and whether bpfrag can do it today.
- **Read it:** the number that answers the question.
- **Decides:** what we'd change depending on the answer.

There are four kinds:

- **Check:** look at a counter once; no comparison needed.
- **A/B:** runs today with `[experiment]` ([measuring.md](measuring.md)).
- **A/B+:** needs a small bpfrag change first (listed under each entry).
- **Setup:** a change outside bpfrag (router, kernel, system settings),
  compared by hand.

## At a glance

| # | Question | Kind | Most useful on |
|---|---|---|---|
| 1 | [Does busy polling reach the game at all?](#1-does-busy-polling-reach-the-game) | Check | any |
| 2 | [Do the socket buffer settings reach the game's socket?](#2-do-the-socket-buffer-settings-reach-the-games-socket) | Check | any |
| 3 | [Does bpfrag change anything on a fast wired line?](#3-does-bpfrag-change-anything-on-a-fast-wired-line) | A/B (`all`) | wired |
| 4 | [Do tier changes cause hiccups of their own?](#4-do-tier-changes-cause-hiccups) | Check, then A/B+ | wired |
| 5 | [Does Energy Efficient Ethernet add delay or drop the link?](#5-energy-efficient-ethernet) | Check, then A/B+ | wired, Intel I225/I226 |
| 6 | [Does Wi-Fi power save cause stalls?](#6-wi-fi-power-save) | A/B (`wifi_power_save`) | Wi-Fi |
| 7 | [Do Wi-Fi background scans cause periodic stalls?](#7-wi-fi-background-scans) | Check, then A/B+ | Wi-Fi |
| 8 | [Does DSCP help on a busy Wi-Fi network?](#8-dscp-on-busy-wi-fi) | A/B (`dscp`) | Wi-Fi |
| 9 | [CS4 or EF for the game's packets?](#9-cs4-or-ef) | A/B+ | Wi-Fi, CAKE |
| 10 | [Does bulk demotion help when the upload is full?](#10-bulk-demotion-with-a-full-upload) | A/B (`bulk`) + Setup | asymmetric lines |
| 11 | [LE or CS1 for bulk traffic on Wi-Fi?](#11-le-or-cs1-on-wi-fi) | A/B+ | Wi-Fi |
| 12 | [Does BBR for downloads protect the game?](#12-bbr-for-downloads) | Setup | any line with a download |
| 13 | [Does fixed coalescing matter during a download?](#13-coalescing-during-a-download) | A/B+ (finer timing) | wired |
| 14 | [Does writeback tightening change anything in a match?](#14-writeback-during-a-big-download) | A/B (`writeback`) + frame times | non-CachyOS |
| 15 | [bpftune or bpfrag for the settings they share?](#15-bpftune-or-bpfrag-for-the-shared-settings) | Setup | bpftune users |
| 16 | [How big a difference does noise alone produce?](#16-an-aa-test) | A/B+ | everyone, once |
| 17 | [How much do time of day and the server matter?](#17-time-of-day-and-server) | analysis, needs M7 | any |
| 18 | [Is BQL letting this machine queue much in the NIC?](#18-byte-queue-limits) | Check | wired, uploading from this PC |
| 19 | [Would `tcp_notsent_lowat` help? (expected: no)](#19-tcp_notsent_lowat) | not planned | none |
| 20 | [What does a TCP game's traffic look like?](#20-tcp-games) | observe (runs today) | MMO players |
| 21 | [Do thin-stream timeouts help a game that talks TCP?](#21-thin-stream-tcp-timeouts) | Check, then Setup | TCP games on Wi-Fi |

Entries 18 and 19, and parts of 5, 7, 9, 12 and M3, came from an outside
review (October 2026); each was checked against kernel sources before
going in, and 19 is here to record why it's not worth testing.

Suggested order on a wired desktop: 1, 2, 4 and 5 first (they're quick
and may remove settings outright), then 3, 16 and 10. On Wi-Fi: 1, 2,
then 6, 7 and 8.

## Checks: does each setting reach the game?

### 1. Does busy polling reach the game?

**Question:** do `busy_read` and `busy_poll` ever cause a busy-polled
packet during a match?

**Why:** `busy_read` is copied into a socket only when the socket is
created (`sk->sk_ll_usec` in `sock_init_data_uid()`, `net/core/sock.c`),
and `poll()`/`select()` only busy-poll sockets that have it. bpfrag
raises it when it detects a match, which is after the game opened its
socket, so that socket keeps 0; sockets the game opens later in the same
session would get it. `epoll` doesn't depend on that: it busy-polls
whenever `busy_poll` is non-zero (`ep_busy_loop_on()`, `fs/eventpoll.c`).
So whether the game is affected depends on how it (or Wine, under Proton)
waits for packets, which is easiest to answer by counting. The kernel counts
every packet received by busy polling: `BusyPollRxPackets` in
`/proc/net/netstat` (`LINUX_MIB_BUSYPOLLRXPACKETS`, `net/core/dev.c`).

**How:** read the counter before and after a few matches:
`nstat -az TcpExtBusyPollRxPackets`.

**Read it:** 0 across matches means busy polling does nothing for that
game. Growth isn't proof it's the game's: sockets other programs open
during a match get `busy_read` too.

**Decides:** 0 everywhere: remove busy polling (it costs power when it
does work). Growth: keep it and run the A/B (`busy_polling`) to see
whether it helps. Either way, worth adding to the health line (M1).

### 2. Do the socket buffer settings reach the game's socket?

**Question:** what receive buffer does the game's socket actually have
during a match?

**Why:** like `busy_read`, `rmem_default` and `wmem_default` are copied
into a socket at creation (`sock_init_data_uid()`), and `rmem_max` only
caps later `SO_RCVBUF` requests, which programs usually make right after
creating the socket. So bpfrag's raise reaches only sockets opened while
a match is on.

**How:** during a match, `ss -uampn` and find the game's process; the
`skmem:(...)` field's `rb` is the receive buffer limit.

**Read it:** `rb212992` (the kernel default on x86-64) means neither the
game nor bpfrag changed it; bpfrag's default would show as `rb262144`. A
game that sets its own size shows double what it asked for (the kernel
doubles `SO_RCVBUF`), capped by `rmem_max`. Combined with the game's own
socket drops (0.3.1 and later): if they're 0 with the default buffer, the
buffer is big enough.

**Decides:** default buffer and no drops: remove the socket buffer
settings. Drops with the default buffer: the setting needs to apply
before the game starts (an option to raise it from the moment bpfrag
starts, not per match), and that becomes the A/B.

### 4. Do tier changes cause hiccups?

**Question:** does switching between COMPETITIVE and INTENSE mid-match
cause a stall?

**Why:** each switch rewrites sysctls and NIC coalescing (10 µs and
0 µs). On most drivers changing coalescing just writes a register
(`igc_ethtool_set_coalesce()`, `rtl_set_coalesce()`). On Intel's ixgbe
(82599, X540, X550), `ixgbe_set_coalesce()` resets the adapter when the
setting crosses 10 µs or leaves "dynamic" (`ixgbe_do_reset()`,
`drivers/net/ethernet/intel/ixgbe/ixgbe_ethtool.c`), which interrupts
traffic. bpfrag's tiers cross exactly that line. In the Deadlock sessions in
[findings.md](findings.md), tiers switched 2 to 10 times a session, often
twice within a minute.

**How:** first a check: `ethtool -i <iface>` for the driver; on ixgbe,
look for "Reset adapter" in `dmesg` after a match. Then compare the times
of tier changes in the log with stall times, which needs stall timestamps
(M5). If tier changes do cost something, an A/B+ with one arm pinned to
a single tier (`detect.pin_tier`) settles it.

**Read it:** stalls clustered within a second or two of tier changes.

**Decides:** if yes: keep coalescing fixed for the whole match (one value
for both tiers), or skip it on drivers known to reset. ixgbe needs a fix
regardless of the result.

### 5. Energy Efficient Ethernet

**Question:** does EEE add delay to the game's packets, or drop the link?

**Why:** Energy Efficient Ethernet (IEEE 802.3az) lets an idle link enter
low-power idle between packets; it has to wake before the next frame goes
out. A game sends a small packet every ~16 ms, so the link can idle
between nearly every packet. The wake time is in microseconds (hypothesis
that it matters: unmeasured, likely below the 1 ms histogram). Separately,
Intel's I226 has had sporadic connection drops with EEE on, with
"disable EEE" as the vendor workaround
([ASUS FAQ for I226-LM](https://www.asus.com/support/faq/1052466)). EEE is
negotiated: if either end doesn't advertise it, the link doesn't use it.

**How:** check `ethtool --show-eee <iface>` for "EEE status: enabled -
active". Turning it off is `ethtool --set-eee <iface> eee off` (a link
renegotiation, so between matches). An A/B needs bpfrag to own it as a
setting, journalled like coalescing, and applied at daemon start rather
than per match because of the renegotiation: switching it at the start of
each match would drop the link just as the match begins.

**Read it:** NIC drops, link flaps in `dmesg`, stalls. Sub-millisecond
wake delays need finer timing (M8).

**Decides:** link drops with EEE on: a strong case for an EEE setting
(off while bpfrag runs) on igc. Nothing measurable: leave it alone.

### 7. Wi-Fi background scans

**Question:** do periodic background scans cause stalls on Wi-Fi?

**Why:** when mac80211 scans in software it leaves the operating channel
for up to about 125 ms before returning (`ieee80211_scan_state_decision()`,
`HZ / 8`, `net/mac80211/scan.c`), spending about 60 ms per active channel
and 111 ms per passive one; the AP buffers the station's traffic
meanwhile.
Many drivers scan in firmware instead (iwlwifi, mt76), with their own
timing. NetworkManager and wpa_supplicant scan in the background, more
often on a weak signal (hypothesis: how often during a match is unmeasured).

**How:** `iw event -t` during a match prints scan start and end with
timestamps; compare with stall times (M5).

**Read it:** stalls lining up with scans, at a regular interval.

**Decides:** if yes, a setting to hold off background scans during a
match (via NetworkManager, or wpa_supplicant's `bgscan` over D-Bus)
becomes worth building. That needs care: roaming relies on scans.

### 20. TCP games

**Question:** what does a game that talks TCP look like on the wire, and
is it regular enough to detect and tune like a UDP match?

**Why:** World of Warcraft and other MMOs, and many older games, use TCP,
so bpfrag never sees them as matches. Whether their traffic is steady
enough to tell from a browser or a download, which tiers would fit, and
whether any setting helps them, is unknown; TCP also brings its own
settings (Nagle, delayed acknowledgements, retransmission timers) that UDP
games don't have, which would need their own knobs.md sections first.

**How:** `[detect] tcp = "observe"`. bpfrag then logs a "TCP game seen"
line and a "TCP game session" summary for every game that talks TCP both
ways for 10 seconds: typical send and receive rates, message sizes, how
steady the rate is, how long, how much ([detection.md](detection.md#games-that-talk-tcp)).
For one particular game, `BPFRAG_OBSERVE=1 %command%` in its launch
options logs the same for its UDP and its TCP, one way or both, without
counting every other process's TCP
([detection.md](detection.md#observing-one-game-bpfrag_observe1)); that
also answers whether a game is UDP or TCP in the first place (Path of
Exile 2, say). Several sessions of normal play, in towns, in raids, idle,
is the data. Send it with the "Share match data" issue form.

**Results so far:** Path of Exile 2 talks TCP, about 30 small messages a
second each way ([findings.md](findings.md#games-observed)).

**Decides:** steady and distinct: a TCP match detector, then
experiments for any settings it gets. Indistinguishable from background
TCP: leave TCP games alone, and say so.

### 21. Thin-stream TCP timeouts

**Question:** does `net.ipv4.tcp_thin_linear_timeouts = 1` shorten the
worst freezes of a game that talks TCP?

**Why:** a game sending about 30 small messages a second, like Path of
Exile 2 ([findings.md](findings.md#games-observed)), rarely has 4 or more
packets in flight: a thin stream
([`Documentation/networking/tcp-thin.rst`](https://docs.kernel.org/networking/tcp-thin.html)).
It can't collect the three duplicate acknowledgements fast retransmit
needs, so a lost packet waits for the tail loss probe (RACK-TLP, on by
default: `tcp_early_retrans = 3`, RFC 8985) or for the retransmission
timeout, at least 200 ms (`tcp_rto_min_us`). If the retransmission is
lost too, the timeout doubles each time. With `tcp_thin_linear_timeouts`
on, an established thin connection keeps the same timeout for up to six
retransmissions before backing off (`TCP_THIN_LINEAR_RETRIES`,
`tcp_retransmit_timer()` in `net/ipv4/tcp_timer.c`). The kernel reads the
sysctl when the timer fires, so turning it on during a match reaches a
connection the game already has. Its old companion `tcp_thin_dupack` is
gone: the sysctl was removed, and the `TCP_THIN_DUPACK` socket option is
accepted and ignored (`net/ipv4/tcp.c`); RACK covers what it did.

Over TCP, a lost packet holds up everything behind it until it's
resent, and a lockstep game waits for it, so these are freezes a player
feels. But the setting only changes what happens once a retransmission
is itself lost (the first timeout is the same), and only for what this
machine sends, the game's inputs: the server's retransmissions are up to
its own kernel. Hypothesis: it helps on lossy Wi-Fi or a phone hotspot
and changes nothing on a clean wired line, where back-to-back losses are
rare.

**How:** check first whether timeouts happen at all during play:
`nstat -az TcpExtTCPTimeouts TcpRetransSegs` before and after a session
(machine-wide, so quiet the rest of the machine), or `ss -ti` on the
game's connection (`retrans:` and `backoff:`). If they do, compare
sessions with the sysctl set by hand, reading the game's own latency
display. For bpfrag to set it per match, it first needs a tier for TCP
games (entry 20), which makes this A/B+.

**Read it:** retransmission timeouts per hour of play; with the setting
on, whether the longest freezes get shorter.

**Decides:** timeouts happen and it shortens them: a setting for TCP
games, with a knobs.md section and an `[experiment]` name. Timeouts never
happen on a kind of link: leave it off there.

### 18. Byte Queue Limits

**Question:** when this machine uploads (seeding, a backup), how much can
queue in the NIC's transmit ring, where the qdisc can no longer put the
game's packets first?

**Why:** Byte Queue Limits size each transmit queue's in-flight bytes
dynamically: `limit` grows when the ring runs dry and shrinks when it
doesn't, up to `limit_max`, which defaults to effectively unlimited
(`DQL_MAX_LIMIT`, `include/linux/dynamic_queue_limits.h`;
`Documentation/ABI/testing/sysfs-class-net-queues`). Above the ring,
`fq_codel` keeps flows apart, so only what's already in the ring is
ahead of the game. At 1 Gbit/s, 30 KB in the ring is about 0.25 ms; on a
line with a slower upload than the NIC, the real queue forms at the
router, not here.

**How:** during a match with an upload running, read
`/sys/class/net/<iface>/queues/tx-*/byte_queue_limits/limit` and
`inflight`. Capping `limit_max` (an outside suggestion: 4–8 KB under
INTENSE) would only be worth building if those are large.

**Read it:** `limit` in the tens of KB or less means the ring adds well
under a millisecond, below what the gap histogram resolves (M8).

**Decides:** small: nothing to do. Hundreds of KB with a download running
on the same queue: a cap becomes an A/B candidate.

## Comparisons that run today

### 3. Does bpfrag change anything on a fast wired line?

**Question:** on a wired line with headroom and no QoS that reads DSCP,
does tuning beat measuring only?

**Why:** most of bpfrag's effect is expected on Wi-Fi, under congestion,
or with CAKE or a QoS router ([knobs.md](knobs.md)). Without those, the
honest prediction is "no difference".

**How:** `[experiment] setting = "all"`. About 10 matches a side, same
game, nothing big downloading.

**Read it:** `matches.py --compare arm`: 99% gap, longest gap, stalls.

**Decides:** no difference is a useful result: it tells wired users with
fast lines what to expect, and it's the reference the other experiments
compare against.

### 6. Wi-Fi power save

**Question:** does power save cause stalls in real matches?

**Why:** in power save the radio sleeps between beacons; after a lull
longer than the dynamic power save timeout (100 ms in mac80211), the
first packets back can wait up to a beacon interval
([knobs.md](knobs.md#wi-fi-power-save)). Ubuntu turns power save on in
NetworkManager; most drivers default to on ([distros.md](distros.md)).

**How:** `setting = "wifi_power_save"`, on Wi-Fi, 10+ matches a side.
Note the driver (`ethtool -i wlan0`): firmware power save (iwlwifi, mt76)
behaves differently from mac80211's.

**Read it:** longest gap and stalls.

**Decides:** no difference on a given driver: say so in knobs.md for that
driver. A difference: keep it on by default.

### 8. DSCP on busy Wi-Fi

**Question:** does CS4 help when other devices load the Wi-Fi?

**Why:** on Wi-Fi the mark picks the access category: CS4 goes to video
(`cfg80211_classify8021d()`, `net/wireless/util.c`), which contends with
a smaller window (7–15 slots) and shorter wait (AIFSN 2) than best effort
(15–1023, AIFSN 3) (`net/mac80211/util.c`; the AP's advertised values win).
That's the uplink only, and only when the air is contended.

**How:** `setting = "dscp"`, with another device streaming or downloading
over the same access point throughout. Keep `[bulk] enabled = false`
(the experiment refuses otherwise).

**Read it:** 99% gap and stalls; the game's own ping graph for the uplink
side, which bpfrag can't see (M3 would).

**Decides:** a difference: confirms the main reason for DSCP on Wi-Fi.
None: DSCP's case rests on CAKE and routers alone.

### 10. Bulk demotion with a full upload

**Question:** when a seed or upload fills the line's upload, does
demoting it help, and does the router need Smart Queues for that?

**Why:** on an asymmetric line (say 950 down / 100 up), a torrent seeding
without a limit can fill the upload, and the game's packets wait behind it
in the gateway's or ISP's queue. LE only helps if that queue reads DSCP.
A plain FIFO doesn't; Smart Queues (UniFi) or CAKE on the router would,
or at least would keep the queue short.

**How:** three conditions, each with a long seed at no upload limit:
`setting = "bulk"` (with `[bulk] enabled = true`) on the router as it is,
then the same with Smart Queues set to about 90% of the upload, then
seeding paused as the reference. The router change is by hand, so run
each condition as its own block of matches.

**Read it:** stalls and the 99% gap, plus the game's ping. The uplink
queue shows in round-trip time more than in arrival gaps, so this one
benefits most from M3.

**Decides:** which advice to give for asymmetric lines: demotion, Smart
Queues, both, or "limit your seeding".

### 14. Writeback during a big download

**Question:** does tightening writeback change anything during a match
with a big download writing to disk?

**Why:** large dirty-page backlogs flush in bursts; the theory is that
those bursts stall I/O the game is waiting on. It isn't networking, and
CachyOS already ships bpfrag's values, so it's a no-op there
([distros.md](distros.md)).

**How:** `setting = "writeback"` on a distribution with kernel defaults,
with a big Steam download to a slow disk. bpfrag's numbers won't show it;
frame times will (M6).

**Decides:** no frame-time difference: remove writeback from bpfrag (it's
the one setting outside networking).

## Needs a small change first

### 9. CS4 or EF

**Question:** which class serves the game best?

**Why:** on Wi-Fi, EF goes to voice (UP 6), CS4 to video (UP 4)
(`cfg80211_classify8021d()`); voice contends harder still (3–7 slots) but
with shorter transmit opportunities, which matters little for small
packets. Where it would matter most is against other video-category
traffic on the same network: a video call marked AF41 also goes to UP 4,
so CS4 game packets contend with it on equal terms while EF ones win.
That's the uplink only: the downlink category depends on the access point
classifying the server's packets, whose marks ISPs often clear. CAKE's
diffserv4 puts both in its Voice tin; diffserv3 puts EF in its Voice tin
but CS4 in best effort (`net/sched/sch_cake.c`). If an AP sends a QoS Map,
its mapping replaces the kernel's.

**Needs:** experiment arms that pick a value rather than on/off
(`arms = ["CS4", "EF"]`).

### 11. LE or CS1 on Wi-Fi

**Question:** should bulk traffic be CS1 on Wi-Fi?

**Why:** Linux sends LE as best effort on Wi-Fi and CS1 as background
(UP 1, the lowest category) (`cfg80211_classify8021d()`), so on a
contended uplink CS1 actually yields to the game while LE doesn't. CAKE
treats both as Bulk. Routers older than RFC 8622 may not know LE.

**Needs:** value arms, as in 9, for `bulk.class`.

### 13. Coalescing during a download

**Question:** does a fixed 10 µs beat igc's dynamic coalescing while a
download shares the game's receive queue?

**Why:** igc moves a busy queue to its bulk setting, about 250 µs
([knobs.md](knobs.md#nic-interrupt-coalescing)). At most a quarter of a
millisecond, so it can't show in a 1 ms histogram.

**Needs:** finer arrival timing (M8). Then `setting = "coalescing"` with
a download running, checking that the health line says the download and
the game share an rx queue.

### 16. An A/A test

**Question:** how often does `--compare` call a difference "significant"
when there's none?

**Why:** match-to-match noise is large, and with enough comparisons
something will look significant by chance. Running both arms identical
shows the noise floor, and calibrates how much to trust a single p-value.

**Needs:** `setting = "none"`: arms drawn and logged, nothing switched
off. (Today the config refuses an experiment whose arms are identical.)

### 17. Time of day and server

**Question:** how much of the spread is evening load or which server the
game picked?

**Why:** if the server or relay dominates, experiments need more matches,
or results should be split by server.

**Needs:** the game's peer address per match (M7). Then it's analysis of
logs already collected, no new matches.

## Setups compared by hand

### 12. BBR for downloads

**Question:** does BBR congestion control for this machine's downloads
and uploads keep the game's latency lower than cubic?

**Why:** BBR paces to the bottleneck's rate and tries to keep its queue
short, while cubic fills the queue until loss. Bazzite ships BBR
([distros.md](distros.md)). The effect is on queues bpfrag's bulk flows
build at the bottleneck, so it overlaps with experiment 10. It applies to
new connections only.

**How:** `sysctl net.ipv4.tcp_congestion_control=bbr` (module
`tcp_bbr`), a block of matches with a big download, then cubic. If it
helps, it could become a setting. Switching it per match would only reach
connections opened during the match: a download that opens new
connections as it goes (Steam's does) would be mostly affected, a
long-lived torrent connection not at all, so a by-hand block of matches
is the cleaner test.

### 15. bpftune or bpfrag for the shared settings

**Question:** for `netdev_budget*`, `netdev_max_backlog` and
`rmem_default`/`rmem_max`, do bpftune's adaptive values or bpfrag's fixed
ones do better?

**How:** switch bpftune on or off between game launches, never mid-session,
and label each block (`matches.py --label`). Everything else bpfrag does
is the same in both. Given checks 1 and 2 and the drop counters, the
likely result is "no difference", which would mean either tool can own
them.

## Suggested, and not expected to help

### 19. `tcp_notsent_lowat`

**Suggestion** (outside review): lower `net.ipv4.tcp_notsent_lowat` from
its default (no limit, `UINT_MAX`) to 16 KB during matches, so uploads
build less local bufferbloat ahead of the game's packets.

**Why it's not planned:** it limits unsent data sitting in each TCP
socket's own write queue (`Documentation/networking/ip-sysctl.rst`;
`tcp_stream_memory_free()`, `net/ipv4/tcp.c`). That data hasn't been
handed to the qdisc or the NIC, so it isn't ahead of the game's UDP
packets anywhere. What a TCP sender may have queued on this machine is
already bounded by TCP Small Queues to roughly a millisecond of its
sending rate (`tcp_small_queue_check()`, `net/ipv4/tcp_output.c`, capped
by `tcp_limit_output_bytes`). The queue that hurts is at the bottleneck,
set by the congestion window, which this doesn't change. It helps programs
that prioritise data within one connection (HTTP/2), and memory use.

**What would change that:** a measurement showing local queueing under an
upload that TSQ doesn't explain. If someone wants to confirm the null
result, it runs as `sysctl:net.ipv4.tcp_notsent_lowat` once a tier sets
it.

## Measurements that would make these possible

| | Measurement | For |
|---|---|---|
| M1 | Busy-polled packets (`BusyPollRxPackets`) during the match, in the health line | 1 |
| M2 | The game's socket buffer sizes (`rb`, via sock_diag as `ss -m` does) | 2 |
| M3 | Round-trip time to the gateway and a public anycast address, about once a second during a match. Arrival gaps measure jitter, not delay: a queue holding a steady 80 ms still delivers a steady 64 Hz stream, so only round-trip time shows it. Game servers and relays may not answer pings, which is why the gateway and a public address are the dependable targets; the server's own address needs M7 | 8, 10, 12, 18 |
| M4 | Gaps between the game's outgoing packets (the egress marker sees them) to tell a game or host hiccup from a network one | all |
| M5 | Timestamps of the last stalls in each match, to line them up with tier changes, scans and other events | 4, 7 |
| M6 | Frame times: a MangoHud log joined to matches by time | 14, busy polling |
| M7 | The game's peer address (or its network) per match | 17 |
| M8 | Sub-millisecond arrival timing | 5, 13 |
| M9 | The game's own TCP retransmissions and timeouts (the `tcp_retransmit_skb` tracepoint carries the socket, so it can be tied to the game's connection) | 21 |

## Out of scope

- **CPU frequency, idle states, scheduling, IRQ affinity, RPS/RFS:**
  they can matter (a CPU waking from a deep idle state delays the
  interrupt handler), but they belong to sched_ext schedulers, gamemode,
  tuned and irqbalance. bpfrag promises not to touch them (AGENTS.md).
- **Game settings** (interpolation, tick rate): not the system's to
  change.
- **Router firmware beyond its QoS switch:** bpfrag runs on the PC.
