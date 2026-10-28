# What bpfrag changes, and why

One section per setting. For each one:

- **Changes:** what bpfrag sets, and in which tiers.
- **Mechanism:** how the kernel uses that setting, with a source:
  kernel documentation, kernel source, or an RFC.
- **Expect:** what should be different during a match, and when nothing
  will be.
- **See it:** which counter or output would show an effect.
- **Confidence:** how solid the case is, and what data would change it.

Kernel source references are to the 7.4-rc1 tree (27 October 2026). Where
something below is a hypothesis rather than established, it says so.
[measuring.md](measuring.md) describes how to test these, and
[findings.md](findings.md) collects the results.

## Summary

| Setting | Mechanism | Likely effect on a gaming PC | Confidence |
|---|---|---|---|
| [DSCP CS4](#dscp-cs4-on-the-games-packets) | verified | Real on busy Wi-Fi (uplink) and with CAKE or a QoS router; none on a plain wired LAN | High for the mechanism, unmeasured in matches |
| [Wi-Fi power save off](#wi-fi-power-save) | verified | Removes wake-up delays of up to a beacon interval after lulls | Medium |
| [NIC interrupt coalescing](#nic-interrupt-coalescing) | verified (igc) | Up to ~0.25 ms less receive delay, mostly while something else downloads | Medium for the mechanism; too small for the 1 ms gap histogram |
| [busy_read / busy_poll](#busy-polling-busy_read-busy_poll) | verified | Unknown: depends on how the game reads its socket; may do nothing | Low |
| [Socket buffers](#socket-buffers-rmem_-wmem_) | verified | None unless the game stops reading for over a second | Low; kept because it's harmless |
| [netdev_max_backlog](#netdev_max_backlog) | verified | None on a NAPI NIC without RPS | Low |
| [netdev_budget / _usecs](#netdev_budget-and-netdev_budget_usecs) | verified | Only matters when receive processing is saturated | Low |
| [udp_early_demux](#udp_early_demux) | verified | None: it's already on by default | None (no-op) |
| [Dirty writeback](#dirty-writeback-vmdirty_) | partly | Not networking; smaller writeback bursts. No-op on CachyOS | Low |
| [Bulk demotion (LE)](#bulk-demotion-dscp-le) | verified | Real with CAKE on the machine or a router that adopts client marks | High for the mechanism, unmeasured in matches |

"Unmeasured in matches" means bpfrag's tests confirm it does what it says
(packets leave marked, settings change and come back), but no one has yet
compared real matches with and without it. That comparison is what
[measuring.md](measuring.md) sets up.

## DSCP CS4 on the game's packets

**Changes:** the DSCP field of every packet leaving the game's UDP ports is
set to CS4 (32), in all tiers. A packet the game already marked is left
alone unless `override = true`.

**Mechanism:**

- RFC 4594 §4.4 defines CS4 as the "Real-Time Interactive" class, for
  "variable rate inelastic traffic" needing "very low delay", and names
  "interactive gaming" among its uses.
- **Wi-Fi.** On transmit, the kernel picks the 802.11 access category from
  the DSCP (`cfg80211_classify8021d()`, `net/wireless/util.c`): the top
  three bits, so CS4 is user priority 4, the video category (AC_VI). That
  follows RFC 8325 §4.2.4. mac80211's default contention parameters
  (`ieee80211_set_wmm_default()`, `net/mac80211/util.c`, from 802.11
  Table 7-37) give AC_VI a contention window of 7–15 slots and AIFSN 2,
  against 15–1023 and AIFSN 3 for best effort. RFC 8325 §6.2 calls this a
  "statistically superior service". The access point can advertise
  different parameters, but rarely does.
- **CAKE.** With `diffserv4`, CAKE puts CS4 in its Voice tin (index 32 of
  `diffserv4[]` in `net/sched/sch_cake.c` is tin 3), which has priority up
  to a quarter of the shaped rate. With `diffserv3`, CS4 is best effort
  (`tc-cake(8)`).
- **Routers.** dscpclassify on OpenWrt adopts DSCP marks set by LAN clients
  (except CS6 and CS7), and with its `layer_cake_ct` script applies the
  connection's mark to the download direction too.

**Expect:**

- On Wi-Fi with other traffic contending for airtime: the game's outgoing
  packets win contention more often. This is the uplink only. Downloads
  are prioritised by the access point, using whatever DSCP the packet
  arrived with, usually 0 from the internet.
- With CAKE (diffserv4) on the machine or the router, and the line busy:
  the game's packets go ahead of other traffic.
- On a wired LAN with no QoS anywhere: nothing. ISPs usually reset DSCP,
  which is harmless.

**See it:** the e2e rig checks packets leave with `tos 0x80`, and
`tcpdump -v` shows it on a real machine. With CAKE, `tc -s qdisc` (also in
`--report`) shows per-tin packet counts. For the effect, compare packet
gaps on a busy Wi-Fi network with `[dscp]` on and off (see
[measuring.md](measuring.md)).

**Confidence:** high that the mechanism works where something honours
DSCP. How much it helps depends on how contended the airtime or link is.

## Wi-Fi power save

**Changes:** power save is turned off on the wireless interfaces carrying
the game's traffic, in COMPETITIVE and INTENSE, and put back afterwards.

**Mechanism:** in 802.11 power save, a client tells the access point it's
dozing. The access point buffers frames for it and announces them in its
beacons, typically every 102.4 ms, and the client wakes to fetch them.
mac80211 enters power save after `dynamic_ps_timeout` of inactivity, 100 ms
by default (`ieee80211_recalc_ps()`, `net/mac80211/mlme.c`). Drivers that
handle power save in firmware (iwlwifi and mt76 among them) use their own
timers.

**Expect:** a 64-tick game sends and receives every ~16 ms, which keeps the
radio awake. The cost shows after lulls longer than the timeout: between
rounds, on slow-tick servers, or when the server pauses. Then the first
packets back can wait for a beacon, up to about 100 ms. Wired: no effect.

**See it:** the longest gap and the stall count (quiet stretches of 100 ms to 2 s)
in the health line, on Wi-Fi. Compare matches with the default against
matches with `wifi_powersave_off = false` under `[tier.all]`.

**Confidence:** medium. The mechanism is well documented. Whether it
triggers during real matches depends on the game and the driver.

## NIC interrupt coalescing

**Changes:** receive interrupt coalescing (`rx-usecs`) is set to 10 µs in
COMPETITIVE and 0 µs in INTENSE, with adaptive coalescing off so the driver
doesn't move it back, on wired interfaces carrying the game. Transmit
coalescing is set along with it where the driver accepts that. The original
values are put back. Wi-Fi drivers generally don't support it, and are
skipped.

**Mechanism:** `rx-usecs` is how long the NIC waits after a packet arrives
before raising an interrupt, so it can batch several packets per interrupt.
For Intel's igc driver (I225/I226), the default is "dynamic":
`igc_update_itr()` (`drivers/net/ethernet/intel/igc/igc_main.c`) moves each
queue between about 14 µs (70,000 interrupts/s) for small packets, 50 µs,
and 250 µs (4,000 interrupts/s) once large packets dominate. A fixed value
replaces that. Realtek's r8169 reports and accepts its own values
(`rtl_get_coalesce()`). Defaults differ per driver: `ethtool -c` shows them.

**Expect:** with only the game on the link, igc is already at its lowest
setting, so little changes. With a download on the same receive queue, igc
moves to its 250 µs bulk setting, and game packets can wait up to that long
before the CPU sees them. A fixed 10 µs caps that. The effect is at most
about a quarter of a millisecond per packet, against a 16 ms tick. It's
jitter, not a large delay.

**See it:** not with bpfrag's own numbers yet: the gap histogram has 1 ms
buckets, which can't resolve differences this small. The health line's
"arrives on eno1 rx queue N" shows whether a download shares the game's
queue. Measuring it properly would take finer-grained arrival timing (a
possible future addition) or a hardware-timestamped capture.

**Confidence:** medium for the mechanism on igc. The effect is small by
construction.

## Busy polling (`busy_read`, `busy_poll`)

**Changes:** `net.core.busy_read` and `net.core.busy_poll` are set to
25/50/75 µs (CASUAL/COMPETITIVE/INTENSE). Both default to 0 (off).

**Mechanism** (`Documentation/admin-guide/sysctl/net.rst`,
`Documentation/networking/napi.rst`):

- `busy_read` sets the default `SO_BUSY_POLL` of new sockets: a read that
  would block spins on the device queue for up to that long instead of
  sleeping until an interrupt.
- `busy_poll` does the same for `poll()` and `select()`, but only on
  sockets that have `SO_BUSY_POLL` set, which `busy_read` provides.
- For `epoll`, every socket in the epoll set must have the same NAPI ID
  (receive queue) for busy polling to happen.
- It needs a driver with NAPI, and it costs CPU and power while spinning.

**Expect:** unknown. It helps when the game's network thread blocks in
`recv()`, `poll()` or `select()` waiting for the next packet. Games that
read non-blocking sockets from their frame loop, or that use epoll across
sockets on different queues, would see little or nothing. Wine/Proton
translate Windows socket calls into their own I/O loop, so a Windows game's
behaviour under Proton isn't obvious either. The spin time is counted as
the game thread's CPU time, which a sched_ext scheduler sees.

**See it:** no direct counter. Compare packet gaps and frame times with
busy polling on and off for the same game: `sysctl = {
"net.core.busy_read" = false, "net.core.busy_poll" = false }` under
`[tier.all]` turns it off.

**Confidence:** low. This is the setting most in need of data. If matches
show no difference, it should go, since it costs power.

## Socket buffers (`rmem_*`, `wmem_*`)

**Changes:** raise-only: `rmem_default` and `wmem_default` to at least
256 KiB, and `rmem_max` and `wmem_max` to at least 8/16/32 MiB by tier.

**Mechanism:**

- `rmem_default` is the receive buffer a socket gets unless it asks for
  another size. The kernel default is 256 × the true size of a 256-byte
  buffer (`SK_RMEM_DEFAULT`, `include/net/sock.h`): 212992 bytes, about
  208 KiB, on x86-64.
- `rmem_max` only caps what a program may request with `SO_RCVBUF`.
  Recent kernels default it to 4 MiB (`net/core/sock.c`; 6.18 already
  does); older ones used 208 KiB.
- Each small UDP packet costs roughly 1 KiB of buffer accounting, so the
  default holds a couple of hundred game packets: one to two seconds at
  128 packets/s.

**Expect:** a game's socket only overflows if the game stops reading for
over a second (a hitch, a loading spike), or if it receives far more than
its tick rate. Otherwise this changes nothing.

**See it:** the health line's socket buffer drops, specifically "(N the
game's)": the total is machine-wide (UDP `RcvbufErrors`), the game's
count comes from its own sockets.

**Confidence:** low that it matters, but raise-only and harmless. Kept from
the original profiles. If no match ever shows drops on the game's sockets
with the defaults, it can go.

`net.ipv4.udp_mem` was removed in 0.1.1. It's counted in pages, the kernel
already sizes it from RAM, and the original values raised its hard limit to
32–128 GiB.

## `netdev_max_backlog`

**Changes:** raise-only, to at least 5000. The kernel default is 1000
(`net/core/hotdata.c`).

**Mechanism:** the per-CPU input queue (`enqueue_to_backlog()`,
`net/core/dev.c`). Packets go through it when:

- RPS/RFS steers them to another CPU;
- a driver without NAPI delivers them with `netif_rx()`: veth, tun/tap and
  other virtual devices.

A normal NAPI NIC with RPS off processes packets directly in its poll
(`netif_receive_skb_internal()` → `__netif_receive_skb()`) and never
touches this queue.

**Expect:** nothing on a typical desktop NIC. It can matter with RPS
enabled, or when the game's traffic arrives through a virtual device (a
VPN's tun device, a container) at high packet rates. As someone testing it
put it, it's mainly relevant for workloads like a busy web server.

**See it:** the health line's backlog drops (`/proc/net/softnet_stat`
column 2).

**Confidence:** low that it matters for games. Kept because raise-only is
harmless.

## `netdev_budget` and `netdev_budget_usecs`

**Changes:** raise-only, to at least 400/600/800 packets and 8000 µs. The
kernel defaults are 300 packets and two jiffies (`net/core/hotdata.c`):
2000 µs on an HZ=1000 kernel, but already 8000 µs at
HZ=250, where the time limit changes nothing.

**Mechanism:** the most packets, and the longest time, one receive softirq
round may process across all NAPI instances before leaving the rest for
the next round or `ksoftirqd`. When a round runs out, the kernel counts a
"time squeeze" (`/proc/net/softnet_stat` column 3).

**Expect:** game traffic is a few hundred packets a second, far below one
round's budget. This only matters when something else saturates receive
processing on the same CPU (a gigabit download, many small packets).
Deferred work then waits for the next softirq run or for `ksoftirqd` to be
scheduled.

**See it:** the health line's "receive processing ran out of budget Nx".

**Confidence:** low for typical matches. Possibly useful during heavy
downloads.

## `udp_early_demux`

**Changes:** set to 1.

**Mechanism:** looks up the socket for connected UDP sockets early in IP
input (`ip_rcv_finish_core()`, `net/ipv4/ip_input.c`).

**Expect:** nothing: the kernel default is already 1
(`Documentation/networking/ip-sysctl.rst`, `net/ipv4/af_inet.c`). It only
does anything if something turned it off. Kept from the original profiles.
It's a candidate to drop.

## Dirty writeback (`vm.dirty_*`)

**Changes:** in COMPETITIVE and INTENSE, lower-only: `vm.dirty_bytes` to
256 MiB and `vm.dirty_background_bytes` to 64 MiB, if the current limits
allow more.

**Mechanism:** these cap how much unwritten file data can build up before
background writeback starts, and before writers are throttled. The defaults
are percentages of RAM (10% and 20%), several GiB on a gaming PC. A Steam
download or shader cache can build up a lot of dirty data that is then
written in bursts.

**Expect:** smaller, more frequent writeback instead of large bursts. This
isn't networking. The case for it is I/O-induced stutter, not packet
latency, and there's no measurement linking it to either yet. CachyOS
already ships these exact values (`70-cachyos-settings.conf` in
CachyOS-Settings), so on CachyOS it changes nothing.

**Confidence:** low. It's the setting furthest from bpfrag's scope, and
it's optional (`writeback = false` under `[tier.all]`).

## Bulk demotion (DSCP LE)

**Changes:** with `[bulk] enabled = true`, packets of other processes
moving bulk data during a match get DSCP LE (1), in both directions,
unless already marked. See the README for what counts as bulk.

**Mechanism:**

- RFC 8622 defines LE ("lower effort", DSCP 1) for traffic that should
  yield to everything else, in place of CS1 (§6, §10).
- CAKE `diffserv3/4/8` put LE and CS1 in the Bulk tin (`diffserv4[]` in
  `sch_cake.c`: index 1 and 8 are tin 1). That tin has priority only up to
  1/16 of the shaped rate.
- Incoming packets are re-marked at tc ingress, before classic tc filters
  run (`sch_handle_ingress()`, `net/core/dev.c`), so a desktop CAKE's IFB
  redirect sees LE.
- dscpclassify on a router adopts the mark, and its `layer_cake_ct` script
  applies it to the download direction.

**A Wi-Fi caveat:** RFC 8622 §11 recommends mapping LE to the 802.11
background category (AC_BK). The kernel doesn't: `cfg80211_classify8021d()`
has no special case for LE, so it takes the top three bits and sends LE as
best effort. CS1 does map to background. So on a Wi-Fi uplink, `class =
"CS1"` would also demote the bulk traffic's airtime, at the cost of CS1's
older meaning (RFC 2474 ranked it above best effort, which some networks
still do). LE stays the default because it's the standard.

**Expect:** with CAKE on the machine or a router that adopts client marks,
and the line saturated by the download: the game's packets wait less behind
it. Without anything that reads DSCP: nothing.

**See it:** `--monitor` and the match summary (how much was demoted), `tc
-s qdisc` for CAKE's Bulk tin counters, and packet gaps for matches during
a download with `[bulk]` on and off.

**Confidence:** high for the mechanism (the self-test and e2e rig check the
marks both ways), unmeasured in real matches.
