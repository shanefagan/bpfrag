# Measuring whether a change helps

Every match leaves a health line in the log when it ends:

```
Deadlock: packet gaps half ≤16 ms, 99% ≤23 ms, longest 48 ms, 0 stalls (100 ms+); no drops; arrives on eno1 rx queue 2, IRQ 140
```

`--dry-run` measures exactly the same way while changing nothing, so the
same game, played with and without bpfrag tuning, gives two sets of these
lines to compare. This page describes how to collect them so a difference
can be trusted, and what each number can and can't show. Results go in
[findings.md](findings.md).

## What the numbers measure

Arrival times are taken at tc ingress on the game's main flow (the local
port that receives the most), before the rest of the network stack, so they
show what reaches the machine, not what the game does with it.

| Number | Meaning | Moved by |
|---|---|---|
| half ≤N ms | median gap between the game's incoming updates (1 ms buckets), while the game sends at its usual rate | the server's tick rate: about 16 ms at 64 a second |
| 99% ≤N ms | the gap 99% of updates beat, while the game sends at its usual rate | jitter anywhere on the path: Wi-Fi, queues, the internet |
| longest N ms | the longest gap counted (pauses of 2 s or more aren't, unless the game kept sending through them: see below) | one-off hiccups, Wi-Fi power save |
| stalls | the flow went quiet for 100 ms to 2 s, then came back at game rate; or for longer while the game kept sending | what a player feels as rubber-banding |
| jitter N µs | how much each gap at game rate differed from the one before, on average, to the microsecond (0.13.0) | the path and the server mostly; settings on this machine by microseconds |
| the game's own sending | its longest gap between sends and its stalls over play, timed as it calls send (0.13.0) | the game or this machine: a freeze, a hitch. A stall coming in with none going out was the network or the server |
| socket buffer drops | a UDP receive buffer overflowed (`RcvbufErrors`), anywhere on the machine; "(N the game's)" is how many were the game's own sockets | socket buffers, a game that stopped reading |
| backlog drops | per-CPU input queue overflowed | `netdev_max_backlog` (RPS or virtual devices only) |
| NIC drops | the NIC's receive ring overflowed | coalescing, ring size, very high rates |
| ran out of budget | receive processing deferred | `netdev_budget*`, heavy receive load |
| arrives on | the receive queue and IRQ | RSS, whether a download shares the queue |
| bulk | what was demoted, and how much | `[bulk]` |

Limits to keep in mind:

- **Gaps are between updates (0.11.0 and later).** A server splits a
  big update into packets sent back to back; packets arriving within
  4 ms of an update's first one count as part of it, and the gap is
  timed from its first packet. No game sends 250 updates a second, so
  this only merges split updates (and relay pings that happen to land
  in one). Before 0.11.0 the gaps were between packets, so a Deadlock
  fight, with updates split into 2–3 packets, read "half ≤2–3 ms".
- **The half and 99% figures are taken at the game's usual rate (0.11.0
  and later).** A second counts if it had at least half the match's
  usual updates and its own median gap was at most half as long again
  as usual. Deadlock sends 32 updates a second instead of 64 while the
  player is dead and on the end screen; before 0.11.0 those stretches
  alone put a match's 99% figure at ≤32 ms (at more than 1% of the
  gaps), whatever the network did. A second with a hiccup still counts:
  most of its gaps are usual.
- **Play only (0.10.0 and later).** The gaps, stalls and longest gap
  count from a minute into the match to five seconds before the last
  second at the game's usual rate (from 0.11.0; 0.10.0 used the last
  arrival, which a relay ping after the end screen could move),
  leaving out loading and the end screen. Matches shorter than a minute
  are counted whole. From 0.12.0, seconds when the game is loading mid-
  match are left out too: from a second in which the game's own TCP
  brought in a megabyte or more to the first second back at the game's
  usual rate (Trackmania loads every map that way while the session
  carries on; from 0.12.1, as 0.12.0 stopped after three seconds and a
  load comes in bursts). Don't compare gap figures
  across 0.10.0, 0.11.0 or 0.12.0.
- **Pauses count as play.** A paused Deadlock match keeps its full 64
  updates a second, each one tiny, so it's indistinguishable from play
  by timing, and its gaps are as real as any. Pauses don't make a match
  look worse; they add easy minutes. The timeline's `udp_rx_bytes_s`
  shows them (a few KB a second instead of tens).

- **1 ms resolution, except jitter.** Changes of tens or hundreds of
  microseconds (interrupt coalescing, busy polling) can't show in the
  half, 99% and longest figures. From 0.13.0 the meter also times each
  gap at game rate to the nanosecond, and the health line's `jitter`
  (with the timeline's `jitter_us`) is how much each gap differed from
  the one before, on average, over play. That's what a change on this
  machine moves; it's still mostly the path's and the server's, so
  compare it across arms, not against zero.
- **Most jitter isn't on this machine.** The internet path and the game
  server dominate the spread. A tuning change shows up as a small shift in
  the 99% figure and the stall count, against a lot of match-to-match noise.
- **Drop counters are system-wide,** except "the game's" socket buffer
  drops (0.3.1 and later), read from the game's own sockets. A torrent
  client's UDP sockets overflowing shows in the total, not in the game's.
- **Stalls changed meaning in 0.3.1.** Before, every gap of 100 ms to 2 s
  counted, including the one-a-second keepalives a game sends in a lobby
  or menu, so a session that included time between matches could show
  hundreds of stalls and a longest gap of about 1000 ms. From 0.3.1 a
  stall is the flow going quiet and coming back at game rate. Don't
  compare stall counts across that version (the CSV has a version
  column).
- **An outage of two to four seconds is a stall** (0.14.1). The
  meter leaves quiet stretches of 2 s or more out of its gaps, because
  nearly all of them are a lobby, a menu or a load; a lost connection is
  only counted once three whole readings pass with nothing received. An
  outage in between showed in neither figure. Now the meter reports those
  stretches separately, and one counts as a stall (and as the longest gap)
  when the game kept sending at a quarter of its usual rate or more
  through every reading it covered: in a lobby or a load the game stops
  sending too. The log and the timeline's `events` say "nothing from the
  server for N s". Only in play (a minute in, not loading), like the other
  gap figures.
- **Gaps measure jitter, not delay.** A queue somewhere on the path that
  holds a steady 80 ms still delivers packets every ~16 ms, so the gaps
  look perfect while the player's latency has doubled. The game's own ping
  shows that; bpfrag doesn't measure round-trip time yet
  ([experiments.md](experiments.md), M3).
- **It's the incoming direction only.** DSCP and Wi-Fi contention affect
  the outgoing packets first. The server's view of your packets, or the
  game's own network graph, covers that side.

## A comparison you can trust

The simplest fair comparison is an **experiment**: bpfrag switches one
setting off in a random half of your matches and records which half each
match was in. You play as usual.

The set-and-forget way is to let bpfrag pick the setting too:

```toml
# /etc/bpfrag/bpfrag.toml
[experiment]
setting = "random"
pool = "wired"     # "wired", "wifi", "auto" (by the default route), or a list
period = "day"     # one setting per day, from 05:00; or "boot"
```

Then `sudo systemctl restart bpfrag`. Once a day bpfrag picks one setting
from the pool and logs it (`Experiment for today: socket_buffers, switched
off in 50% of matches (picked at random from the wired pool: ...)`); the
pick is kept in `/var/lib/bpfrag`, so restarts and reboots during the day
don't change it. The day starts at 05:00, so an evening that runs past
midnight stays one experiment. Settings this machine already has (because
the distribution ships them, or bpftune holds them) are left out, since
both halves would be the same. The pools are the settings the built-in
profiles change: `dscp`, `socket_buffers`, `writeback` and `bulk`, plus
`wifi_power_save` on Wi-Fi. The day's pick waits until the network is up.
`sudo bpfrag --check` shows today's pick.

Testing one setting at a time is the point: switching everything off at
once (`setting = "all"`) can show whether bpfrag helps as a whole, but not
which setting did it.

To test one setting yourself, name it: `setting = "socket_buffers"`. The
names are the sections of [knobs.md](knobs.md): `dscp`,
`wifi_power_save`, `socket_buffers`, `writeback`, `bulk` (needs `[bulk]
enabled = true`), `coalescing` (only if your config sets
`coalesce_usecs`),
`all`, or `sysctl:<name>` for a single sysctl.

Either way, each match logs its arm when it starts (`Experiment:
socket_buffers off for this match`), `--monitor` shows it, and the health
line at the end says it again. `keep = 0.3` would keep the setting in 30%
of matches.

Why random: picking which matches get which setting by hand, or running
one evening of each, lets everything else that varies (time of day, the
server, the map, your ISP's evening load) line up with one side. A coin
flip per match spreads those evenly over both sides, so a difference that
shows up is the setting's.

Still worth doing:

1. **One experiment at a time,** so every difference has one cause.
2. **Same game and connection.** Note anything else running (downloads,
   streams, other devices); keep that the same through the experiment, or
   it becomes part of what you measure.
3. **Enough matches.** Match-to-match spread is large. Ten or more on each
   side is a start, more for small effects. A single great or terrible
   match proves nothing.
4. **Compare medians,** and look at how much the two sides overlap, not
   only at their middles. `matches.py --compare arm` does this (below).
5. **Write down the null results too.** "No difference over 20 matches" is
   what justifies removing a setting.

Without an experiment you can still compare by hand: turn a knob off under
`[tier.all]` (for example `wifi_powersave_off = false`), alternate A, B,
A, B by session, and label each with `matches.py --label`. For a
dry-run baseline, put `BPFRAG_FLAGS="--dry-run"` in `/etc/default/bpfrag`
and restart.

## Turning the log into data

`docs/scripts/matches.py` reads the journal and prints one CSV row per
match: the game, whether bpfrag was tuning or only measuring, the
experiment arm, the tiers, and every number from the health line. It
needs only Python 3, and also reads a saved log: `journalctl -u bpfrag |
docs/scripts/matches.py -`.

To compare an experiment's two arms directly (with `random`, each setting
tested is compared on its own):

```sh
docs/scripts/matches.py --since "2026-11-01" --compare arm
```

```
arm            matches    99% gap ms    longest ms        stalls    game drops
off                 12            23          99.5           1.5             0
on                  12            19          97.5             2             0

99% gap ms: p = 0.005 (difference in medians)
longest ms: p = 0.877 (difference in medians)
...
```

(Illustrative numbers.) The p-value is from a permutation test: how
often splitting the same matches into two random groups gives a
difference at least this big. Small means the difference is unlikely to
be chance. With fewer than about ten matches a side, or many identical
values (stalls are often 0), treat it as a lead, not proof. Matches
shorter than 5 minutes are left out (`--min-minutes`). `--compare label`
and `--compare mode` (tuned against dry-run) work the same way.

For a spreadsheet instead, leave out `--compare`; label sessions with
`--label`. A `gap_p99_ms` of 64 means "over 63 ms", the histogram's last
bucket. `silences` counts times nothing came from the server for 3
seconds or more while the game kept sending, until it came back (from
0.12.4): a lost connection the game got back, which the gap figures can't
show, since the old flow never resumes and the new one starts fresh.
A `server_changes` above 0 means the game moved to another
server mid-match: either several games the detector saw as one, or one
game moving (Deadlock does, through Steam's relays, with no break). The
match's timeline tells them apart ([detection.md](detection.md)); leave
rows of several games out of comparisons.

## Match timelines

The end-of-match line sums a whole match up. To see what happens inside
one (where one game ends and the next begins, when the server sends at
half its usual rate, what the traffic does around a stall), turn on
timelines:

```toml
[capture]
timeline = true
keep = 50        # the newest 50 are kept
```

Each match then gets a CSV file in `/run/bpfrag/captures`, named by its
start time and the game, and logged at the end of the match ("timeline
written to ..."). `/run` is in memory, so writing a row a second costs no
disk writes, and the files go at reboot: copy out the ones to keep. It's
about 300 KB an hour of play. The first line is a `#` comment with the
bpfrag version, the game and the experiment arm, then a row a second:

| Column | Meaning |
|---|---|
| `t`, `unix` | seconds since the match started; the time |
| `tier` | the tier in effect |
| `udp_tx_pps`, `udp_rx_pps` | the game's UDP datagrams a second, all its sockets |
| `udp_tx_bytes_s`, `udp_rx_bytes_s` | the same in bytes |
| `tcp_tx_bytes_s`, `tcp_rx_bytes_s` | the game's own TCP |
| `server`, `server_pps` | the server it receives from (a letter per address, and the port) and its packets that second (before 0.12.6, a mean over three seconds) |
| `peers` | addresses and ports that sent the game anything that second (relay pings included) |
| `port` | the game's local port that received the most that second |
| `gaps`, `gap_p50_ms`, `gap_p99_ms`, `gap_max_ms` | arrival gaps that second on the ports carrying the match; 64 is over 63 ms, except that from 0.12.3 a `gap_max_ms` over 63 ms is the gap's exact length |
| `stalls` | stalls that finished that second |
| `jitter_us` | how much each gap at game rate differed from the one before, on average, in µs (0.13.0) |
| `send_gap_max_ms`, `send_stalls` | the game's own sending that second: its longest gap between sends and the stalls (100 ms to 2 s) that ended in it (0.13.0) |
| `events` | match start and end, tier changes, server changes, the server going quiet for 2 s or more while the game kept sending (a stall in the match's summary; the `stalls` column is the meter's own count and doesn't include it) |

There are no addresses in it, so it can be attached to a "Share match
data" issue as it is. Any spreadsheet or `pandas.read_csv(path,
comment="#")` reads it.

## The comparisons worth running first

Ordered by how likely each is to show something:

1. **Bulk demotion during a download** (`setting = "bulk"`, with
   `[bulk] enabled = true`). Keep a big download or seed running through
   the experiment. This only shows an effect where something reads DSCP:
   CAKE (diffserv3, diffserv4 or diffserv8) on this machine, or a router
   that adopts client marks (dscpclassify), and only when the line is
   actually full. Check `tc -s qdisc` afterwards: CAKE's Bulk tin should
   show the traffic.
2. **Wi-Fi power save,** on Wi-Fi only (`wifi_power_save`). Watch the
   longest gap and stalls.
3. **DSCP on a busy Wi-Fi network** (`dscp`), with other devices
   streaming or downloading.
4. **Something bpfrag no longer sets** (busy polling, coalescing, the
   backlog or budget): put it in your config first, then name it
   (`sysctl:net.core.busy_poll`, `coalescing`). Worth it on hardware or a
   game unlike the ones in [findings.md](findings.md).
5. **Everything** (`all`): the overall picture, once the individual
   pieces are understood.

The buffer settings only matter when their drop counters move. If they stay at 0 across many matches with the defaults,
that's the finding. What a setting can do also depends on your
distribution's defaults: `sudo bpfrag --check` shows which settings
already hold their tier's value ([distros.md](distros.md)).

## Sharing your results

Open a [Share match data](https://github.com/shanefagan/bpfrag/issues/new?template=match_data.yml)
issue and paste the CSV from `matches.py`, with a few lines about the
setup: distribution, connection, line speed, any queue management, and
what was running alongside. The CSV has no addresses or host names, but
it does name the games and the times. Results go into
[findings.md](findings.md), "no difference" included.

## When a counter moves

- **Socket buffer drops:** check whether the game hitched at that moment.
  A dropped packet a few times a match is normal during loading or alt-tab.
- **NIC drops or "ran out of budget":** look for something else receiving
  heavily (a download, a backup), and at `arrives on`: is it on the same
  queue?
- **Stalls on Wi-Fi only:** a power save or roaming suspect. Compare with
  power save off, and check `iw dev wlan0 link` for the signal.

## Sharing results

Add an entry to [findings.md](findings.md) with the setup, the conditions,
the number of matches and the medians, including results where nothing
changed. `sudo bpfrag --report` gives the setup details (kernel, NIC
driver, config) in one go.
