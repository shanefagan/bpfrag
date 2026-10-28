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
| half ≤N ms | median gap between the game's incoming packets (1 ms buckets) | the server's tick rate; shouldn't change |
| 99% ≤N ms | the gap 99% of packets beat | jitter anywhere on the path: Wi-Fi, queues, the internet |
| longest N ms | the longest gap counted (pauses of 2 s or more aren't) | one-off hiccups, Wi-Fi power save |
| stalls | the flow went quiet for 100 ms to 2 s, then came back at game rate | what a player feels as rubber-banding |
| socket buffer drops | a UDP receive buffer overflowed (`RcvbufErrors`), anywhere on the machine; "(N the game's)" is how many were the game's own sockets | socket buffers, a game that stopped reading |
| backlog drops | per-CPU input queue overflowed | `netdev_max_backlog` (RPS or virtual devices only) |
| NIC drops | the NIC's receive ring overflowed | coalescing, ring size, very high rates |
| ran out of budget | receive processing deferred | `netdev_budget*`, heavy receive load |
| arrives on | the receive queue and IRQ | RSS, whether a download shares the queue |
| bulk | what was demoted, and how much | `[bulk]` |

Limits to keep in mind:

- **1 ms resolution.** Changes of tens or hundreds of microseconds
  (interrupt coalescing, busy polling) can't show in the gap numbers.
  They'd need finer timing.
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
- **It's the incoming direction only.** DSCP and Wi-Fi contention affect
  the outgoing packets first. The server's view of your packets, or the
  game's own network graph, covers that side.

## A comparison you can trust

The simplest fair comparison is an **experiment**: bpfrag switches one
setting off in a random half of your matches and records which half each
match was in. You play as usual.

```toml
# /etc/bpfrag/bpfrag.toml
[experiment]
setting = "busy_polling"
```

Then `sudo systemctl restart bpfrag`. Each match logs its arm when it
starts (`Experiment: busy_polling off for this match`), `--monitor` shows
it, and the health line at the end says it again. The setting names are
the sections of [knobs.md](knobs.md): `dscp`, `wifi_power_save`,
`coalescing`, `busy_polling`, `socket_buffers`, `backlog`, `budget`,
`writeback`, `bulk` (needs `[bulk] enabled = true`), `all` (the "off"
matches are only measured, like a dry run), or `sysctl:<name>` for a
single sysctl. `keep = 0.3` would keep the setting in 30% of matches.

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

To compare an experiment's two arms directly:

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
bucket.

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
4. **Busy polling** (`busy_polling`). Check first that it happens at all
   ([experiments.md](experiments.md#1-does-busy-polling-reach-the-game)):
   it probably doesn't reach the game's socket. Note frame times and CPU
   use too, since busy polling costs both.
5. **Everything** (`all`): the overall picture, once the individual
   pieces are understood.

The buffer, backlog and budget settings only matter when their drop
counters move. If they stay at 0 across many matches with the defaults,
that's the finding. What a setting can do also depends on your
distribution's defaults: `sudo bpfrag --check` shows which settings
already hold their tier's value ([distros.md](distros.md)).

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
