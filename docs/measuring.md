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

1. **One change at a time.** Pick one setting (say Wi-Fi power save) and
   compare it on against off, with everything else the same. To turn one
   knob off without stopping the rest, add it under `[tier.all]` in
   `/etc/bpfrag/bpfrag.toml`, for example `wifi_powersave_off = false`.
   The comparisons that matter most are in the next section.
2. **Same game, same server region, same connection,** at similar times of
   day. Note anything else running (downloads, streams, other devices on
   the network).
3. **Alternate,** don't batch: A, B, A, B... so a bad evening affects both
   sides alike. A whole session of each risks comparing two different
   evenings.
4. **Enough matches.** Match-to-match spread is large. Ten or more of each
   is a start, and more is better for small effects. A single great or
   terrible match proves nothing.
5. **Compare medians across matches,** not single matches: the median of
   each side's 99% gap, longest gap and stall count. Look at how much the
   two sides overlap, not only at their middles.
6. **Write down the null results too.** "No difference over 20 matches" is
   what justifies removing a setting.

Restart the service after editing the config: `sudo systemctl restart
bpfrag`. For a dry-run baseline, put `BPFRAG_FLAGS="--dry-run"` in
`/etc/default/bpfrag` and restart.

## Turning the log into data

`docs/scripts/matches.py` reads the journal and prints one CSV row per
match: the game, whether bpfrag was tuning or only measuring, the tiers,
and every number from the health line. Give each condition a label:

```sh
# a session with everything on
docs/scripts/matches.py --since "2026-11-01 19:00" --label baseline-tuned > tuned.csv
# a session with --dry-run (or with one knob off)
docs/scripts/matches.py --since "2026-11-02 19:00" --label dryrun --no-header >> tuned.csv
```

It needs only Python 3. It also reads a saved log: `journalctl -u bpfrag -o
short-iso | docs/scripts/matches.py -`. Open the CSV in any spreadsheet and
compare the `gap_p99_ms`, `gap_longest_ms` and `stalls` columns per label.
A `gap_p99_ms` of 64 means "over 63 ms", the histogram's last bucket.

## The comparisons worth running first

Ordered by how likely each is to show something:

1. **Bulk demotion during a download.** Start a big Steam download and keep
   it running. Compare matches with `[bulk] enabled = true` against `false`.
   This only shows an effect where something reads DSCP: CAKE (diffserv3,
   diffserv4 or diffserv8) on this machine, or a router that adopts client
   marks (dscpclassify). Check `tc -s qdisc` afterwards: CAKE's Bulk tin
   should show the traffic.
2. **Wi-Fi power save,** on Wi-Fi only. `wifi_powersave_off = false` against
   the default. Watch the longest gap and stalls.
3. **DSCP on a busy Wi-Fi network.** Other devices streaming or
   downloading. `[tier.all] dscp = false` against the default.
4. **Busy polling.** `sysctl = { "net.core.busy_read" = false,
   "net.core.busy_poll" = false }` under `[tier.all]`. Note frame times and
   CPU use too, since busy polling costs both.
5. **Everything against `--dry-run`.** The overall picture, once the
   individual pieces are understood.

The buffer, backlog and budget settings only matter when their drop
counters move. If they stay at 0 across many matches with the defaults,
that's the finding.

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
