# Roadmap

What might come next, in rough order. Everything here is speculative:
nothing is promised, and an item moves up when a measurement or a user
asks for it. [experiments.md](experiments.md) is the companion list of
things to measure; this one is things to build.

The rule from [docs/README.md](README.md) applies to every item: a new
setting needs a mechanism, a source, an expected effect and a number that
would show it. A new measurement needs a question it answers.

## Before 1.0

1.0 means the surface stops moving, not that the features are finished.

- **More matches on the current release.** The outage rule and
  second-game detection (0.14.1) are tested synthetically; a week of real
  play should show neither misfires.
- **A page of stability promises:** which config keys, CLI flags, D-Bus
  names, timeline columns and journal fields won't change without a major
  version, and which are free to (log wording, the health line's text).
- **A changelog** from 0.1, and a last pass over the README.
- **Small fixes from the November review:** the health line when the
  daemon stops mid-match, a cap on `/proc` reads, atomic send counters,
  blank send columns once the game has no server.

## Next: measurements

bpfrag's strongest result so far is that it can say where a bad match came
from. These extend that.

- **Round-trip time** (experiments M3). The gaps measure jitter, not
  delay: a queue holding a steady 80 ms looks perfect. A probe a second to
  the gateway and to one public address during a match would separate
  "the home network" from "beyond it". Needs care: it sends packets, which
  nothing in bpfrag does today, so it would be off by default.
- **Health during the match on D-Bus** (M10): the figures so far as a
  property refreshed every few seconds, not only in `MatchEnded`. What an
  overlay or a status bar needs to say "your side is fine" mid-game.
- **A stable name for a server across matches** (M7), without storing
  addresses: a salted hash per install would let "relay C is the bad one"
  hold from one evening to the next.
- **The game's socket buffer sizes** (M2), to settle whether the buffer
  settings reach the game's socket at all. If they don't, they go.
- **Frame times next to the timeline** (M6): join a MangoHud log by time,
  so a network stall and a frame hitch can be told apart, or shown to be
  the same event.
- **An A/A mode** (experiment 16): two arms with nothing different, to
  show how big a difference noise alone produces before reading any A/B.

## Next: detection

- **TCP games' health.** Since 0.17 a game whose TCP looks like a
  multiplayer game's is tuned like a match, with a summary of its
  session at the end but no gap figures. Next: time the game's receives
  (what it feels when a lost segment holds the rest back; arrival gaps at
  the NIC don't show that) and count its retransmissions and timeouts
  (M9), so its health line can say where a freeze came from.
- **Back-to-back games** (experiment 22): where one match ends when the
  next starts in the same process, from the timelines already collected.
- **Hosted servers** (experiment 24): what a game server on the same
  machine looks like, and whether bpfrag should treat it as a match.

## Maybe: settings

Each of these waits on its experiment. Given how the first settings have
measured (busy polling, the backlog, the budget and coalescing all came
out), the bar is a visible effect.

- **Energy Efficient Ethernet off during a match** (experiment 5), on
  the Intel I225/I226 controllers where it has a history of trouble.
- **Wi-Fi background scans held off during a match** (experiment 7), if
  the timelines show periodic stalls that line up with scans.
- **EF in place of CS4** for the game's packets (experiment 9), as a
  config choice if it measures better through CAKE or on Wi-Fi.
- **Removing what doesn't pay:** socket buffers are the next candidate,
  if the game's socket turns out never to use them (M2).

## Maybe: reach

- **Other distributions' package repositories** (AUR, COPR, a PPA), once
  1.0 gives them something stable to carry.
- **Results from more than one machine.** Every finding so far is one
  desktop, one wired NIC, mostly one game. A documented way to share a
  set of timelines (already free of addresses) would test whether the
  findings hold on Wi-Fi, on a handheld, on other games.
- **A status-bar or overlay example** beyond the waybar output, built on
  the D-Bus interface.

## Not planned

- **CPU scheduling, frequency, idle states, IRQ affinity, RPS/RFS:**
  sched_ext schedulers, gamemode, tuned and irqbalance own these, and
  bpfrag promises to stay out ([AGENTS.md](../AGENTS.md)).
- **More than one game at a time.**
- **Changing the game's own settings,** or anything on the router beyond
  what the packets' DSCP mark asks of it.
- **Kernels before 6.6.**
- **`tcp_notsent_lowat`** (experiment 19): recorded there as not worth
  testing, with the reason.
