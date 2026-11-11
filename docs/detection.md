# How a match is detected

How bpfrag decides a game's match has started, which tier it's in, which
interfaces carry it, and when it's over. The code is in `src/detect/`.

Every process doing UDP gets a 1-second window of tx/rx packets and bytes. A
process becomes a candidate after **3 consecutive windows** where:

- the smoothed rate (8-window mean) is at least **25 pkt/s**;
- **both directions** carry at least 5 pkt/s. Games send input and receive
  snapshots; mDNS, DNS bursts and one-way streams don't;
- the **average payload is ≤ 1100 bytes**. Bulk QUIC and torrents sit at
  1200 bytes and up;
- **jitter** (mean absolute deviation ÷ mean) is ≤ 0.5. Tick-driven netcode
  is close to a metronome.

The candidate then has to pass the **classifier**. A Discord call is also a
steady 50 pkt/s two-way stream, so traffic alone can't decide. The classifier
checks these signals, strongest first:

1. `BPFRAG_GAME=1` / `0` in the environment. This is an explicit tag, e.g.
   `BPFRAG_GAME=1 %command%` in Steam launch options. (`BPFRAG_OBSERVE=1`
   is a different tag: it asks for the game's traffic to be logged, and
   doesn't change this decision; see
   [below](#observing-one-game-bpfrag_observe1).)
2. Allow and deny globs on the process name. The built-in deny list covers
   browsers, voice and chat clients, torrent clients, network daemons and the
   Steam client itself.
3. `SteamAppId` / `SteamGameId`, which is set for everything Steam launches,
   native or Proton.
4. `LD_PRELOAD` containing gamemode or MangoHud.
5. An executable or command line inside a game library (`steamapps/common/`,
   `~/Games/`, Lutris, Heroic).
6. Wine/Proton: `*.exe` on the command line, or a `wine*` executable.
7. A launcher ancestor: reaper, pressure-vessel, gamescope, Lutris, Heroic,
   umu, Bottles and so on.

A game that passes is **watched** before anything is tuned: the arrival
meter goes on its ports, on the default-route interfaces and on loopback,
and counts where its packets arrive. Traffic from outside in two of three
one-second windows, and more of it than over loopback, starts the match
(usually two seconds in); a game checking in with servers from its menu
sends some too (Deadlock pings Steam's relays for a second or two as it
starts, while its menu runs over loopback, or sometimes before the menu
is up, so from 0.12.5 nothing in a game's first 20 seconds,
`launch_secs`, starts a match). Some games talk to a server of their own in
their menus, over loopback: Deadlock does, about 128 packets a second each
way, which by rate alone looks like an INTENSE match. If after three
seconds the game's traffic arrives on loopback and not from outside, no
match starts, and the log says so once:

```
Deadlock (pid 643053): its traffic stays on this machine (a menu or a local server); waiting for traffic from outside before tuning
```

A game in that state doesn't hold the watch for good: another game that
passes the checks takes it over, so the second game opened is tuned too.
The game set aside isn't picked up again for 60 seconds, so two games in
their menus don't swap places every few seconds.

`bpfrag --monitor` shows the same while it lasts. The match starts when
traffic from outside does. If the meter sees the game's traffic nowhere
(a path it isn't attached to, say an interface missing from `--iface`), the
rate alone decides, as before.

The tier comes from the game's update rate: twice the smaller of its
smoothed send and receive rates, about twice the server's tick rate. (The
total would count a server that splits big updates into several packets
as a faster one: Deadlock, a 64-tick game, receives 50 to 150 packets a
second as fights come and go.) It's the median over the last 8 windows,
and from 0.12.4 leaves out traffic with peers other than the game's
server: Deadlock pings a handful of Steam's relays for half a minute at a
time, 20 more packets a second each way, which twice moved a 64-tick
match to INTENSE.

- **INTENSE** at ≥ 155 pkt/s: 128-tick servers.
- **COMPETITIVE** at ≥ 85 pkt/s: 64-tick servers.
- **CASUAL** below that.

There's ±15 pkt/s of hysteresis around each threshold. Moving up takes 3
confident windows, and tier changes are at least 5 seconds apart. Within a
match the tier only goes up: a game's update rate dips with what's
happening in it (Deadlock sends 32 a second instead of 64 while the player
is dead), and following it down re-applied settings every couple of
minutes for nothing. While the game's traffic isn't arriving from outside
(back in its menu at the end of a match), the tier doesn't change at all.

bpfrag puts the DSCP marker on the interfaces carrying the default routes,
or the ones you pass with `--iface`. The marker counts the game's packets per
interface, and per-interface settings (coalescing, Wi-Fi power save) go only
on the links carrying at least 10% of them, so a desktop with both Ethernet
and Wi-Fi up doesn't touch the one the game isn't using. They wait a few
seconds at the start of a match while the marker finds that out, and a link
the game stops using keeps its settings for 30 seconds, so stray packets on a
second link don't toggle anything. If the packets only show up inside
a tunnel (WireGuard, OpenVPN, PPPoE), they still leave through a real link
underneath, so those settings stay on every default-route interface.

During a match bpfrag re-checks every 2 seconds, so docking, switching from
Wi-Fi to Ethernet, or a VPN coming up is followed without waiting for the
next match.

A match ends **immediately when the game exits** (via the
`sched_process_exit` hook), after **15 quiet seconds**, for example back in
the menus, or after **6 seconds of its traffic staying on this machine**
(back to a menu with a server of its own; shorter than the quiet wait,
since Deadlock can be in its next game 12 seconds after the last one
ends, and with 15 seconds two games became one match on 2026-11-02).
"Quiet" is the median of the
last five seconds at 10 packets a second or fewer: menus and queues are
mostly silent but ping relays in short bursts, and judging each second on
its own let those bursts keep one match going into the next (0.4.0 and
earlier); a second with traffic again doesn't add to the count, and the
count only starts over once traffic has stayed for three seconds in a row
(a burst can fall across two of bpfrag's readings, which until 0.16.0
started the count again every time and kept the match going). Within
30 seconds of the game loading something over its own TCP (a megabyte
or more in a second), quiet doesn't end the match: Trackmania goes 16
seconds without UDP while it loads a map, which cut sessions in two
before 0.12.6. "Staying on this machine" is the same median, of packets from
outside, while loopback carries at least that. During a match, packets
from peers other than its server don't count as its traffic from outside:
a relay Deadlock had moved away from kept pinging it at 5 to 10 a second,
which held a match open on the end screen until the game was closed
(fixed in 0.16.2). With the game left
running, each match is its own match: its own health line, its own
experiment draw, its own row in `matches.py`, its own timeline. A dip
while you're dead or waiting to respawn stays well above that (Deadlock
still gets 70+ packets a second).

Before 0.8.0, a game whose menu talks to itself never went quiet between
matches: Deadlock's Street Brawl games, played back to back, ended up as
one long match, and the "match" carried on, tuned, in the menu after the
last one ([findings.md](findings.md#back-to-back-games)). After a match
ends that way, the game is watched again, and its next game starts a new
match.

bpfrag also follows which server the game receives from (the remote
address and port sending the most to the game's ports, at 10 packets a
second or more), logs it, and logs when another one takes over for three
seconds:

```
Deadlock: receiving from server A:27031 on local port 51234 (~64 pkt/s)
Deadlock: server changed from A:27031 (now ~0 pkt/s) to B:27044 on local port 51234 (~62 pkt/s)
```

Servers are named by a letter per address, in the order they turn up,
plus the port; addresses themselves are only logged at debug level
(`-v`), since a game that talks peer to peer would put other players'
home addresses in the log. The end-of-match line counts the changes
("the game's server changed 5 times"). A change within one match means
the game moved without going quiet or back to its menu. That can be two
games in one ([experiments.md](experiments.md#22-back-to-back-games)),
but it can also be the same game moving mid-match: Deadlock moved twice
on 2026-11-02 with no break at all, the same rate carrying straight on
from a new address and a new local port (most likely Steam's relay
network changing route). `[capture] timeline` shows which
([measuring.md](measuring.md#match-timelines)).

Rejections by the deny list (or `BPFRAG_GAME=0`) are only logged at debug
level (`-v`). A steady UDP process with no game signals at all is logged
once at info, since it may be a native game that needs `--allow`.

If you want to see the detector's view of your system, run
`sudo bpfrag --dry-run -v` and `bpfrag --monitor 1` in another terminal. The
monitor lists the busiest UDP processes, their rates and the verdict for each.


## Games that talk TCP

Match detection looks for a steady two-way UDP stream, which is how most
competitive games talk. Some games use TCP instead (World of Warcraft and
other MMOs, many older games), and UDP games also use TCP on the side (a
map or replay download). bpfrag doesn't tune for TCP games yet: what
their traffic looks like across games isn't known well enough to detect
them reliably.

`[detect] tcp = "observe"` gathers that data. With it, bpfrag counts TCP
send and receive calls per process all the time (which costs a little CPU
on every TCP send and receive), and for any process the classifier calls
a game (a launcher parent, a Steam app, a game path, the allow list) that
keeps talking TCP both ways for 10 seconds, it logs:

```
TCP game seen: Wow.exe (pid 4242) at ~18 sends/s and ~25 receives/s [launched by lutris]; observing only, nothing is tuned
TCP game session: Wow.exe for 1h12m03s: typically 18 sends/s and 25 receives/s, 64 and 210 bytes each, rate variation 0.41, 38 MB in all
```

The session ends after 30 quiet seconds or when the game exits. Rates are
of send and receive calls, not packets. "Rate variation" is the mean
deviation of the per-second rate over its mean: near 0 for a game that
ticks like a metronome, far above 1 for a download. Nothing is changed for
these games in any mode.

During a UDP match, the game's own TCP traffic is always counted, and the
match's health line says how much it moved when it's over 1 MB ("the
game's own TCP: 120 MB"), so a map download during a match shows up.

## Observing one game: `BPFRAG_OBSERVE=1`

For a game whose traffic isn't known (UDP or TCP, steady or bursty), tag
it in its environment rather than turning on `tcp = "observe"` for every
process. In Steam, put this in the game's launch options:

```
BPFRAG_OBSERVE=1 %command%
```

(Lutris and Heroic have an environment variables setting per game; from a
terminal, `BPFRAG_OBSERVE=1 ./game`.) bpfrag then logs the UDP and the
TCP of every process with the tag, which is the game and everything it
starts, since children inherit their parent's environment:

```
Observing Some Game (SomeGame-Win64, pid 4242): TCP at ~31 sends/s and ~33 receives/s [BPFRAG_OBSERVE=1]
Observed Some Game (SomeGame-Win64, pid 4242): TCP for 52m10s: typically 31 sends/s and 33 receives/s, 60 and 240 bytes each, rate variation 0.38, 41 MB in all
```

(Illustrative numbers.) The first line comes once the process has had
traffic for 10 seconds, one way or both; the second when it goes quiet
for 30 seconds or exits, or a short transfer of a megabyte or more ends
(a map download). The fields are the ones in "Games that talk TCP"
above; for UDP a send or receive is one datagram. The name in brackets is
the program itself, which tells the game apart from its launcher or
helpers when they share the game's name.

The tag only adds logging. Whether the process is a game, and whether
its UDP traffic starts a match, is decided as usual: a tagged UDP game is
still detected and tuned like any other. To log a game without ever
tuning for it, tag it with `BPFRAG_GAME=0` as well.

`bpfrag --classify PID` says whether a process carries the tag, and
`bpfrag --monitor` lists the tagged processes being logged. bpfrag lists
/proc every 5 seconds to find tagged processes (the BPF side can't see
environments), so the first few seconds of a game's traffic can be
missed. Reading other users' environments needs `CAP_SYS_PTRACE`, which
the systemd unit gives bpfrag.

## Bulk transfers

While a match is on, a second detector (`src/detect/bulk.rs`) follows
every other process's combined send and receive rate, TCP and UDP, in the
same 1-second windows:

- a process moving at least `bulk.min_mbps` (2 Mbit/s) for `bulk.secs` (5)
  windows in a row is bulk;
- it stops being bulk after `bulk.release_secs` (10) windows below that;
- the game is never bulk, and nor is anything on the never list (streaming
  hosts like OBS, voice apps, VPN and overlay clients);
- anything on the always list (torrent clients) is bulk whenever it moves
  anything.

TCP is only counted while a match is on. What happens to bulk traffic is
in the README ("Bulk transfers during a match") and
[knobs.md](knobs.md#bulk-demotion-dscp-le).
