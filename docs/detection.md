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
   `BPFRAG_GAME=1 %command%` in Steam launch options.
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

The tier comes from the smoothed packet rate. Total packets per second are
roughly twice the server tick rate:

- **INTENSE** at ≥ 155 pkt/s: 128-tick servers.
- **COMPETITIVE** at ≥ 85 pkt/s: 64-tick servers.
- **CASUAL** below that.

There's ±15 pkt/s of hysteresis around each threshold. Moving up takes 3
confident windows, moving down takes 4, and tier changes are at least 5
seconds apart. A match never drops back to CASUAL while traffic is still
flowing.

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
`sched_process_exit` hook), or after **15 quiet seconds**, for example back in
the menus. "Quiet" is the median of the last five seconds at 10 packets a
second or fewer: menus and queues are mostly silent but ping relays in
short bursts, and judging each second on its own let those bursts keep one
match going into the next (0.4.0 and earlier). With the game left running,
each match is its own match: its own health line, its own experiment
draw, its own row in `matches.py`. A dip while you're dead or waiting to
respawn stays well above that (Deadlock still gets 70+ packets a second).

Rejections by the deny list (or `BPFRAG_GAME=0`) are only logged at debug
level (`-v`). A steady UDP process with no game signals at all is logged
once at info, since it may be a native game that needs `--allow`.

If you want to see the detector's view of your system, run
`sudo bpfrag --dry-run -v` and `bpfrag --monitor 1` in another terminal. The
monitor lists the busiest UDP processes, their rates and the verdict for each.


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
