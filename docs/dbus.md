# D-Bus interface

bpfrag publishes what it is doing on the system bus, so other programs (a
status bar, a notification, an experiment runner) can follow matches
without root and without polling `/run/bpfrag/stats.json`.

| | |
|---|---|
| Bus | system |
| Name | `com.performativenonsense.Bpfrag1` |
| Object | `/com/performativenonsense/Bpfrag1` |
| Interface | `com.performativenonsense.Bpfrag1` |

`Get` and `GetAll` take the interface name or, as the D-Bus specification
allows, an empty string.

It is read-only. There are no methods, `Set` is refused, and the bus
policy (`/usr/share/dbus-1/system.d/com.performativenonsense.Bpfrag1.conf`)
only lets other users call `Get`, `GetAll`, `Introspect` and `Ping`. Only
root, which is what the service runs as, can own the name.

## What it shows, and what it leaves out

Everything on the bus is also in `/run/bpfrag/stats.json`, which any user
can already read, and most of it is in the Waybar tooltip. The bus carries
less than that file: only the game and bpfrag's own state. The list of
other processes' UDP rates and the bulk transfers seen during a match are
left out.

`Reason` is why the classifier counts the process as a game, for example
`Steam app 730`. That can come from the game's environment, which other
users can't read in `/proc`; it is shown here for the same reason the
Waybar tooltip shows it, so you can tell why bpfrag acted.

bpfrag only knows about a game once it has traffic worth a look. It
doesn't see games being launched, or a game sitting in a menu without
traffic.

## Properties

| Property | Type | Between matches | During a match |
|---|---|---|---|
| `Version` | s | bpfrag's version | same |
| `DryRun` | b | true when started with `--dry-run` | same |
| `InMatch` | b | false | true |
| `GamePid` | u | 0 | the game's process id |
| `Game` | s | "" | its process name |
| `Reason` | s | "" | why it counts as a game |
| `Tier` | s | "" | `casual`, `competitive` or `intense` |
| `MatchSince` | t | 0 | when the match started, Unix seconds |
| `Experiment` | s | "" | this match's `[experiment]` arm, e.g. `busy_polling off`; "" if none |
| `Applied` | a(sss) | empty | each setting changed: name, value now, value before the match |
| `State` | s | `idle`, or `menu` | `match` |
| `AppId` | u | 0 | the game's Steam app id; 0 if Steam didn't launch it (or it's a non-Steam game added to Steam) |
| `MatchStartedAt` | t | 0 | when the match's traffic began, Unix milliseconds |

`State` is `idle` with no game in sight, `menu` while a game's traffic
stays on this machine (a menu or a local server, as in Deadlock's menu),
and `match` during a match. Most games send nothing in their menus, so for
them it goes straight from `idle` to `match` and back. The game's name in
a menu is in the `StateChanged` signal; the other properties stay empty
until a match.

`MatchStartedAt` is earlier than `MatchSince`: a match is only declared
once its traffic has been steady for a few seconds, and `MatchSince` is
when that happened. To cut a recording, use `MatchStartedAt`, and
`match_ended_at_ms` from `StateChanged` for the end.

In a dry run (`DryRun` true) nothing is changed, so `Applied` lists what
bpfrag would set, with the "before" value empty.

`Version` and `DryRun` never change. Every other property sends
`PropertiesChanged` when it changes, with the new values, so there is no
need to poll.

## Signals

**`StateChanged(s state, a{sv} info)`**, whenever `State` changes, after
the properties have been updated. `info` has:

| Key | Type | Meaning |
|---|---|---|
| `from` | s | the state before |
| `at_ms` | t | when the change happened, Unix milliseconds, by the game's traffic where bpfrag knows it: into a match, when its traffic began; out of one, when it stopped. Earlier than the signal itself, by up to `linger_secs` at the end of a match |
| `pid`, `game`, `app_id` | u, s, u | the game (the one leaving, on the way to `idle`); missing when there is none |
| `match_started_at_ms`, `match_ended_at_ms` | t, t | leaving a match: when its traffic began and stopped |
| `end_reason` | s | leaving a match: the same reason as `MatchEnded` |

**`MatchStarted(u pid, s game, s tier, s reason, s experiment)`**, when a
match is detected and its settings have been applied. The properties
already describe the match when it arrives.

**`TierChanged(u pid, s game, s from, s to)`**, when the tick rate moves the
match to another tier and its settings have been re-applied.

**`MatchEnded(u pid, s game, s reason, t duration_secs, s peak_tier,
s experiment, a{sv} health)`**, after the match's settings have been
restored. `reason` is what ended it: `game exited`, `netcode quiet for 15s`,
or `bpfrag stopped` when the daemon shuts down mid-match. `health` holds
the match's connection health, the same numbers as the log line (see
[measuring.md](measuring.md)); a key is missing when there is nothing to
report, and the dict is empty when bpfrag stopped:

| Key | Type | Meaning |
|---|---|---|
| `packets` | t | packets measured on the game's main flow |
| `gap_p50_ms`, `gap_p99_ms` | u | half, and 99%, of the gaps between them were at most this long; 64 means over 63 ms |
| `gap_max_ms` | d | the longest gap |
| `stalls` | t | times the game's traffic went quiet for 100 ms to 2 s mid-match and came back (lobbies and loading aren't counted) |
| `socket_drops` | t | UDP receive buffer overflows, anywhere on the machine |
| `game_socket_drops` | t | of those, on the game's own sockets |
| `backlog_drops` | t | per-CPU input backlog overflows |
| `nic_drops` | t | receive ring overflows on the game's interfaces |
| `squeezed` | t | times receive processing ran out of budget |
| `game_tcp_bytes` | t | TCP the game itself moved during the match (map or replay downloads, say) |
| `server_changes` | t | times the game moved to another server without going quiet (back-to-back games seen as one match) |
| `busy_polled` | t | packets received by busy polling, machine-wide; only present when busy polling was on during the match (or the count moved) |

## Writing a client

For a program that follows matches (switching OBS scenes, clipping a
recording, logging match times):

- **Start from the properties.** Read `State` (and the rest with `GetAll`)
  when the client starts, then follow `StateChanged` and
  `PropertiesChanged`. A client started mid-match learns about it that
  way, not from a `MatchStarted` it missed.
- **Watch the name.** bpfrag restarting drops the name and takes it again
  (`NameOwnerChanged` on `org.freedesktop.DBus`); read the properties
  again then. A stop mid-match sends `MatchEnded` and `StateChanged` with
  `end_reason` `bpfrag stopped` first.
- **Cut by the timestamps, not the signal's arrival.** Starts are
  declared a few seconds into the traffic and ends after `linger_secs`
  (15 s by default) of quiet; `at_ms`, `MatchStartedAt` and
  `match_ended_at_ms` say when it really happened. They come from the
  system clock, so they line up with a recording's timestamps.
- **Several matches in one session are normal.** Back-to-back games end
  and start their own matches (`match` → `menu` → `match`) when the game
  goes back to its menu in between.
- **In a Flatpak**, the sandbox needs `--system-talk-name=com.performativenonsense.Bpfrag1`.

Bot matches and matches against people are both matches; bpfrag doesn't
tell them apart.

## Trying it

```sh
busctl --system introspect com.performativenonsense.Bpfrag1 /com/performativenonsense/Bpfrag1
busctl --system get-property com.performativenonsense.Bpfrag1 \
    /com/performativenonsense/Bpfrag1 com.performativenonsense.Bpfrag1 Tier
gdbus monitor --system --dest com.performativenonsense.Bpfrag1
```

None of these need root. (`busctl monitor` does: it uses the bus's
privileged monitoring interface. `gdbus monitor` only subscribes.)

From Python, with PyGObject, which most desktops already have:

```python
from gi.repository import Gio, GLib

def on_signal(conn, sender, path, iface, name, args):
    print(name, args.unpack())

bus = Gio.bus_get_sync(Gio.BusType.SYSTEM)
bus.signal_subscribe(None, "com.performativenonsense.Bpfrag1", None,
                     "/com/performativenonsense/Bpfrag1", None,
                     Gio.DBusSignalFlags.NONE, on_signal)
GLib.MainLoop().run()
```

## Turning it off

```toml
[general]
dbus = false
```

Without a system bus (a container, a test namespace), bpfrag logs that
once and carries on; it tries again every 30 seconds.

## If the name can't be owned

The log then says `D-Bus: can't own com.performativenonsense.Bpfrag1`. Signals
still go out, but property reads can't reach bpfrag. Usually the bus
hasn't loaded the policy file yet: the packages reload it when they
install, and after a `make install` run `sudo systemctl reload dbus`.
bpfrag asks for the name again every 30 seconds, so it doesn't need a
restart.

## Stability

The `1` in the name is the interface version, and what's documented here
holds for as long as it is `Bpfrag1`:

- Properties, signals and their arguments keep their names, types and
  meaning. The `State` and `Tier` values listed stay.
- New properties, signals, `info` and `health` keys may be added. Clients
  should ignore what they don't know, and treat a missing dict key as
  "not known".
- A new `State` or `Tier` value is a breaking change, so it would come
  with a new interface.
- Anything that breaks an existing client goes in a new interface
  (`com.performativenonsense.Bpfrag2`), published alongside the old one
  for at least one release.

What bpfrag counts as a match can still get better within `Bpfrag1` (a
menu no longer counting as one, say): that changes when the signals fire,
not what they mean.
