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

bpfrag only knows about a game once a match is detected, from its traffic.
It doesn't see games being launched, or exiting outside a match.

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

`Version` and `DryRun` never change. Every other property sends
`PropertiesChanged` when it changes, with the new values, so there is no
need to poll.

## Signals

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
| `stalls` | t | gaps of 100 ms or more |
| `socket_drops` | t | UDP receive buffer overflows, anywhere on the machine |
| `game_socket_drops` | t | of those, on the game's own sockets |
| `backlog_drops` | t | per-CPU input backlog overflows |
| `nic_drops` | t | receive ring overflows on the game's interfaces |
| `squeezed` | t | times receive processing ran out of budget |

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

## Changes

The `1` in the name is the interface version. New properties, signals and
`health` keys may be added under it; anything that would break an existing
client gets a new name instead.
