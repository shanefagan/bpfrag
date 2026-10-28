# bpfrag

eBPF-driven, self-reverting network tuning for competitive gaming on Linux.

bpfrag watches UDP traffic per process from the kernel. When a game's netcode
shows up (a steady, two-way, small-packet tick stream from a process that
is a game), it applies a networking profile for the length of the
match. When the match ends or the game exits, every change is put back
exactly as it was.

It only touches networking, plus optionally dirty-page writeback. It never
touches CPU scheduling, so it runs alongside sched_ext schedulers, and it
leaves bpftune's sysctls alone while bpftune is running (see [Running
alongside other tuners](#running-alongside-other-tuners)).

```
$ sudo bpfrag
20:14:02 INFO  bpfrag 0.3.0 started; waiting for game traffic
20:15:10 INFO  Match detected: Counter-Strike 2 (pid 6230) at ~128 pkt/s (tx 64, rx 64) -> COMPETITIVE [Steam app 730]
20:15:10 INFO  COMPETITIVE profile: net.core.busy_poll=50, net.core.busy_read=50, enp6s0 coalescing=10us, ..., dscp=CS4 on enp6s0
20:52:47 INFO  Match ended after 37m37s (game exited); settings restored
20:52:47 INFO  Counter-Strike 2: packet gaps half ≤16 ms, 99% ≤19 ms, longest 31 ms, 0 stalls (100 ms+); no drops
```

## How it works

```
 kernel (BPF)                                    userspace (Rust)
 ────────────                                    ────────────────
 raw_tp sock_send_length ─┐
 raw_tp sock_recv_length ─┴─► per-process UDP ─► detector, 1 s windows:
                              (and TCP in a        steady? two-way? small packets?
                              match) counters
                                                       │
 raw_tp sched_process_exit ─► ringbuf ─────────► "game exited": end match now
                                                       │
                                                       ▼
                                                 classifier: is it really a game?
                                                 (Steam app id, launcher lineage,
                                                  Wine/Proton, allow/deny lists)
                                                       │
 tc egress (tcx link) ◄── game's UDP ports ◄──── tier from tick rate:
   rewrites DSCP                                 CASUAL / COMPETITIVE / INTENSE
                                                 apply knobs (journalled first)
 tc ingress (tcx link) ─► gaps between the ───► match health: packet gaps,
   times arrivals         game's packets         drop counters
                                                 ... match over -> restore
```

The BPF side only counts packets, reports game exits, marks packets and times
their arrival. Every decision happens in Rust, where it can be unit tested
and changed without fighting the verifier.

## What gets tuned

| Knob | CASUAL | COMPETITIVE | INTENSE |
|---|---|---|---|
| DSCP mark on the game's packets | CS4 | CS4 | CS4 |
| NIC interrupt coalescing (rx/tx) | untouched | 10 µs | 0 µs |
| `net.core.busy_read` / `busy_poll` | 25 µs | 50 µs | 75 µs |
| `net.core.{r,w}mem_max` (raise-only) | 8 MiB | 16 MiB | 32 MiB |
| `net.core.{r,w}mem_default` (raise-only) | 256 KiB | 256 KiB | 256 KiB |
| `net.core.netdev_max_backlog` (raise-only) | 5000 | 5000 | 5000 |
| `net.core.netdev_budget` (raise-only) | 400 | 600 | 800 |
| `net.core.netdev_budget_usecs` (raise-only) | 8000 | 8000 | 8000 |
| `net.ipv4.udp_early_demux` | 1 | 1 | 1 |
| `vm.dirty_bytes` / `dirty_background_bytes` (lower-only) | untouched | 256 / 64 MiB | 256 / 64 MiB |
| Wi-Fi power save (wireless interfaces) | untouched | off | off |

The network values are the three profiles from the original bpftune
gaming-tuner patches, minus `net.ipv4.udp_mem`. That one is counted in pages,
the kernel already sizes it from RAM (several GiB, against the kilobytes a
game buffers), and the original values raised its hard limit to 32–128 GiB. "Raise-only" means bpfrag never shrinks something you
already sized larger, and "lower-only" means writeback is only ever
tightened. Everything is overridable per tier (see `dist/bpfrag.toml`).

How much each one matters varies a lot. The clearest cases are DSCP CS4,
which gets the game's packets ahead on busy Wi-Fi and through CAKE or QoS
routers, and turning Wi-Fi power save off, which avoids wake-up delays after
lulls. Interrupt coalescing trims up to a quarter of a millisecond while
something else downloads. The buffer, backlog and budget headroom only
matter when their drop counters move, and busy polling's effect on games is
still unmeasured. **[docs/knobs.md](docs/knobs.md)** goes through every
setting: the kernel mechanism behind it, with sources, what to expect, when
nothing will happen, and how confident that is.

## How a match is detected

A process becomes a candidate after 3 seconds of steady, two-way,
small-packet UDP traffic at 25 packets/s or more, the shape of a game's
netcode. A classifier then checks it really is a game: Steam app ids, a
game library path, Wine/Proton, a launcher ancestor, gamemode or MangoHud,
and allow and deny lists, so a Discord call or a browser's QUIC traffic
doesn't count. The tier follows the packet rate (about twice the server's
tick rate), with hysteresis. A match ends the moment the game exits, or
after 15 quiet seconds.

`sudo bpfrag --dry-run -v` with `bpfrag --monitor 1` in another terminal
shows the detector's view. [docs/detection.md](docs/detection.md) has the
details: thresholds, classifier signals, tiers, and how the interfaces the
game uses are followed.
## Is it helping?

Every match gets a health report, live in `--monitor` and the Waybar
tooltip, and logged when the match ends:

```
Deadlock: packet gaps half ≤16 ms, 99% ≤23 ms, longest 48 ms, 0 stalls (100 ms+); no drops; arrives on eno1 rx queue 2, IRQ 140
```

- **Packet gaps** are timed as packets arrive, on the game's main flow. A
  64-tick server gives gaps of about 16 ms; the 99% figure, the longest gap
  and stalls (the flow going quiet for 100 ms or more mid-match) show the
  spikes you feel as rubber-banding. Lobbies and menus, where games send
  only keepalives, aren't counted.
- **Drops** are the kernel counters that grow when the receive path can't
  keep up: socket buffers, the input backlog, the NIC's ring.
- **The receive queue** is where the game's packets come in, and which IRQ
  serves it.

Most of the spread in packet gaps comes from the internet and the game
server, so one match proves little either way. To find out what a setting
does, let bpfrag run an experiment: it switches that setting off in a
random half of your matches and labels each one.

```toml
[experiment]
setting = "wifi_power_save"
```

`docs/scripts/matches.py --compare arm` then compares the two halves.
**[docs/measuring.md](docs/measuring.md)** has the details, and results
go in [docs/findings.md](docs/findings.md). `--dry-run` measures the same
way but changes nothing, for a baseline.

What a tier changes also depends on your distribution's defaults: `sudo
bpfrag --check` lists every setting's value now and what each tier would
set it to. [docs/distros.md](docs/distros.md) compares Ubuntu, CachyOS and
Bazzite.

## Bulk transfers during a match

A Steam download or a torrent running during a match fills the queues
the game's packets wait in. bpfrag can mark that traffic low priority
for the length of the match, so whatever honours DSCP serves the game
first. It's off by default; turn it on in `/etc/bpfrag/bpfrag.toml`:

```toml
[bulk]
enabled = true
```

- **What counts as bulk:** any process other than the game moving at
  least 2 Mbit/s (sent plus received, TCP and UDP) for 5 seconds. It stops
  being bulk after 10 seconds below that. Torrent clients count as soon as
  they move anything. OBS and other streaming hosts, voice apps, and VPN or
  overlay clients (whose traffic may be the game's) never count. The
  thresholds and both lists are in `[bulk]`.
- **What happens:** its packets get DSCP **LE** (RFC 8622 "lower effort"),
  in both directions: outgoing at tc egress, incoming at tc ingress. A
  packet the app or the sender already marked is left alone, and nothing
  changes outside a match or in a dry run.
- **Where it helps:**
  - **CAKE on this machine** (diffserv3/4/8): LE goes in the Bulk tin.
    bpfrag marks downloads before a CAKE setup's redirect to its IFB, so
    download shaping sees it too.
  - **An OpenWrt router running [dscpclassify](https://github.com/jeverley/dscpclassify):**
    it adopts the DSCP its clients set and, with its `layer_cake_ct`
    script, applies the connection's mark to the download direction as
    well. The same goes for the game's CS4.
  - **Nothing that reads DSCP:** no effect, and no harm.
- **Seeing it:** `--monitor` lists bulk processes live ("bulk: steam 38
  Mbit/s (marked LE)"), the log says when one starts and stops, and the
  match summary says how much each moved ("bulk: steam 412 MB marked
  LE"). With `[bulk]` off, they are shown but not marked, so you can see
  what it would do first. `--report` includes `tc -s qdisc`, where CAKE's
  per-tin counters show LE traffic landing in the Bulk tin.

## Running alongside other tuners

**sched_ext (scx_lavd, scx_rusty, scx_bpfland...).** There's no overlap.
bpfrag never touches CPU scheduling, priorities, affinity or frequency.
sched_ext schedulers use struct_ops, while bpfrag uses tracepoints and tc,
and the two run side by side.

The one indirect interaction is busy polling. A socket read may spin for up
to 25–75 µs, and the scheduler counts that as the game thread's runtime. If
you'd rather not have it, set `sysctl = { "net.core.busy_read" = false,
"net.core.busy_poll" = false }` under `[tier.all]`.

**bpftune.** They do overlap, and bpfrag handles it. bpftune's sysctl watcher
switches off a whole tuner (e.g. `udp_buffer`, `net_buffer`) as soon as any
other process writes one of its sysctls. So while bpftune is running, bpfrag
yields those sysctls by default (`--bpftune auto`):

| Sysctl | Owner while bpftune runs |
|---|---|
| `rmem_max`, `rmem_default`, `netdev_max_backlog`, `netdev_budget`, `netdev_budget_usecs` | bpftune: it sizes these from observed drops rather than a fixed profile |
| `busy_read`, `busy_poll`, `wmem_*`, `udp_early_demux`, NIC coalescing, DSCP, writeback | bpfrag: bpftune doesn't touch them |

In that pairing bpftune looks after capacity and bpfrag looks after latency
during matches. `bpfrag --check` shows exactly what's being yielded. Use
`--bpftune yield` to always yield, or `--bpftune ignore` to write them
anyway, which will switch off bpftune's tuners. If you're running a bpftune
build that includes the old gaming tuner patch, disable one of the two.

**gamemode** is complementary. It handles the CPU governor, GPU performance
level, niceness and ioprio, while bpfrag does the network side. They pair
well.

**tuned** profiles like network-latency set `busy_read` and `busy_poll` too.
That's fine because of the general rule below.

**General rule.** On restore, if a value no longer holds what bpfrag wrote,
someone else changed it during the match, and bpfrag leaves it alone and logs
that.

## Safety

- Every original value goes into a journal at `/run/bpfrag/journal.json`
  **before** the knob is changed. If the journal can't be written, the knob
  isn't changed. Restores run newest-first.
- If the daemon is killed or crashes, `ExecStopPost=bpfrag --restore` in the
  systemd unit puts everything back, and the next start replays any leftover
  journal. `/run` is tmpfs, so a reboot clears the journal along with the
  settings it describes.
- The DSCP marker and the arrival meter are **tcx links**, so they detach
  by themselves if the process dies. They hand every packet on to whatever
  else is on the interface: other tcx programs, classic tc filters (such as
  a desktop CAKE setup's redirect to its IFB) and the qdisc.
- `--dry-run` logs every intended change without making any of them. A lock
  file stops two instances from fighting over the same knobs.

## Install

Every [release](https://github.com/shanefagan/bpfrag/releases) has a `.deb`
(Debian 12+, Ubuntu 22.04+), an `.rpm` (current Fedora) and a binary tarball
that runs on any x86-64 distro with glibc 2.35 or newer, all on kernel 6.6
or newer.

The packages enable and start the service when first installed. It does
nothing until a game's match is detected. To see what this machine supports
and follow what bpfrag does:

```sh
sudo bpfrag --check && sudo bpfrag --selftest
journalctl -u bpfrag -f
```

With the binary tarball, copy the files into place and run
`sudo systemctl enable --now bpfrag` yourself.

Building it yourself needs Rust 1.85 or newer, clang, libclang (for
bindgen), libelf and zlib.

**Arch, CachyOS, EndeavourOS.** Build a package from the checkout. It builds
whatever is committed:

```sh
cd packaging/arch && makepkg -si
```

makepkg compiles with the flags in `/etc/makepkg.conf`. CachyOS sets those
for the build machine's CPU (AVX-512 on Zen 4, for example), so a package
built there crashes with SIGILL on older CPUs. To build one to share, use
portable flags:

```sh
RUSTFLAGS="-C target-cpu=x86-64-v2" CFLAGS="-O2 -march=x86-64-v2 -mtune=generic" makepkg -f
```

**Debian 12+, Ubuntu 22.04+.** Build a `.deb` with
[cargo-deb](https://github.com/kornelski/cargo-deb). Debian 13's own cargo
is new enough; on older releases and Ubuntu, use [rustup](https://rustup.rs).
The package needs the glibc it was built against or newer, so build on the
oldest release you'll install it on.

```sh
sudo apt install clang libclang-dev libelf-dev zlib1g-dev pkg-config make
cargo install cargo-deb --locked
make deb
sudo apt install ./target/debian/bpfrag_*.deb
```

**Fedora, Nobara.** `make rpm` packs the committed tree and its
vendored crates into source tarballs, then runs `rpmbuild` on
`packaging/rpm/bpfrag.spec`, which builds offline. `make srpm` stops at the
`.src.rpm`, which COPR or mock can build. On Bazzite and other image-based
Fedoras, build in a toolbox and layer the RPM with `rpm-ostree install`.

```sh
sudo dnf install rpm-build git && sudo dnf builddep packaging/rpm/bpfrag.spec
make rpm
sudo dnf install ./target/rpm/RPMS/*/bpfrag-[0-9]*.rpm
```

On removal, every package stops the service while `/usr/bin/bpfrag` is
still installed, so any settings changed mid-match are restored first.
Edits to `/etc/default/bpfrag` and `/etc/bpfrag/bpfrag.toml` survive
upgrades.

**Anything else.** Unpack the release tarball (binary, systemd unit, man
page, example config), or install the build dependencies and use the
Makefile:

```sh
make
sudo make install
sudo systemctl daemon-reload
```

The BPF object needs no vmlinux.h or bpftool at build time.
`src/bpf/vmlinux_lite.h` declares only the kernel fields used, and CO-RE
relocates them against your running kernel when the object loads.

### Checking it on your hardware

After your first real match:

- `journalctl -u bpfrag` should show `Match detected` and then `Match ended
  ... settings restored`.
- `ethtool -c <nic>` should show the original coalescing values again.
- `sysctl net.core.busy_poll` should be back at its old value.

If a restore ever fails, `sudo bpfrag --restore` replays the journal.

## Usage

```
sudo bpfrag                         run (what the service does)
sudo bpfrag --dry-run -v            detect and log, change nothing
bpfrag --monitor 1                  live view of the running instance
sudo bpfrag --check                 capabilities + bpftune/sched_ext/gamemode status
sudo bpfrag --selftest              run test packets through the tc programs on this kernel
bpfrag --waybar                     one JSON line for a status bar
sudo bpfrag --classify <PID>        would this process count as a game, and why
bpfrag --dump-config                effective config, in the TOML file's format
sudo bpfrag --restore               undo a crashed instance's changes

sudo bpfrag --tier competitive      same profile for every match
sudo bpfrag --dscp EF --iface wlan0 mark EF on wlan0 only
sudo bpfrag --allow 'Moonlight'     treat a process as a game
sudo bpfrag --stats 60              stats line in the log every minute
```

### Waybar

`bpfrag --waybar` prints one line of JSON and doesn't need root. Outside a
match the text is empty, so the module hides itself. The tooltip shows the
game, why it counts as a game, every applied setting and the last match.

```jsonc
"custom/bpfrag": {
    "exec": "bpfrag --waybar",
    "return-type": "json",
    "interval": 2,
    "format": "{}"
}
```

`alt` and `class` are `off`, `idle`, `casual`, `competitive` or `intense`, for
`format-icons` or CSS.

For the service, put flags in `/etc/default/bpfrag` as `BPFRAG_FLAGS="..."`.
Tiers, classifier lists and detector thresholds go in
`/etc/bpfrag/bpfrag.toml`; see `dist/bpfrag.toml` for an annotated example.

## Requirements

- **Kernel 6.6 or newer with BTF** (`/sys/kernel/btf/vmlinux`): UDP is
  counted with the `sock_send_length` and `sock_recv_length` tracepoints
  (6.4), and the tc programs attach as tcx links (6.6). `--check` tells
  you whether this machine qualifies.
- **Root.** Under the hood it uses `CAP_BPF`, `CAP_PERFMON` and
  `CAP_NET_ADMIN`, plus `CAP_SYS_PTRACE` to read a game's
  `/proc/<pid>/environ` when the game runs as your user. The systemd unit
  trims the daemon's capability bounding set to what it needs.

## Reporting a problem

Open an [issue](https://github.com/shanefagan/bpfrag/issues/new/choose) and
attach a report:

```sh
sudo bpfrag --report > bpfrag-report.md
```

It collects the version, OS and kernel, `--check`, `--selftest`,
`--monitor`, the effective configuration, the service state, the restore
journal and this boot's log. The hostname, user names in home paths, and
IP and MAC addresses are replaced, but read it through before posting.

## Documentation

- [docs/knobs.md](docs/knobs.md): why each setting, with sources, and what to expect
- [docs/measuring.md](docs/measuring.md): how to measure whether it helps
- [docs/distros.md](docs/distros.md): distribution defaults, and what that leaves bpfrag to do
- [docs/experiments.md](docs/experiments.md): experiments and checks worth running, and what each needs
- [docs/findings.md](docs/findings.md): results, open questions, bugs found, overhead
- [docs/detection.md](docs/detection.md): how matches, tiers, interfaces and bulk transfers are detected
- [docs/development.md](docs/development.md): code layout, tests, releases
- `man bpfrag`, and `dist/bpfrag.toml` for every configuration option

## Lineage

bpfrag grew out of Shane's gaming-tuner patches for bpftune. It shares no
code with bpftune and doesn't link its library.

Carried over from those patches:

- the detection idea and thresholds: 25/70/140 pkt/s, a margin of 15, and
  8-window smoothing;
- the variance gate, the tier hysteresis, and the asymmetric confidence and
  dwell for tier changes;
- "never drop to CASUAL mid-match";
- the three profiles' network values;
- launcher-lineage trust and ethtool coalescing.

What's new:

- per-process attribution instead of one global counter, which is where the
  QUIC, torrent and Discord false positives came from;
- the classifier gate, now running in userspace with Steam app ids and allow
  and deny lists;
- an immediate revert when the game exits;
- DSCP marking;
- raise-only and lower-only knobs, and the don't-clobber restore rule;
- the crash journal;
- bpftune and sched_ext coexistence.

## License

MIT (see `LICENSE`). Copyright © 2025–2026 Shane Fagan.

The BPF sources in `src/bpf/` are dual-licensed `GPL-2.0-only OR MIT`, and the
object declares `"Dual MIT/GPL"` to the kernel. The kernel only lets
programs with a GPL-compatible license use GPL-only helpers such as
`bpf_probe_read_kernel()`, which CO-RE field reads rely on. You can still use
those files under MIT. The GPL text is in `LICENSE-GPL-2.0`.
