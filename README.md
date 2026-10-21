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
20:14:02 INFO  counting UDP per process via socket tracepoints
20:14:02 INFO  bpfrag 0.1.0 started; waiting for game traffic
20:15:10 INFO  Match detected: Counter-Strike 2 (pid 6230) at ~128 pkt/s (tx 64, rx 64) -> COMPETITIVE [Steam app 730]
20:15:10 INFO  COMPETITIVE profile: net.core.busy_poll=50, net.core.busy_read=50, enp6s0 coalescing=10us, ..., dscp=CS4 on enp6s0
20:52:47 INFO  Match ended after 37m37s (game exited); settings restored
```

## How it works

```
 kernel (BPF)                                    userspace (Rust)
 ────────────                                    ────────────────
 raw_tp sock_send_length ─┐
 raw_tp sock_recv_length ─┴─► per-process UDP ─► detector, 1 s windows:
                              counters (per-CPU)   steady? two-way? small packets?
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
                                                 ... match over -> restore
```

The BPF side only counts packets, reports game exits and marks packets. Every
decision happens in Rust, where it can be unit tested and changed without
fighting the verifier.

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
| `net.ipv4.udp_mem` (raise-only, per field) | 64K/427K/8M pages | 100K/853K/16M | 200K/1.7M/32M |
| `net.ipv4.udp_early_demux` | 1 | 1 | 1 |
| `vm.dirty_bytes` / `dirty_background_bytes` (lower-only) | untouched | 256 / 64 MiB | 256 / 64 MiB |
| Wi-Fi power save (wireless interfaces) | untouched | off | off |

The network values are the three profiles from the original bpftune
gaming-tuner patches. "Raise-only" means bpfrag never shrinks something you
already sized larger, and "lower-only" means writeback is only ever
tightened. Everything is overridable per tier (see `dist/bpfrag.toml`).

How much each knob actually matters:

- **DSCP CS4** is RFC 4594's class for real-time interactive traffic, which
  covers gaming explicitly. On Wi-Fi it maps to the WMM video queue (RFC 8325),
  which gets shorter contention windows than best effort. This is the biggest
  win on a busy wireless network. Routers running cake with diffserv honour it
  too. ISPs usually strip it, which is harmless. If the game already marks its
  own packets, bpfrag leaves them alone unless you set `override = true`.
- **Wi-Fi power save** lets the radio doze between beacons. A steady 64-tick
  stream mostly keeps it awake, but lulls (between rounds, slow tick servers)
  let it doze, and waking it can add tens of milliseconds to the next packets.
  It's off for the match and back on afterwards.
- **Interrupt coalescing** at 0–10 µs removes up to tens of microseconds of
  receive jitter on wired NICs. Most Wi-Fi drivers don't support changing it,
  and bpfrag skips them quietly.
- **Writeback limits** stop a Steam download or shader-cache write from
  building up gigabytes of dirty pages that then flush in bursts mid-match.
  The values are the ones CachyOS ships, so on CachyOS this is a no-op.
- **Busy polling** trades a little CPU for a little receive latency, and only
  on drivers with NAPI busy-poll support.
- **Buffer and backlog headroom** prevents drops during bursts; it doesn't
  make anything faster. It's kept from the original profiles because drops
  hurt more than a few KiB of RAM.

## How a match is detected

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
the menus.

Rejections by the deny list (or `BPFRAG_GAME=0`) are only logged at debug
level (`-v`). A steady UDP process with no game signals at all is logged
once at info, since it may be a native game that needs `--allow`.

If you want to see the detector's view of your system, run
`sudo bpfrag --dry-run -v` and `bpfrag --monitor 1` in another terminal. The
monitor lists the busiest UDP processes, their rates and the verdict for each.

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
| `rmem_max`, `rmem_default`, `udp_mem`, `netdev_max_backlog`, `netdev_budget`, `netdev_budget_usecs` | bpftune: it sizes these from observed drops rather than a fixed profile |
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
- The DSCP marker is a **tcx link** on kernel 6.6+, so it detaches by itself
  if the process dies. On older kernels it falls back to a cls_bpf filter,
  which is journalled and removed by `--restore`.
- `--dry-run` logs every intended change without making any of them. A lock
  file stops two instances from fighting over the same knobs.

## Install

Building needs Rust 1.85 or newer, clang, libclang (for bindgen), libelf
and zlib. Every route below installs the service without enabling it, so
check the machine first:

```sh
sudo bpfrag --check && sudo bpfrag --selftest
sudo systemctl enable --now bpfrag
journalctl -u bpfrag -f
```

**Arch, CachyOS, EndeavourOS.** Build a package from the checkout. It builds
whatever is committed:

```sh
cd packaging/arch && makepkg -si
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

**Anything else.** Install the build dependencies and use the Makefile:

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
sudo bpfrag --selftest              run test packets through the DSCP marker on this kernel
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

- **Kernel ≥ 6.4 with BTF** (`/sys/kernel/btf/vmlinux`) for the primary
  hooks, the `sock_send_length` and `sock_recv_length` raw tracepoints.
  Fedora, Arch/CachyOS, Bazzite, Nobara, current SteamOS and Ubuntu 24.04
  all qualify.
- **Kernels 5.17–6.3** use a fallback on fexit of
  `udp{,v6}_{send,recv}msg`. It compiles, but it hasn't been tested on a real
  old kernel yet. Run `--check` to see which path you get.
- **DSCP marking** uses tcx on 6.6+, and legacy tc otherwise.
- **Root.** Under the hood it uses `CAP_BPF`, `CAP_PERFMON` and
  `CAP_NET_ADMIN`, plus `CAP_SYS_PTRACE` to read a game's
  `/proc/<pid>/environ` when the game runs as your user. The systemd unit
  trims the daemon's capability bounding set to what it needs.

## Overhead

The raw tracepoints fire on every socket send and receive. Anything that isn't
UDP returns after a single field read. Measured with `kernel.bpf_stats_enabled`
inside a cloud microVM, so expect less on bare metal:

- about 0.25 µs per UDP receive;
- about 0.4 µs per UDP send;
- about 0.5 µs per egress packet for the DSCP marker, which is only attached
  during a match.

Userspace wakes once a second.

## Layout

The structure follows the sched_ext Rust schedulers:

```
src/bpf/main.bpf.c       BPF programs
src/bpf/intf.h           shared C/Rust interface (bindgen -> bpf_intf.rs)
src/bpf/vmlinux_lite.h   minimal CO-RE kernel types
src/bpf_skel.rs          libbpf-cargo skeleton (BpfSkel)
src/main.rs              Opts + Tuner::init()/run(), the "Scheduler" of this project
src/detect.rs            windows, smoothing, tiers, hysteresis (pure, unit tested)
src/classify.rs          is-it-a-game rules
src/knobs.rs             journalled, reversible knobs
src/coexist.rs           bpftune / sched_ext / gamemode / tuned awareness
src/bpf.rs               hook selection, map access, tc attach
src/net.rs               interfaces + ethtool coalescing
src/egress.rs            which links the game uses, with hysteresis
src/wifi.rs              Wi-Fi power save over nl80211 (generic netlink, no deps)
src/stats.rs             Metrics, --stats, --monitor
src/selftest.rs          --selftest: BPF_PROG_TEST_RUN packet vectors
dist/                    systemd unit, man page, /etc/default file, example config
packaging/arch/          PKGBUILD (bpfrag-git) + install hook
packaging/debian/        changelog + postinst for cargo-deb ([package.metadata.deb])
packaging/rpm/           spec, build.sh (vendored, offline), rpmlintrc
tests/rig/e2e.sh         end-to-end test in a throwaway netns (root)
.github/workflows/ci.yml fmt, clippy, tests, --selftest and the e2e rig as root,
                         MSRV check, .deb and .rpm builds
```

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

## Testing

```sh
cargo test                     # detector, classifier, config, journal, netlink, packaging (42 tests)
sudo bpfrag --selftest         # BPF_PROG_TEST_RUN vectors through the DSCP marker (12 checks)
sudo tests/rig/e2e.sh          # real kernel: netns + fake Steam game + noise (33 checks)
```

`--selftest` loads the BPF object on your running kernel and pushes
hand-built IPv4 and IPv6 packets through the tc program. Nothing is attached
and no setting changes. It checks that:

- the DSCP or traffic class is rewritten;
- ECN bits and the IPv6 flow label survive;
- the IPv4 header checksum is still valid, including with IP options;
- non-game ports, fragments, and ports whose owner is no longer marked are
  left byte-for-byte untouched.

It's the quickest way to confirm the marker on a new kernel.

The end-to-end rig creates a throwaway network namespace with an echo
server. It then runs a fake Steam game alongside Discord-, Firefox- and
daemon-shaped noise, and checks:

- the noise is ignored, the game is detected and tiers follow its tick rate;
- the game's packets leave with `tos 0x80` (CS4) while everything else
  doesn't;
- every rewritten packet still has a valid IPv4 header checksum, the
  receiving kernel logs no checksum errors, and it echoes the packets back;
- an outside change made mid-match is respected;
- nothing is changed while the journal can't be written;
- a new default route mid-match is followed;
- per-interface settings move to the interface the game's packets actually use;
- the Waybar output is correct during and after a match;
- bpftune's sysctls are yielded while bpftune runs;
- `kill -9` followed by `--restore` puts everything back;
- `--dry-run` changes nothing.

In every case where bpfrag owns the change, the system ends byte-identical to
baseline.

## License

MIT (see `LICENSE`). Copyright © 2025–2026 Shane Fagan.

The BPF sources in `src/bpf/` are dual-licensed `GPL-2.0-only OR MIT`, and the
object declares `"Dual MIT/GPL"` to the kernel. The kernel only lets
programs with a GPL-compatible license use GPL-only helpers such as
`bpf_probe_read_kernel()`, which CO-RE field reads rely on. You can still use
those files under MIT. The GPL text is in `LICENSE-GPL-2.0`.
