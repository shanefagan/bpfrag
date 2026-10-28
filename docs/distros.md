# Distribution defaults

The same bpfrag tier changes different things on different machines,
because distributions ship different defaults. Some of bpfrag's settings
are already in place on one distribution and missing on another, and a
few things bpfrag doesn't touch (the kernel's tick rate, the default
queueing discipline, TCP congestion control) decide how much its
settings can do.

`sudo bpfrag --check` shows all of this for the machine it runs on:
each setting's value now and what each tier would set it to ("=" where
it already holds), then the kernel build, default qdisc, congestion
control and NetworkManager's Wi-Fi power save default. `--report`
includes it, so bug reports carry it too. **The table below is what the
distributions ship; `--check` is what a given machine actually has.**

Every cell comes from the distribution's own packages or build files,
read on 2026-10-28; sources are listed under the table. "Not checked"
means exactly that: send `bpfrag --check` output (or a source) to fill
it in.

## What bpfrag doesn't change

| | Kernel default | Ubuntu 24.04 | Ubuntu 26.04 | CachyOS | Bazzite |
|---|---|---|---|---|---|
| Timer frequency (`CONFIG_HZ`) | set at build time | 1000 [u1] | 1000 [u2] | 1000 [c2] | not checked |
| Preemption model | set at build time | voluntary, switchable [u1] | lazy, switchable [u2] | full [c2] | not checked |
| Default qdisc | `pfifo_fast` unless the build picks one | `fq_codel`, from procps [u3] | `fq_codel`, from procps [u4] | `fq_codel`, in the kernel build [c3] | not set by Bazzite |
| TCP congestion control | `cubic` | `cubic` [u1] | `cubic` [u2] | `cubic`; BBRv3 is a build option, off by default [c2] | `bbr`, sysctl [b1] |
| NetworkManager `wifi.powersave` | not set: the driver's default, which is on (`CFG80211_DEFAULT_PS=y`) | 3, on [u5] | 3, on [u6] | not set, so on | not set on desktops; 2, off, on the Deck image [b2] |

## What bpfrag changes

| | Kernel default | Ubuntu 24.04 | Ubuntu 26.04 | CachyOS | Bazzite |
|---|---|---|---|---|---|
| `net.core.rmem_max`, `wmem_max` | 4 MiB from Linux 6.18, 208 KiB before [k1] | 208 KiB (Linux 6.8) | 4 MiB (Linux 7.0) | 4 MiB (current kernels) | follows its kernel |
| `net.core.netdev_max_backlog` | 1000 | 1000 | 1000 | 4096 [c1] | 1000 |
| `vm.dirty_*` | ratio 20% / background 10% | kernel default | kernel default | 256 MiB / background 64 MiB [c1] | kernel default; Deck image 256 MiB / 128 MiB [b3] |
| Busy polling, `netdev_budget*`, `rmem_default` | 0, 300 packets / 2 jiffies, 208 KiB | kernel default | kernel default | kernel default | kernel default |

## What that means for bpfrag

- **Socket buffers do more on older kernels.** On Ubuntu 24.04's 6.8
  kernel (and its newer kernels up to 6.17), `rmem_max` is 208 KiB, so a game that asks
  for a bigger receive buffer gets capped; bpfrag's raise lifts that
  during a match. From 6.18 the cap is already 4 MiB. Whether any game
  needs more than 208 KiB is open (see [findings.md](findings.md)).
- **`netdev_budget_usecs` depends on the tick rate.** Its default is two
  jiffies: 2 ms at HZ=1000 (Ubuntu, CachyOS) but 8 ms at HZ=250, where
  bpfrag's 8000 µs changes nothing ([knobs.md](knobs.md#netdev_budget-and-netdev_budget_usecs)).
- **Wi-Fi power save is on almost everywhere,** by the driver or by
  NetworkManager. bpfrag turns it off for matches on every distribution
  here; it matters most where nothing else does (all but the Deck image).
- **The default qdisc is `fq_codel` everywhere checked.** It keeps the
  game's packets from waiting behind this machine's own uploads when the
  NIC is the bottleneck. bpfrag doesn't change it.
- **Bazzite uses BBR.** BBR builds smaller queues at the bottleneck than
  cubic, which protects a game from a download on the same line. That
  would make bulk demotion matter less there; untested.
- **CachyOS already raises `netdev_max_backlog`** past the kernel default
  (bpfrag still raises it further, to 5000), and its writeback limits are
  exactly bpfrag's (256 MiB, background 64 MiB), so on CachyOS bpfrag's
  writeback setting changes nothing.

## Not checked yet

Debian, Fedora, Arch, openSUSE, Pop!_OS, Nobara and SteamOS. Their
package servers weren't reachable when this was written. For SteamOS:
Bazzite's Deck image carries a file named `99-valve-wifi-backend.conf`
that turns Wi-Fi power save off, which suggests SteamOS does the same;
that is a guess until someone checks a SteamOS install.

## Sources

- [u1] Ubuntu 24.04 `linux-modules-6.8.0-147-generic` 6.8.0-147.147,
  `/boot/config-6.8.0-147-generic`: `CONFIG_HZ=1000`,
  `CONFIG_PREEMPT_VOLUNTARY=y`, `CONFIG_PREEMPT_DYNAMIC=y`,
  `CONFIG_DEFAULT_TCP_CONG="cubic"`, no `CONFIG_NET_SCH_DEFAULT`. HZ was
  raised from 250 for 24.04 ([kernel-team list, March 2024](https://lists.snapcraft.io/archives/kernel-team/2024-March/149407.html)).
- [u2] Ubuntu 26.04 `linux-modules-7.0.0-14-generic` 7.0.0-14.14:
  `CONFIG_HZ=1000`, `CONFIG_PREEMPT_LAZY=y`, `CONFIG_PREEMPT_DYNAMIC=y`,
  `CONFIG_DEFAULT_TCP_CONG="cubic"`.
- [u3] Ubuntu 24.04 `procps` 2:4.0.4-4ubuntu3.3,
  `/etc/sysctl.d/10-bufferbloat.conf`: `net.core.default_qdisc = fq_codel`.
  Ubuntu's `systemd` package doesn't ship upstream's `50-default.conf`,
  which sets the same thing.
- [u4] Ubuntu 26.04 `procps` 4.0.4-9ubuntu1,
  `/usr/lib/sysctl.d/55-bufferbloat.conf`: the same line.
- [u5] Ubuntu 24.04 `network-manager` 1.46.0-1ubuntu2.8,
  `/etc/NetworkManager/conf.d/default-wifi-powersave-on.conf`:
  `wifi.powersave = 3`.
- [u6] Ubuntu 26.04 `network-manager` 1.54.3-2ubuntu3: the same file and
  value.
- [k1] Linux `net/core/sock.c`: `sysctl_rmem_max` and `sysctl_wmem_max`
  are `SK_RMEM_MAX`/`SK_WMEM_MAX` (256 packets' worth, 208 KiB on x86-64)
  up to v6.17 and `4 << 20` from v6.18.
- [c1] [CachyOS-Settings](https://github.com/CachyOS/CachyOS-Settings)
  f79b237, `usr/lib/sysctl.d/70-cachyos-settings.conf`:
  `net.core.netdev_max_backlog = 4096`, `vm.dirty_bytes = 268435456`,
  `vm.dirty_background_bytes = 67108864`.
- [c2] [linux-cachyos](https://github.com/CachyOS/linux-cachyos) 523baf9,
  `linux-cachyos/PKGBUILD`: `_HZ_ticks` 1000, `_preempt` full,
  `_tcp_bbr3` no by default.
- [c3] linux-cachyos 523baf9, `linux-cachyos/config`:
  `CONFIG_DEFAULT_FQ_CODEL=y`, `CONFIG_CFG80211_DEFAULT_PS=y`.
- [b1] [Bazzite](https://github.com/ublue-os/bazzite) b00fd74,
  `system_files/desktop/shared/usr/lib/sysctl.d/75-networking.conf`:
  `net.ipv4.tcp_congestion_control=bbr` (the Deck image builds on the
  desktop one, so it has this too).
- [b2] Bazzite b00fd74,
  `system_files/deck/shared/etc/NetworkManager/conf.d/99-valve-wifi-backend.conf`:
  `wifi.powersave=2`.
- [b3] Bazzite b00fd74,
  `system_files/deck/shared/usr/lib/sysctl.d/65-memory.conf`:
  `vm.dirty_bytes=268435456`, `vm.dirty_background_bytes=134217728`.
- Upstream systemd's `sysctl.d/50-default.conf` sets
  `net.core.default_qdisc = fq_codel`; distributions that ship it get
  `fq_codel` from there.
