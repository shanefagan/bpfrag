# Development

How the code is laid out, how it's tested and how releases are made.
AGENTS.md has the rules a change must keep.

## Layout

The top level follows the sched_ext Rust schedulers (`main.rs`,
`bpf_skel.rs`, `bpf_intf.rs`, `stats.rs`, BPF sources in `src/bpf/`); the
rest is grouped by job:

```
src/main.rs                  command line: options and the one-shot commands
src/daemon.rs                Tuner::init()/run(), the "Scheduler" of this project
src/bpf_skel.rs              libbpf-cargo skeleton (BpfSkel)
src/bpf_intf.rs              bindgen'd src/bpf/intf.h
src/stats.rs                 metrics, --stats, --monitor, --waybar
src/bus.rs                   the read-only D-Bus interface (docs/dbus.md)
src/health/mod.rs            per-match health: packet gaps, drop counters
src/health/counters.rs       the kernel drop counters it reads

src/bpf/main.bpf.c           BPF programs: per-process UDP counters, exit events, DSCP
                             marker, arrival meter
src/bpf/intf.h               structs and constants shared by C and Rust
src/bpf/vmlinux_lite.h       minimal CO-RE kernel types
src/bpf/mod.rs               kernel check, shared helpers
src/bpf/maps.rs              reading and writing the BPF maps
src/bpf/tc.rs                attaching the marker and the meter (tcx links)

src/detect/mod.rs            windows, smoothing, tiers, hysteresis (pure, unit tested)
src/detect/classify.rs       is-it-a-game rules
src/detect/egress.rs         which links the game uses, with hysteresis
src/detect/bulk.rs           which other processes move bulk data during a match

src/tune/mod.rs              Knobs: apply a profile, restore everything
src/tune/journal.rs          the restore journal and crash recovery
src/tune/sysctl.rs           \
src/tune/coalesce.rs          | one file per knob type, with its apply
src/tune/writeback.rs         | and restore rules
src/tune/wifi.rs             /
src/tune/coexist.rs          bpftune / sched_ext / gamemode / tuned awareness

src/net/mod.rs               interfaces and default routes
src/net/ethtool.rs           NIC interrupt coalescing (ethtool ioctl)
src/net/nl80211.rs           Wi-Fi power save
src/net/netdev.rs            which receive queue and IRQ a NAPI instance is
src/net/genl.rs              generic netlink for both, no deps

src/config/mod.rs            config file, command-line overrides, validation
src/config/builtin.rs        built-in lists and tier profiles
src/experiment.rs            A/B experiments: which setting a match goes without
src/cli/check.rs             --check
src/cli/selftest.rs          --selftest: BPF_PROG_TEST_RUN packet vectors
src/cli/report.rs            --report: diagnostics for a bug report, addresses removed

dist/                        systemd unit, man page, /etc/default file, example config
packaging/arch/              PKGBUILD (bpfrag-git) + install hook
packaging/debian/            changelog + postinst for cargo-deb ([package.metadata.deb])
packaging/rpm/               spec, build.sh (vendored, offline), rpmlintrc
packaging/release-files.md   what each release file is for (CI adds it to the release notes)
packaging/bump-version.sh    set a new version everywhere it is recorded (just bump)
justfile                     build, test, install, package and release recipes;
                             CI runs the same ones
tests/e2e/                   end-to-end tests in a throwaway netns (root, pytest):
                             rig.py is the network, the daemon and the fake game;
                             one test per behaviour; programs/ are the fake game,
                             the echo and bulk server and the pcap check
docs/                        why each setting, how to measure, findings, internals
docs/scripts/matches.py      the log as a CSV of matches
docs/scripts/graphs.py       graphs from match timelines (docs/images)
AGENTS.md                    notes for coding agents (CLAUDE.md imports it)
.github/workflows/ci.yml     the justfile's recipes: fmt, clippy, tests, --selftest and
                             the e2e rig as root, MSRV check, .deb/.rpm builds,
                             releases on tags
.github/ISSUE_TEMPLATE/      bug report (asks for --report) and feature request forms
.github/pull_request_template.md  testing and scope checklist
```


## Testing

The [justfile](../justfile) holds every build and test command, and CI
runs the same recipes, so a change that passes `just ci` passes CI's test
job. `just` alone lists them all.

```sh
just pre-commit    # cargo fmt --check, clippy -D warnings, unit tests: no root
just ci            # all of the below, as CI runs it
```

| Recipe | What | Root |
|---|---|---|
| `just fmt-check` | `cargo fmt --check` | |
| `just lint` | `cargo clippy --locked --all-targets -- -D warnings`, and `cargo doc` with warnings as errors | |
| `just test` | unit tests: detectors, classifier, config, journal, health, report, D-Bus, packaging (137) | |
| `just build` | `cargo build --locked --release` | |
| `just check-system` | `bpfrag --check`: what this machine and kernel support (never fails) | yes |
| `just selftest` | `bpfrag --selftest`: BPF_PROG_TEST_RUN vectors through both tc programs, then 2,000 random and damaged packets each way (32 checks) | yes |
| `just deny` | `cargo deny check` against `deny.toml`: RustSec advisories, permissive licences only, crates.io only (needs cargo-deny) | no |
| `just unit-security` | `systemd-analyze security` on `dist/bpfrag.service`: fails if its exposure rises above 5.1 | no |
| `just fuzz [packets] [seed]` | the selftest with 200,000 random packets; a failure prints the seed that repeats it | yes |
| `just e2e` | real kernel: netns, fake Steam game, noise, crash recovery, D-Bus (32 tests; needs `python3-pytest`) | yes |
| `just e2e-unit` | the same, with only the systemd unit's capabilities | yes |
| `just msrv` | `cargo +1.85 check` (the `rust-version` in Cargo.toml) | |

Recipes that need root use `sudo` unless they already run as root (a
container), and build the binary as you first, so `target/` stays yours.

`--selftest` loads the BPF object on your running kernel and pushes
hand-built IPv4 and IPv6 packets through the tc programs. Nothing is attached
and no setting changes. It checks that:

- the DSCP or traffic class is rewritten;
- ECN bits and the IPv6 flow label survive;
- the IPv4 header checksum is still valid, including with IP options;
- non-game ports, fragments, and ports whose owner is no longer marked are
  left byte-for-byte untouched;
- the arrival meter counts and times packets to the game's port, and
  nothing else;
- a bulk process's TCP and UDP flows are demoted to LE in both directions,
  over IPv4 and IPv6, unless the app or the sender marked them, while the
  game keeps its class;
- every program returns TCX_NEXT, so later tc filters still run.

It's the quickest way to confirm both programs on a new kernel.

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
- packet gaps on the game's flow are measured (about 16 ms at 64 pkt/s),
  logged when the match ends, and measured in `--dry-run` too;
- bpftune's sysctls are yielded while bpftune runs;
- `kill -9` followed by `--restore` puts everything back;
- classic tc filters redirecting through IFB devices (a desktop CAKE setup)
  keep seeing every packet during a match;
- a download during the match is bulk and leaves and arrives marked LE
  (arriving at the IFB, where CAKE sees it), an OBS upload isn't, marking
  stops once the download does, and the match summary says how much was
  demoted;
- `--dry-run` changes nothing, bulk traffic included;
- on a private bus with the shipped policy, another user can read the D-Bus
  properties but can't set them or take the name, the match signals
  arrive (including when bpfrag stops mid-match), and without a bus the
  daemon carries on.

In every case where bpfrag owns the change, the system ends byte-identical to
baseline.


## Overhead

The raw tracepoints fire on every socket send and receive. Anything that isn't
UDP returns after a couple of field reads, and so does TCP outside a match
(it's only counted while a match is on, for bulk detection). Measured with
`kernel.bpf_stats_enabled` inside a cloud microVM, so expect less on bare
metal:

- about 0.25 µs per UDP receive;
- about 0.4 µs per UDP send;
- about 0.5 µs per egress packet for the DSCP marker, which is only attached
  during a match;
- about 1.3 times the marker's cost per incoming packet for the arrival
  meter, also only during a match (measured side by side in the e2e rig);
- during a match, about 0.3–0.5 µs more per TCP send or receive, and while
  a bulk transfer is being demoted, a flow lookup per packet in the marker
  and the meter. A 20 Mbit/s download is about 2,000 packets a second:
  roughly a millisecond of CPU per second.

Userspace wakes once a second.


Side-by-side numbers for each release are in [findings.md](findings.md#overhead).

## Packages

```sh
just deb          # .deb in target/debian/ (needs cargo-deb); just deb-lint, just deb-smoke
just rpm          # .rpm and .src.rpm in target/rpm/; just srpm, just rpm-lint, just rpm-smoke
just tarball      # binary, unit, man page, configs and licences, for any glibc distro
```

`deb-smoke` and `rpm-smoke` install the package, run it and remove it, so
they're for a container or a VM; CI runs them in Ubuntu 22.04 and Fedora
containers.

Distributions don't need just: bpfrag builds with `cargo build --release`,
and `just install` (with `DESTDIR` and `PREFIX`, or `SYSCONFDIR`, `UNITDIR`
and `DBUSDIR`) is the list of files a package ships. `install` and
`uninstall` ask before they run; `just --yes install` doesn't.

The BPF object needs no vmlinux.h or bpftool at build time:
`src/bpf/vmlinux_lite.h` declares only the kernel fields used, and CO-RE
relocates them against the running kernel when the object loads.

Notes per distribution:

- **Debian, Ubuntu:** the build dependencies are `clang libclang-dev
  libelf-dev libdbus-1-dev zlib1g-dev pkg-config`. Debian 13's cargo is
  new enough; older releases need [rustup](https://rustup.rs). A .deb
  needs the glibc it was built against or newer, so build on the oldest
  release it's for.
- **Fedora:** `sudo dnf install rpm-build git && sudo dnf builddep
  packaging/rpm/bpfrag.spec`. `packaging/rpm/build.sh --srpm` stops at
  the `.src.rpm`, for COPR or mock.
- **Arch, CachyOS:** makepkg compiles with `/etc/makepkg.conf`'s flags,
  and CachyOS's are for the build machine's CPU (AVX-512 on Zen 4), so a
  package built there crashes with SIGILL on older CPUs. For one to share:
  `RUSTFLAGS="-C target-cpu=x86-64-v2" CFLAGS="-O2 -march=x86-64-v2
  -mtune=generic" makepkg -f`.


## Releasing

```sh
just bump 0.2.0 "One line about what changed"
git commit -am "Release 0.2.0"
git tag -a v0.2.0            # the tag message becomes the release notes
git push origin main v0.2.0
```

`just bump` runs `packaging/bump-version.sh`, which updates `Cargo.toml`,
`Cargo.lock`, the RPM spec, the Debian changelog and the man page; a unit
test fails if any of them disagree. For a `v*` tag, CI runs everything as
usual, checks the tag matches `Cargo.toml` (`just check-tag`), and
publishes a GitHub release. The tag's message becomes the
release notes, and the release carries the `.deb`, `.rpm`, `.src.rpm`, the
vendored-crates tarball the spec needs, the binary tarball and
`SHA256SUMS`.

To redo a tag, write the notes to a file and `git tag -s -f -F notes.md
v0.2.0`. Copying them out of the old tag with `--format='%(contents)'`
brings its signature along as text, and CI refuses a tag message with a
signature block in it.

