# AGENTS.md

Notes for AI coding agents (and people) working on bpfrag. README.md is
the user-facing documentation; this file covers how to change the code
without breaking its promises.

## What bpfrag is, and isn't

- A daemon that detects a competitive game's network traffic with eBPF,
  tunes networking for the length of the match, and puts every setting
  back afterwards.
- **Networking only**, plus dirty-page writeback. Never CPU scheduling,
  CPU frequency, IRQ affinity or anything else sched_ext schedulers or
  gamemode own. "Runs next to sched_ext" is a design promise.
- **No code from Oracle's bpftune.** bpfrag grew out of Shane's own
  gaming-tuner patches for bpftune (see README "Lineage"), but shares no
  code with bpftune and doesn't link its library. Don't copy from it.
- One game at a time.
- Licence: MIT. The BPF sources in `src/bpf/` are `GPL-2.0-only OR MIT`
  (the kernel needs a GPL-compatible licence string for GPL-only helpers).
  Keep the SPDX headers.

## Layout

See `docs/development.md` ("Layout"). In short: `main.rs` is the CLI,
`daemon.rs` the main loop, `src/bpf/` holds the BPF C plus its Rust side,
`detect/` decides when a match is on, `tune/` changes and restores settings (one file per
knob type), `net/` is plain OS interfaces with no policy, `health/`
measures each match, `config/` and `cli/` are what they say. The top
level mirrors the sched_ext Rust schedulers (`main.rs`, `bpf_skel.rs`,
`bpf_intf.rs`, `stats.rs`).

## Build and test

Needs Rust 1.85+, clang, libclang, libelf, libdbus, zlib. The BPF object
is built by `build.rs` (libbpf-cargo); `src/bpf/intf.h` is bindgen'd into
`bpf_intf.rs`.

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                                   # pure logic, no root
sudo ./target/release/bpfrag --selftest      # BPF on this kernel, changes nothing
sudo tests/rig/e2e.sh target/release/bpfrag  # real kernel, netns, fake game
sudo tests/rig/e2e.sh tests/rig/unit-caps.sh # same, with only the unit's capabilities
```

CI runs all of these, plus a Rust 1.85 build, the .deb (Ubuntu 22.04
container) and the .rpm (Fedora container).

## Rules that keep it safe

- **Journal first.** Every knob saves its original value to the journal
  (`tune/journal.rs`) before changing anything. If the journal can't be
  written, don't change the knob. New `Saved` fields need
  `#[serde(default)]` so older journals still load.
- **Restore leaves other people's changes alone.** On restore, if a value
  no longer holds what bpfrag wrote, someone else changed it: keep theirs.
  Each knob's `restore()` implements this.
- **Raise-only / lower-only.** Capacity sysctls only ever go up (`>=`
  values), writeback only ever tightens.
- **`--dry-run` changes nothing on the system.** Observing is fine (BPF
  counters, the arrival meter); writing a sysctl, coalescing,
  power save or attaching the DSCP marker is not.
- **Crash safety.** tc programs attach as tcx links (they die with the
  process); anything that would outlive bpfrag must be journalled so
  `--restore` can undo it.
- **Kernel 6.6+ only.** The socket tracepoints (6.4) and tcx (6.6) are
  required (`bpf::check_kernel`); there are no fallbacks for older
  kernels, so don't add classic tc filters or fexit/kprobe hooks.
- **Bulk demotion is narrow.** Only while a match is on, only with
  `bulk.enabled` and not in a dry run, and never on a packet that already
  carries a DSCP. The never list (streaming hosts, voice apps, VPN and
  overlay clients) exists because demoting those would demote the player.
- **bpftune coexistence.** Sysctls in `config::BPFTUNE_SYSCTLS` are left
  to bpftune while it runs (`tune/coexist.rs`). Writing them would make
  bpftune switch its own tuners off.

## BPF side

- Keep the kernel side dumb: count, report exits, mark, time arrivals.
  Every decision belongs in Rust where it can be unit tested.
- `src/bpf/vmlinux_lite.h` declares only the kernel fields used, with
  `preserve_access_index` (CO-RE). Add fields there rather than pulling
  in a full vmlinux.h.
- Shared structs and constants go in `src/bpf/intf.h` so both sides use
  one definition.
- Packet offsets in tc programs must stay constants the verifier can
  follow (that's why the L2 length is only ever 0 or 14).
- tc programs return `TCX_NEXT`, never `TC_ACT_OK`. For a tcx link,
  `TC_ACT_OK` means "accept and stop", which skips later tcx programs and
  every classic tc filter on the interface (a CAKE setup's IFB redirect,
  for one). `--selftest` and the e2e rig check this.
- Any change to a tc program gets a `--selftest` vector
  (`cli/selftest.rs`), which runs on the real kernel via
  BPF_PROG_TEST_RUN.

## Rust conventions

- **MSRV is 1.85** (Debian 13's rustc). No let-chains (`if let ... &&`,
  stable only in 1.88): use `Option::filter`, `is_some_and`, match guards
  or nested ifs. Clippy's `incompatible_msrv` catches newer std APIs, not
  newer syntax; the CI job on 1.85 catches both.
- Module headers are `//!` docs; `cargo doc` should build without
  warnings.
- Prefer enums to strings for anything with a fixed set of values (tiers,
  config modes, verdicts).
- Name things for what they do. In particular, don't use "Oracle" as a
  name (bpftune is Oracle's project and the two get confused).
- Log wording is plain and specific ("Match detected: ...", "settings
  restored"), no gamer slang. Expected, deliberate cases (deny-listed
  processes) log at debug, not info.

## Things tests enforce

- Every long CLI flag appears in `dist/bpfrag.8`: update the man page
  when adding or renaming one.
- The versions in `Cargo.toml`, `packaging/rpm/bpfrag.spec`,
  `packaging/debian/changelog` and the man page header agree. Use
  `packaging/bump-version.sh NEW "note"` to change them.
- `dist/bpfrag.toml` must load with every example uncommented.

## Packaging and releases

- .deb: `[package.metadata.deb]` in Cargo.toml plus `packaging/debian/`.
  .rpm: `packaging/rpm/bpfrag.spec`, built offline from a vendored-crates
  tarball by `packaging/rpm/build.sh`. Arch: `packaging/arch/PKGBUILD`.
- Releases: bump the version, commit, tag `vX.Y.Z`, push; CI builds and
  publishes the GitHub release (see `docs/development.md`, "Releasing").
- makepkg rewrites `pkgver` in the PKGBUILD on every build; don't commit
  that change on its own.
- Packages built on CachyOS carry its CPU-specific flags (AVX-512 on
  Zen 4) and crash on older CPUs; see README for portable flags.

## Commits

Small, focused commits with a message that says what changed and why.
Behaviour changes, refactors and dependency bumps go in separate commits.
An agent's commits end with a `Co-Authored-By:` trailer naming it; don't
add links to chat sessions (they're private, so dead links for everyone
else).

Commits on `main` are GPG-signed by Shane. An agent that can't sign as him
delivers its work as commits on a `claude/<topic>` branch in his checkout,
for him to bring in with `git cherry-pick -S main..claude/<topic>`. Don't
push unsigned commits to `main`, and don't force-push it.

## Documentation

- README.md is for users: what bpfrag does, install, use. Keep it short and
  link to `docs/` for depth.
- `docs/knobs.md` explains every setting bpfrag changes. A new setting, or
  a changed value, gets a section there: what changes, the kernel mechanism
  with a primary source (kernel documentation or source, or an RFC), what
  to expect, when nothing will happen, and the counter that would show it.
  Mark hypotheses as hypotheses.
- Measured results go in `docs/findings.md`, null results included.
- Distribution defaults go in `docs/distros.md`, each with the package or
  file it was read from. Don't fill a cell from memory.
- A new setting also gets an `[experiment]` name (`src/experiment.rs`),
  so it can be tested like the others.

## Bug reports

`--report` (`cli/report.rs`) is what users attach to issues. When you add
state that would help debug a problem (a new file under the run dir, a
new kind of setting), include it there. Anything that can identify the
machine or its network goes through `report::redact`.
