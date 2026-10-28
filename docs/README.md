# bpfrag documentation

The [README](../README.md) covers what bpfrag does and how to install and
use it. These pages go deeper.

- [knobs.md](knobs.md): every setting bpfrag changes, the kernel mechanism
  behind it (with sources: kernel documentation and source, RFCs), what to
  expect, when nothing will happen, and how sure we are.
- [measuring.md](measuring.md): how to tell whether a setting helps: what
  the health numbers mean, how to run a comparison that can be trusted, and
  `scripts/matches.py`, which turns the log into a CSV of matches.
- [distros.md](distros.md): what Ubuntu, CachyOS, Bazzite and the kernel
  ship by default, which of bpfrag's settings that leaves to do, and the
  sources.
- [experiments.md](experiments.md): the backlog of experiments and
  checks worth running, why, and what each needs.
- [findings.md](findings.md): results so far, open questions, bugs found,
  and overhead measurements.
- [detection.md](detection.md): how a match, its tier, its interfaces and
  bulk transfers are detected.
- [development.md](development.md): code layout, tests, overhead and
  releases. Rules for changing the code are in [AGENTS.md](../AGENTS.md).

The principle: every setting bpfrag changes should come with a mechanism,
a source for it, an expected effect, and a number that would show it. When
the data says a setting does nothing, it should go.
