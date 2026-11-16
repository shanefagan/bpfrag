# Contributing

Thanks for looking. bpfrag is small and has one maintainer, so the most
useful things are, in order: data, bug reports, then code.

## Match data

Most of what bpfrag claims rests on one desktop, one wired line and a few
games ([docs/findings.md](docs/findings.md)). Results from other setups,
Wi-Fi above all, are worth more than most patches. The
[Share match data](https://github.com/shanefagan/bpfrag/issues/new/choose)
issue form says what to send, and [docs/measuring.md](docs/measuring.md)
how to collect it. "It made no difference" is a result, and gets recorded.

## Bugs

Open an [issue](https://github.com/shanefagan/bpfrag/issues/new/choose)
with a report attached:

```sh
sudo bpfrag --report > bpfrag-report.md
```

Addresses, the hostname and user names are replaced in it, but read it
through before posting. For a security problem, see
[SECURITY.md](SECURITY.md) and don't open a public issue.

## Code

Read [AGENTS.md](AGENTS.md) first: it's short, and it's the rules that
keep bpfrag safe to run (journal before changing, restore without
overwriting anyone else's change, `--dry-run` changes nothing).
[docs/development.md](docs/development.md) has the layout, the tests and
how to build packages.

Before a pull request:

```sh
just pre-commit   # fmt, clippy, docs, unit tests: no root
just selftest     # if the BPF programs changed (sudo)
just e2e          # if detection, tuning or restore changed (sudo)
```

CI runs the same recipes. The pull request template lists the rest.

What gets merged:

- **Networking only.** No CPU scheduling, frequency, IRQ affinity or
  anything else sched_ext schedulers and gamemode own.
- **Settings need evidence.** A new setting needs a mechanism with a
  primary source (kernel documentation or source, or an RFC), an expected
  effect, and a number that would show it, written up in
  [docs/knobs.md](docs/knobs.md). Several settings have been removed
  because they measured the same on and off; a new one has to clear that.
- **Per-game logic needs data.** A profile or rule for one game comes with
  timelines showing what that game does.
- **No code from Oracle's bpftune.** bpfrag shares none and can't take any.
- **A bug fix comes with a test that fails without it.**
- **Small commits** that say what changed and why. Behaviour changes,
  refactors and dependency bumps go in separate commits.
- **Plain wording** in logs and docs, no gamer slang.

Kernel 6.6 or newer and Rust 1.85 are the floors; see AGENTS.md for what
that rules out.

## AI-assisted changes

Much of bpfrag was written with an AI coding agent, and that's fine for
contributions too. You're responsible for what you submit: read it, run
it, and be able to explain it. An agent's commits end with a
`Co-Authored-By:` trailer naming it.

## Licence

bpfrag is MIT; the BPF sources in `src/bpf/` are `GPL-2.0-only OR MIT`.
By contributing you agree your work is under the same terms, and that
it's yours to give.

## Conduct

See the [code of conduct](CODE_OF_CONDUCT.md).
