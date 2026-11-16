# Security policy

bpfrag runs as root, loads eBPF programs, changes kernel settings and
rewrites a field in packets. A flaw in it matters, and a report is welcome.

## Supported versions

The latest release. bpfrag is before 1.0 and moves quickly, so fixes go
into a new release and aren't backported.

## Reporting a vulnerability

Please don't open a public issue. Use GitHub's private reporting: on the
repository's **Security** tab, **Report a vulnerability**
([direct link](https://github.com/shanefagan/bpfrag/security/advisories/new)).
If that isn't possible, email <mail@shanefagan.com>.

Useful in a report: the bpfrag version (`bpfrag --version`), the
distribution and kernel, what an attacker needs to start with (a local
user, a process on the machine, a host on the network), and steps or a
proof of concept.

This is one person's project. Expect an answer within a week, and a fix
or a plan within a month for anything confirmed. You'll be credited in the
release notes unless you'd rather not be.

## What counts

- Anything that lets an unprivileged local user or process gain
  privileges, change settings, or read what it shouldn't through bpfrag:
  the D-Bus interface (meant to be read-only, with nothing hidden), the
  config and journal files, the run directory, the lock file.
- A packet, or another process's traffic, that makes the eBPF programs
  misbehave: marking or demoting traffic they shouldn't, corrupting a
  packet, or dropping one.
- Settings left changed after bpfrag stops or crashes, where `--restore`
  doesn't put them back.
- The systemd unit's sandboxing being weaker than it claims.
- `bpfrag --report` leaving an IP or MAC address, a hostname or a user
  name in its output. Reports get attached to public issues.

## What doesn't

- That bpfrag needs root, or the capabilities its unit lists: it can't
  load eBPF or write these settings without them.
- What root can do with bpfrag's config: whoever can edit
  `/etc/bpfrag/bpfrag.toml` already controls the machine.
- A setting not helping, or a game not being detected: those are ordinary
  issues.
