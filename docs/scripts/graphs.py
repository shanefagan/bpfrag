#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Graphs of what bpfrag measured, from its match timelines.

Reads timeline CSVs (`[capture] timeline = true` writes one per match to
/run/bpfrag/captures) and draws three SVGs, light and dark:

- match.svg: one match second by second, the server's updates and the
  longest gap in each second (--match picks it; the longest match by
  default).
- gaps.svg: one row per match, a dot at every second with a gap of
  50 ms or more from the server, stalls (100 ms or more) marked: where
  in a match the gaps fall. The stalls by cause (the game starting, a
  relay change, the end screen, play) are printed.
- experiments.svg: each A/B experiment in the matches given, one dot per
  match, on against off: the longest gap in play and the jitter.

It also prints the numbers behind each graph, as the table to go with
it. Play is worked out as the daemon does (health/mod.rs): from a minute
in, loading and the end screen left out; the figures agree with the
health line to about a millisecond.

    docs/scripts/graphs.py --out docs/images /run/bpfrag/captures/*.csv
    docs/scripts/graphs.py --match 2026-11-13_13-13-13_Deadlock.csv *.csv

Needs only the Python standard library.
"""
import argparse
import csv
import html
import math
import os
import re
import statistics
import sys

# Matches shorter than this are left out of the comparisons, as in
# matches.py.
MIN_MINUTES = 5
SETTLE_S = 60  # health/mod.rs SETTLE
END_TRIM = 5  # readings before the last at the usual rate
LOADING_HOLD = 3
STALL_MS = 100

HEADER = re.compile(r"^# bpfrag (\S+); (.+?) \(pid (\d+)\)(?: \[.*?\])?(?:; experiment: (.+?) (on|off))?$")

# Colours: categorical slots 1 and 2 of the dataviz reference palette,
# validated for colour-blind separation in light and dark.
STYLE = """
<style>
  svg { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; font-size: 12px; }
  .surface { fill: #fcfcfb; }
  .ink { fill: #0b0b0b; }
  .ink2 { fill: #52514e; }
  .muted { fill: #898781; }
  .grid { stroke: #e1e0d9; stroke-width: 1; }
  .axis { stroke: #c3c2b7; stroke-width: 1; }
  .band { fill: #0b0b0b; fill-opacity: 0.05; }
  .s1 { stroke: #2a78d6; fill: none; stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }
  .s1fill { fill: #2a78d6; }
  .s2ring { fill: #fcfcfb; stroke: #eb6834; stroke-width: 2; }
  .s2fill { fill: #eb6834; }
  .dotring { stroke: #fcfcfb; stroke-width: 2; }
  .mark { stroke: #0b0b0b; stroke-width: 2; }
  .threshold { stroke: #898781; stroke-width: 1; }
  @media (prefers-color-scheme: dark) {
    .surface { fill: #1a1a19; }
    .ink { fill: #f0efec; }
    .ink2 { fill: #c3c2b7; }
    .grid { stroke: #2c2c2a; }
    .axis { stroke: #383835; }
    .band { fill: #f0efec; fill-opacity: 0.07; }
    .s1 { stroke: #3987e5; }
    .s1fill { fill: #3987e5; }
    .s2ring { fill: #1a1a19; stroke: #d95926; }
    .s2fill { fill: #d95926; }
    .dotring { stroke: #1a1a19; }
    .mark { stroke: #f0efec; }
  }
</style>
"""


def num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


class Match:
    """One timeline, with play worked out as the daemon does."""

    def __init__(self, path):
        self.path = path
        self.name = os.path.basename(path)
        with open(path, newline="") as f:
            first = f.readline().strip()
            self.rows = list(csv.DictReader(f))
        m = HEADER.match(first)
        if not m:
            raise ValueError(f"{path}: not a bpfrag timeline")
        self.version, self.game, _, self.setting, self.arm = m.groups()
        stamp = re.match(r"(\d{4}-\d\d-\d\d)_(\d\d)-(\d\d)", self.name)
        self.when = f"{stamp[1]} {stamp[2]}:{stamp[3]}" if stamp else self.name
        self.t = [num(r["t"]) or 0.0 for r in self.rows]
        self.minutes = (self.t[-1] if self.t else 0) / 60
        self.updates = [num(r["gaps"]) or 0 for r in self.rows]
        self.p50 = [num(r["gap_p50_ms"]) for r in self.rows]
        self.longest = [num(r["gap_max_ms"]) for r in self.rows]
        self.stalls = [int(num(r["stalls"]) or 0) for r in self.rows]
        self.jitter = [num(r["jitter_us"]) for r in self.rows]
        self.sent = [num(r["udp_tx_pps"]) or 0 for r in self.rows]
        self.tcp_rx = [num(r["tcp_rx_bytes_s"]) or 0 for r in self.rows]
        self.events = [r["events"] for r in self.rows]
        self._play()

    def _play(self):
        n = len(self.rows)
        play = [i for i in range(n) if self.t[i] >= SETTLE_S and self.updates[i] > 0]
        self.rate = statistics.median([self.updates[i] for i in play]) if play else 0
        self.interval = statistics.median([self.p50[i] for i in play if self.p50[i]]) if play else 0
        sent = statistics.median([self.sent[i] for i in play]) if play else 0
        self.state = set()  # readings of the game's state arriving
        loading = set()
        for i in range(n):
            if self.t[i] < SETTLE_S:
                continue
            p50 = self.p50[i] or 0
            state = self.updates[i] > self.rate and 0 < p50 * 2 < self.interval
            quiet = self.sent[i] * 4 < sent
            big_tcp = self.tcp_rx[i] >= 1_000_000 and not self.usual(i)
            if state:
                self.state.add(i)
                loading.add(i - 1)
            if state or quiet or big_tcp:
                loading.update(range(i, i + LOADING_HOLD + 1))
        self.loading = loading
        usual = [i for i in play if i not in loading and self.usual(i)]
        self.upto = usual[-1] - END_TRIM if usual else None
        self.play = [i for i in play if i not in loading and self.upto is not None and i <= self.upto]
        self.usual_play = [i for i in self.play if self.usual(i)]

    def usual(self, i):
        p50 = self.p50[i]
        return self.updates[i] * 2 >= self.rate and p50 is not None and p50 * 2 <= self.interval * 3

    def figures(self):
        """The health line's play figures: longest gap, stalls, jitter."""
        if not self.usual_play:
            return None
        w = [(self.updates[i], self.jitter[i]) for i in self.usual_play if self.jitter[i] is not None]
        return {
            "longest": max(self.longest[i] or 0 for i in self.play),
            "stalls": sum(self.stalls[i] for i in self.play),
            "jitter": sum(u * j for u, j in w) / sum(u for u, _ in w) if w else None,
            "p99": statistics.median(num(self.rows[i]["gap_p99_ms"]) for i in self.usual_play),
        }

    def stall_causes(self):
        """Each stall's reading, and when it happened."""
        changes = [i for i, e in enumerate(self.events) if "->" in e and "server" in e]
        first_state = min(self.state) if self.state else None
        out = []
        for i, s in enumerate(self.stalls):
            if not s:
                continue
            if self.upto is not None and i > self.upto + END_TRIM:
                cause = "end screen"
            elif any(c - 5 <= i <= c + 2 for c in changes):
                cause = "relay change"
            elif self.t[i] < SETTLE_S or i in self.loading or (first_state is not None and i <= first_state):
                cause = "game starting"
            elif self.upto is not None and i > self.upto:
                cause = "end screen"
            else:
                cause = "play"
            out.extend([cause] * s)
        return out


# --- drawing ---------------------------------------------------------------


def esc(s):
    return html.escape(str(s), quote=True)


def text(x, y, s, cls="ink2", anchor="start", size=None, weight=None):
    extra = f' font-size="{size}"' if size else ""
    extra += f' font-weight="{weight}"' if weight else ""
    return f'<text x="{x:.1f}" y="{y:.1f}" class="{cls}" text-anchor="{anchor}"{extra}>{esc(s)}</text>'


def svg(width, height, title, desc, body):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img">\n'
        f"<title>{esc(title)}</title>\n<desc>{esc(desc)}</desc>\n{STYLE}"
        f'<rect class="surface" width="{width}" height="{height}" rx="8"/>\n' + "\n".join(body) + "\n</svg>\n"
    )


def nice_ticks(lo, hi, n=5):
    """Round ticks from at or below `lo` to at or above `hi`."""
    span = hi - lo or 1
    step = 10 ** math.floor(math.log10(span / n))
    for m in (1, 2, 5, 10):
        if span / (step * m) <= n:
            step *= m
            break
    v = math.floor(lo / step + 1e-9) * step
    ticks = [round(v, 6)]
    while ticks[-1] < hi - 1e-9:
        v += step
        ticks.append(round(v, 6))
    return ticks


def fmt(v):
    return f"{v:,.0f}" if abs(v) >= 1 or v == 0 else f"{v:g}"


def match_svg(m):
    W, left, right = 760, 64, 24
    pw = W - left - right
    tmax = m.t[-1] or 1
    x = lambda t: left + pw * t / tmax
    body = [
        text(left, 28, f"One {m.game} match, second by second", "ink", size=15, weight=600),
        text(
            left,
            48,
            f"{m.when}, bpfrag {m.version}. Shaded: left out of the figures (the game starting, the end screen).",
        ),
    ]
    panels = [
        ("Updates a second from the server", 90, 130, lambda i: m.updates[i], False, (0, None)),
        ("Longest gap in each second, ms (log scale)", 268, 130, lambda i: m.longest[i], True, (10, 2000)),
    ]
    # shading: before play and after it
    first_play = m.play[0] if m.play else 0
    last_play = m.play[-1] if m.play else len(m.t) - 1
    shade = [(0, m.t[first_play])]
    shade += [(m.t[last_play], tmax)]
    # the game's state arriving after the first minute, if it did
    late = sorted(i for i in m.state)
    for top, label_y in ((90, 0), (268, 0)):
        pass
    for title, top, h, get, log, (lo, hi) in panels:
        vals = [get(i) for i in range(len(m.t)) if get(i) is not None]
        if not log:
            hi = max(200, max(vals) if vals else 1)
            ticks = nice_ticks(0, hi, 4)
            hi = ticks[-1]
            y = lambda v, top=top, h=h, hi=hi: top + h - h * v / hi
        else:
            ticks = [10, 20, 50, 100, 200, 500, 1000, 2000]
            y = lambda v, top=top, h=h: top + h - h * (math.log10(max(min(v, hi), lo)) - math.log10(lo)) / (
                math.log10(hi) - math.log10(lo)
            )
        body.append(text(left, top - 12, title, "ink"))
        for a, b in shade:
            if b > a:
                body.append(f'<rect class="band" x="{x(a):.1f}" y="{top}" width="{x(b) - x(a):.1f}" height="{h}"/>')
        for i in late:
            if m.t[i] >= SETTLE_S:
                body.append(f'<rect class="band" x="{x(m.t[i] - 1):.1f}" y="{top}" width="{x(4) - x(0):.1f}" height="{h}"/>')
        for v in ticks:
            yy = y(v)
            body.append(f'<line class="grid" x1="{left}" x2="{left + pw}" y1="{yy:.1f}" y2="{yy:.1f}"/>')
            body.append(text(left - 8, yy + 4, fmt(v), "muted", "end"))
        if log:
            yy = y(STALL_MS)
            body.append(f'<line class="threshold" x1="{left}" x2="{left + pw}" y1="{yy:.1f}" y2="{yy:.1f}"/>')
            body.append(text(left + pw - 4, yy - 5, "a stall: 100 ms or more", "muted", "end"))
        pts = []
        path = []
        for i in range(len(m.t)):
            v = get(i)
            if v is None or (not log and m.updates[i] == 0 and not pts):
                if pts:
                    path.append(pts)
                    pts = []
                continue
            pts.append(f"{x(m.t[i]):.1f},{y(v):.1f}")
        if pts:
            path.append(pts)
        for p in path:
            if len(p) > 1:
                body.append(f'<polyline class="s1" points="{" ".join(p)}"/>')
        body.append(f'<line class="axis" x1="{left}" x2="{left + pw}" y1="{top + h}" y2="{top + h}"/>')
    # time axis
    base = 268 + 130
    for v in nice_ticks(0, tmax / 60, 8):
        xx = x(v * 60)
        body.append(text(xx, base + 18, f"{fmt(v)} min", "muted", "middle"))
    # selective labels on the top panel
    top, h = 90, 130
    hi = nice_ticks(0, max(200, max(m.updates)), 4)[-1]
    ylab = lambda v: top + h - h * v / hi
    if m.play:
        mid = m.play[len(m.play) // 3]
        body.append(text(x(m.t[mid]), ylab(m.rate) - 8, f"play: {m.rate:.0f} a second", "ink2", "middle"))
    dead = [i for i in m.play if m.updates[i] and m.updates[i] * 2 < m.rate * 1.5 and m.updates[i] * 3 > m.rate]
    if dead:
        i = dead[len(dead) // 2]
        body.append(text(x(m.t[i]), ylab(m.updates[i]) + 18, "dead: half the rate", "ink2", "middle"))
    if m.state:
        i = max(m.state, key=lambda j: m.updates[j])
        body.append(text(x(m.t[i]) + 6, ylab(m.updates[i]) + 4, "the game's state arriving", "ink2"))
    body.append(text(x(tmax) - 2, top + 14, "end screen", "muted", "end"))
    f = m.figures() or {}
    desc = (
        f"{m.game} match at {m.when}: {m.rate:.0f} updates a second in play; longest gap in play "
        f"{f.get('longest', 0):.0f} ms, {f.get('stalls', 0)} stalls in play."
    )
    return svg(W, base + 32, f"One {m.game} match, second by second", desc, body)


CAUSES = ["game starting", "relay change", "end screen", "play"]
LONG_MS = 50  # three updates missed at 64 a second


def hitches_svg(matches):
    """One row per match: every second with a gap of LONG_MS or more."""
    ms = sorted(matches, key=lambda m: m.name)
    W, left, right = 760, 112, 24
    pw = W - left - right
    top, row = 104, 16
    tmax = max(m.t[-1] for m in ms) or 1
    ticks = nice_ticks(0, tmax / 60, 6)
    x = lambda t: left + pw * t / (ticks[-1] * 60)
    long_play = long_out = stalls = 0
    rows = []
    for k, m in enumerate(ms):
        yy = top + k * row + row / 2
        play = set(m.play)
        rows.append(text(left - 10, yy + 4, m.when, "muted", "end"))
        rows.append(f'<line class="grid" x1="{x(0):.1f}" x2="{x(m.t[-1]):.1f}" y1="{yy:.1f}" y2="{yy:.1f}"/>')
        if m.play:
            a, b = m.t[m.play[0]], m.t[m.play[-1]]
            for lo, hi in ((0, a), (b, m.t[-1])):
                if hi > lo:
                    rows.append(
                        f'<rect class="band" x="{x(lo):.1f}" y="{yy - 6:.1f}" width="{x(hi) - x(lo):.1f}" height="12" rx="2"/>'
                    )
        for i, v in enumerate(m.longest):
            if not v or v < LONG_MS:
                continue
            if i in play:
                long_play += 1
            else:
                long_out += 1
            if v >= STALL_MS:
                stalls += 1
                rows.append(f'<circle class="s2fill dotring" cx="{x(m.t[i]):.1f}" cy="{yy:.1f}" r="5"/>')
            else:
                rows.append(f'<circle class="s1fill dotring" cx="{x(m.t[i]):.1f}" cy="{yy:.1f}" r="4"/>')
    total = long_play + long_out
    ybot = top + len(ms) * row
    games = ", ".join(sorted({m.game for m in ms}))
    title = f"Where the long gaps fall, in {len(ms)} matches"
    body = [
        text(24, 28, title, "ink", size=15, weight=600),
        text(
            24,
            48,
            f"Every second with a gap of {LONG_MS} ms or more from the server ({games}): {total}, "
            f"{long_play} of them in play.",
        ),
        text(24, 66, "Shaded: the game starting and the end screen, left out of the match's figures."),
        f'<circle class="s1fill dotring" cx="{left + 6}" cy="86" r="4"/>',
        text(left + 16, 90, f"{LONG_MS}–99 ms", "ink2"),
        f'<circle class="s2fill dotring" cx="{left + 96}" cy="86" r="5"/>',
        text(left + 106, 90, "a stall, 100 ms or more", "ink2"),
    ]
    body += rows
    for v in ticks:
        body.append(text(x(v * 60), ybot + 16, f"{fmt(v)} min", "muted", "middle"))
    causes = {c: 0 for c in CAUSES}
    for m in ms:
        for c in m.stall_causes():
            causes[c] += 1
    desc = (
        f"{total} seconds with a gap of {LONG_MS} ms or more, {long_play} in play; "
        f"{stalls} of them stalls. Stalls by when: "
        + ", ".join(f"{c} {causes[c]}" for c in CAUSES)
    )
    return svg(W, ybot + 30, title, desc, body), causes


def experiments_svg(matches):
    groups = {}
    for m in matches:
        if m.setting and m.minutes >= MIN_MINUTES and m.figures():
            groups.setdefault(m.setting, []).append(m)
    names = sorted(groups)
    W, left, gapx = 760, 150, 40
    pw = (W - left - 24 - gapx) // 2
    top, row = 104, 64
    metrics = [("longest", "Longest gap in play, ms"), ("jitter", "Jitter, µs")]
    body = [
        text(24, 28, "Each experiment, one dot per match", "ink", size=15, weight=600),
        text(24, 48, "Setting on or off, picked at random per match. Bars: each side's median."),
    ]
    # legend
    body.append(f'<circle class="s1fill dotring" cx="{left + 6}" cy="66" r="5"/>')
    body.append(text(left + 16, 70, "on", "ink2"))
    body.append(f'<circle class="s2ring" cx="{left + 56}" cy="66" r="4"/>')
    body.append(text(left + 66, 70, "off", "ink2"))
    rows_out = []
    for k, (key, label) in enumerate(metrics):
        x0 = left + k * (pw + gapx)
        vals = [m.figures()[key] for n in names for m in groups[n] if m.figures()[key] is not None]
        if not vals:
            continue
        ticks = nice_ticks(min(vals), max(vals), 4)
        lo, hi = ticks[0], ticks[-1]
        if hi == lo:
            hi = lo + 1
        x = lambda v, x0=x0, lo=lo, hi=hi: x0 + pw * (v - lo) / (hi - lo)
        body.append(text(x0, top - 14, label, "ink"))
        ybot = top + len(names) * row
        for v in ticks:
            body.append(f'<line class="grid" x1="{x(v):.1f}" x2="{x(v):.1f}" y1="{top}" y2="{ybot}"/>')
            body.append(text(x(v), ybot + 16, fmt(v), "muted", "middle"))
        for r, n in enumerate(names):
            y0 = top + r * row
            for j, arm in enumerate(("on", "off")):
                yy = y0 + 18 + j * 24
                ms = [m for m in groups[n] if m.arm == arm]
                vs = sorted(m.figures()[key] for m in ms if m.figures()[key] is not None)
                for v in vs:
                    if arm == "on":
                        body.append(f'<circle class="s1fill dotring" cx="{x(v):.1f}" cy="{yy}" r="5"/>')
                    else:
                        body.append(f'<circle class="s2ring" cx="{x(v):.1f}" cy="{yy}" r="4"/>')
                if vs:
                    med = statistics.median(vs)
                    body.append(f'<line class="mark" x1="{x(med):.1f}" x2="{x(med):.1f}" y1="{yy - 9}" y2="{yy + 9}"/>')
                    if k == 0:
                        rows_out.append((n, arm, len(vs)))
                if k == 0:
                    body.append(text(left - 12, yy + 4, f"{arm} ({len(vs)})", "muted", "end"))
            if k == 0:
                body.append(text(24, y0 + 34, n, "ink"))
    height = top + len(names) * row + 30
    desc = "; ".join(
        f"{n}: "
        + ", ".join(
            f"{arm} {len([m for m in groups[n] if m.arm == arm])} matches, median longest gap "
            f"{statistics.median([m.figures()['longest'] for m in groups[n] if m.arm == arm] or [0]):.0f} ms"
            for arm in ("on", "off")
        )
        for n in names
    )
    return svg(W, height, "Each experiment, one dot per match", desc, body), groups


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("timelines", nargs="+", help="timeline CSVs")
    ap.add_argument("--out", default=".", help="directory for the SVGs (default: here)")
    ap.add_argument("--match", help="the timeline for match.svg (default: the longest)")
    a = ap.parse_args()
    matches = []
    for p in a.timelines:
        try:
            matches.append(Match(p))
        except (ValueError, KeyError) as e:
            print(f"skipped {p}: {e}", file=sys.stderr)
    if not matches:
        sys.exit("no timelines")
    os.makedirs(a.out, exist_ok=True)
    if a.match:
        one = next((m for m in matches if m.name.endswith(os.path.basename(a.match))), None) or Match(a.match)
    else:
        one = max(matches, key=lambda m: m.minutes)
    with open(os.path.join(a.out, "match.svg"), "w") as f:
        f.write(match_svg(one))
    s, counts = hitches_svg(matches)
    with open(os.path.join(a.out, "gaps.svg"), "w") as f:
        f.write(s)
    e, groups = experiments_svg(matches)
    with open(os.path.join(a.out, "experiments.svg"), "w") as f:
        f.write(e)

    w = csv.writer(sys.stdout)
    w.writerow(["match", "game", "version", "setting", "arm", "minutes", "p99_ms", "longest_ms", "stalls", "jitter_us"])
    for m in sorted(matches, key=lambda m: m.name):
        fg = m.figures() or {}
        w.writerow(
            [
                m.when,
                m.game,
                m.version,
                m.setting or "",
                m.arm or "",
                f"{m.minutes:.1f}",
                fg.get("p99", ""),
                fg.get("longest", ""),
                fg.get("stalls", ""),
                f"{fg['jitter']:.0f}" if fg.get("jitter") is not None else "",
            ]
        )
    print("\nstalls by cause: " + ", ".join(f"{c} {counts[c]}" for c in CAUSES), file=sys.stderr)
    for n, ms in sorted(groups.items()):
        for arm in ("on", "off"):
            side = [m.figures() for m in ms if m.arm == arm]
            if side:
                print(
                    f"{n} {arm}: {len(side)} matches, median longest {statistics.median(f['longest'] for f in side):.0f} ms,"
                    f" jitter {statistics.median(f['jitter'] for f in side if f['jitter']):.0f} µs",
                    file=sys.stderr,
                )
    print(f"wrote match.svg ({one.when}), gaps.svg, experiments.svg to {a.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
