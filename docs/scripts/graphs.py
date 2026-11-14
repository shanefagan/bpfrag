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
- onoff.svg: bpfrag tuning against changing nothing, the share of seconds
  of play with a gap over 40, 60 and 100 ms. "Nothing changed" is the
  off arm of `[experiment] setting = "all"`, or a --dry-run; "tuning" is
  a match with nothing switched off. Matches with one setting off are
  left out. Drawn only with matches on both sides; the "all" experiment
  is the fair test (picked at random per match, so the server, the time
  of day and the relay even out).

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
import random
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

# "# bpfrag 0.16.3 (dry run); Deadlock (pid 1) [Steam app 1422450]; experiment: writeback off"
HEADER = re.compile(
    r"^# bpfrag (\S+)( \(dry run\))?; (.+?) \(pid (\d+)\)(?: \[.*?\])?"
    r"(?:; experiment: (?:none|(.+?) (on|off)))?$"
)

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
        self.version, dry, self.game, _, self.setting, self.arm = m.groups()
        self.dry_run = dry is not None
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

    def tuned(self):
        """True if bpfrag tuned everything it would, False if it changed
        nothing (a dry run, or the "all" experiment's off arm), None if
        an experiment switched one setting off."""
        if self.dry_run or (self.setting == "all" and self.arm == "off"):
            return False
        if self.arm in (None, "on"):
            return True
        return None

    def play_seconds_over(self, ms):
        """Seconds of play, and how many had a gap longer than `ms`."""
        return len(self.play), sum(1 for i in self.play if (self.longest[i] or 0) > ms)

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
        text(
            left,
            66,
            f"Good looks like flat lines: updates steady at the server's rate, gaps near "
            f"{1000 / m.rate:.0f} ms. Lower gaps are better."
            if m.rate
            else "Lower gaps are better.",
        ),
    ]
    panels = [
        ("Updates a second from the server", 108, 130, lambda i: m.updates[i], False, (0, None)),
        (
            "Longest gap in each second, ms (log scale; lower is better)",
            286,
            130,
            lambda i: m.longest[i],
            True,
            (10, 2000),
        ),
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
    base = 286 + 130
    for v in (v for v in nice_ticks(0, tmax / 60, 8) if v * 60 <= tmax):
        xx = x(v * 60)
        body.append(text(xx, base + 18, f"{fmt(v)} min", "muted", "middle"))
    # selective labels on the top panel
    top, h = 108, 130
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
    top, row = 122, 16
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
        text(24, 84, "Fewer dots between the shaded parts is better: those are the gaps you feel in play."),
        f'<circle class="s1fill dotring" cx="{left + 6}" cy="104" r="4"/>',
        text(left + 16, 108, f"{LONG_MS}–99 ms", "ink2"),
        f'<circle class="s2fill dotring" cx="{left + 96}" cy="104" r="5"/>',
        text(left + 106, 108, "a stall, 100 ms or more", "ink2"),
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


def pct(v):
    """A share as two significant figures: 0.14%, 4.9%, 12%; 0% for none."""
    return "0%" if v == 0 else f"{v:.2g}%"


ONOFF_MS = (40, 60, 100)  # 40: past the 32 ms gaps while dead


def onoff_svg(matches):
    """bpfrag tuning against changing nothing: the share of seconds of
    play with a gap longer than each of ONOFF_MS. None without matches on
    both sides."""
    usable = [m for m in matches if m.minutes >= MIN_MINUTES and m.play]
    sides = {True: [m for m in usable if m.tuned() is True], False: [m for m in usable if m.tuned() is False]}
    if not sides[True] or not sides[False]:
        return None, sides
    share, over, secs = {}, {}, {}
    for side, ms in sides.items():
        secs[side] = sum(m.play_seconds_over(0)[0] for m in ms)
        over[side] = [sum(m.play_seconds_over(t)[1] for m in ms) for t in ONOFF_MS]
        share[side] = [100 * n / secs[side] for n in over[side]]
    chance = [shuffled(sides, t) for t in ONOFF_MS]
    random_off = sum(1 for m in sides[False] if m.setting == "all")
    how = (
        "picked at random per match (experiment all)"
        if random_off == len(sides[False]) and all(m.setting == "all" for m in sides[True])
        else "tuning against dry runs and the experiment's off arm"
    )
    W, left, right = 760, 64, 24
    pw = W - left - right
    top, h = 152, 220
    hi = max(max(v) for v in share.values()) or 1
    ticks = nice_ticks(0, hi, 4)
    y = lambda v: top + h - h * v / ticks[-1]
    title = "bpfrag on and off"
    body = [
        text(24, 28, title, "ink", size=15, weight=600),
        text(
            24,
            48,
            f"Seconds of play with a gap from the server longer than each length. {len(sides[True])} matches "
            f"tuned, {len(sides[False])} not;",
        ),
        text(24, 66, f"{how}. A stall is a gap of 100 ms or more."),
        text(
            24,
            84,
            "Lower is better. 1% is about 12 seconds of a 20-minute match. Under each: how often shuffling "
            "the matches gives",
        ),
        text(24, 102, "a difference this big. Under 5% is unlikely to be chance; above it, the two sides can't be told apart."),
        f'<rect class="s1fill" x="{left}" y="116" width="12" height="12" rx="2"/>',
        text(left + 18, 126, "bpfrag tuning", "ink2"),
        f'<rect class="s2fill" x="{left + 120}" y="116" width="12" height="12" rx="2"/>',
        text(left + 138, 126, "nothing changed", "ink2"),
    ]
    for v in ticks:
        body.append(f'<line class="grid" x1="{left}" x2="{left + pw}" y1="{y(v):.1f}" y2="{y(v):.1f}"/>')
        body.append(text(left - 8, y(v) + 4, f"{v:g}%", "muted", "end"))
    group = pw / len(ONOFF_MS)
    bw = 24
    for k, t in enumerate(ONOFF_MS):
        cx = left + group * (k + 0.5)
        for j, side in enumerate((True, False)):
            v = share[side][k]
            x0 = cx - bw - 1 if j == 0 else cx + 1  # a 2px gap between the pair
            top_y = y(v)
            hh = top + h - top_y
            cls = "s1fill" if side else "s2fill"
            if hh > 0:
                r = min(4, hh, bw / 2)
                body.append(
                    f'<path class="{cls}" d="M{x0:.1f},{top + h} v{-(hh - r):.1f} a{r},{r} 0 0 1 {r},{-r} '
                    f'h{bw - 2 * r} a{r},{r} 0 0 1 {r},{r} v{hh - r:.1f} z"/>'
                )
            # each pair's labels lean away from the gap between them
            lx, anchor = (x0 + bw, "end") if j == 0 else (x0, "start")
            label = f"{pct(v)} ({over[side][k]:,} s)" if over[side][k] else "0"
            body.append(text(lx, top_y - 6, label, "ink", anchor))
        label = f"over {t} ms" if t < STALL_MS else f"{t} ms or more (a stall)"
        body.append(text(cx, top + h + 18, label, "muted", "middle"))
        p = chance[k]
        verdict = "no difference" if p is None else f"by chance {p:.0%} of the time"
        body.append(text(cx, top + h + 36, verdict, "ink2", "middle"))
    body.append(f'<line class="axis" x1="{left}" x2="{left + pw}" y1="{top + h}" y2="{top + h}"/>')
    desc = "; ".join(
        f"over {t} ms: tuning {over[True][k]} of {secs[True]} s, nothing changed {over[False][k]} of "
        f"{secs[False]} s" + ("" if chance[k] is None else f", a difference this big by chance {chance[k]:.0%} of the time")
        for k, t in enumerate(ONOFF_MS)
    )
    return svg(W, top + h + 52, title, desc, body), sides


def shuffled(sides, ms, n=5000):
    """How often shuffling the matches between the two sides gives a
    difference in the share of seconds over `ms` at least as big as the
    real one; None if neither side had any."""
    rows = [(m.play_seconds_over(ms)[1], len(m.play)) for side in (True, False) for m in sides[side]]
    k = len(sides[True])
    if not any(o for o, _ in rows):
        return None

    def diff(rs):
        a, b = rs[:k], rs[k:]
        return abs(sum(o for o, _ in a) / sum(s for _, s in a) - sum(o for o, _ in b) / sum(s for _, s in b))

    real = diff(rows)
    rng = random.Random(1)
    hits = 0
    for _ in range(n):
        rng.shuffle(rows)
        hits += diff(rows) >= real - 1e-12
    return hits / n


def experiments_svg(matches):
    groups = {}
    for m in matches:
        if m.setting and m.minutes >= MIN_MINUTES and m.figures():
            groups.setdefault(m.setting, []).append(m)
    names = sorted(groups)
    W, left, gapx = 760, 150, 40
    pw = (W - left - 24 - gapx) // 2
    top, row = 104, 64
    metrics = [("longest", "Longest gap in play, ms (lower is better)"), ("jitter", "Jitter, µs (lower is better)")]
    body = [
        text(24, 28, "Each experiment, one dot per match", "ink", size=15, weight=600),
        text(24, 48, "Setting on or off, picked at random per match. Bars: each side's median. Further left is better."),
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
    o, sides = onoff_svg(matches)
    if o:
        with open(os.path.join(a.out, "onoff.svg"), "w") as f:
            f.write(o)
    else:
        print(
            f"onoff.svg not drawn: {len(sides[True])} tuned matches, {len(sides[False])} with nothing changed "
            "(needs both: [experiment] setting = \"all\", or --dry-run)",
            file=sys.stderr,
        )
    e, groups = experiments_svg(matches)
    with open(os.path.join(a.out, "experiments.svg"), "w") as f:
        f.write(e)

    w = csv.writer(sys.stdout)
    w.writerow(
        ["match", "game", "version", "dry_run", "setting", "arm", "minutes", "p99_ms", "longest_ms", "stalls", "jitter_us"]
    )
    for m in sorted(matches, key=lambda m: m.name):
        fg = m.figures() or {}
        w.writerow(
            [
                m.when,
                m.game,
                m.version,
                "yes" if m.dry_run else "",
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
    for side, name in ((True, "tuning"), (False, "nothing changed")):
        ms = sides[side]
        if ms:
            over = [100 * sum(m.play_seconds_over(t)[1] for m in ms) / sum(len(m.play) for m in ms) for t in ONOFF_MS]
            print(
                f"{name}: {len(ms)} matches, seconds of play over "
                + ", ".join(f"{t} ms {v:.2f}%" for t, v in zip(ONOFF_MS, over)),
                file=sys.stderr,
            )
    drawn = "match.svg, gaps.svg, experiments.svg" + (", onoff.svg" if o else "")
    print(f"wrote {drawn} to {a.out} (match.svg: {one.when})", file=sys.stderr)


if __name__ == "__main__":
    main()
