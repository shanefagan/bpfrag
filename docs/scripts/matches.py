#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One CSV row per match, from bpfrag's log.

Reads the journal (or a saved log on stdin) and prints a row for every
match: when, which game, whether bpfrag was tuning or only measuring
(--dry-run), the tiers, and the health line's numbers. See
docs/measuring.md.

    docs/scripts/matches.py --since 2026-11-01 --label wifi-ps-on > a.csv
    docs/scripts/matches.py --since 2026-11-01 --compare arm
    journalctl -u bpfrag -o short-iso | docs/scripts/matches.py -
    sudo bpfrag --dry-run 2>&1 | tee run.log; docs/scripts/matches.py - < run.log

Needs only the Python standard library.
"""
import argparse
import csv
import random
import re
import statistics
import subprocess
import sys

TIERS = ["CASUAL", "COMPETITIVE", "INTENSE"]
# short-iso journal, the default journal format ("Oct 28 10:02:38"), or the
# daemon's own stderr ("10:02:38")
STAMP = re.compile(
    r"^(\d{4}-\d\d-\d\dT[\d:]+[+-]\d{4}|[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d"
    r"|\d\d:\d\d:\d\d(?:\.\d+)?)"
)
STARTED = re.compile(r"bpfrag (\S+) started( in dry-run mode)?")
DETECTED = re.compile(r"Match detected: (.+?) \(pid \d+\) at ~(\d+) pkt/s .* -> (\w+) \[(.*)\]$")
RETIER = re.compile(r": traffic now ~\d+ pkt/s .*; (\w+) -> (\w+)$")
ENDED = re.compile(r"Match ended after (\S+) \((.*)\); settings restored")
GAPS = re.compile(
    r"packet gaps half (≤\d+|over \d+) ms, 99% (≤\d+|over \d+) ms, "
    r"longest (\d+) ms, (\d+) stalls? \(100 ms\+\)"
)
DROPS = re.compile(
    r"drops: (\d+) socket buffer(?: \((\d+) the game's\))?, (\d+) backlog, (\d+) NIC"
)
SQUEEZE = re.compile(r"ran out of budget (\d+)x")
QUEUE = re.compile(r"arrives on ([^;]+)")
BULK = re.compile(r"bulk: (.*?)( marked \w+| \(not marked\))(?:;|$)")
EXPERIMENT = re.compile(r"; experiment: (\S+) (on|off)\b")

FIELDS = [
    "label", "started", "game", "mode", "version", "start_tier", "peak_tier",
    "duration_s", "end_reason", "start_pps", "gap_p50_ms", "gap_p99_ms",
    "gap_longest_ms", "stalls", "socket_drops", "game_socket_drops", "backlog_drops",
    "nic_drops", "squeezed", "rx_queue", "bulk", "bulk_marked", "experiment", "arm", "reason",
]


def secs(d):
    """'1h02m03s', '37m37s', '45s' -> seconds."""
    total = 0
    for n, unit in re.findall(r"(\d+)([hms])", d):
        total += int(n) * {"h": 3600, "m": 60, "s": 1}[unit]
    return total


def ms(v):
    """'≤16' -> 16; 'over 63' -> 64 (the histogram's last bucket)."""
    return int(v[1:]) if v.startswith("≤") else int(v.split()[1]) + 1


def parse(lines, label):
    rows, mode, version, cur = [], "tuned", "", None
    for line in lines:
        line = line.rstrip("\n")
        stamp = STAMP.match(line)
        stamp = stamp.group(1) if stamp else ""
        if m := STARTED.search(line):
            version = m.group(1)
            mode = "dry-run" if m.group(2) else "tuned"
            cur = None
        elif m := DETECTED.search(line):
            cur = {
                "label": label, "started": stamp, "game": m.group(1),
                "mode": mode, "version": version, "start_tier": m.group(3),
                "peak_tier": m.group(3), "start_pps": m.group(2),
                "reason": m.group(4),
            }
        elif cur and (m := RETIER.search(line)):
            if m.group(2) in TIERS and TIERS.index(m.group(2)) > TIERS.index(cur["peak_tier"]):
                cur["peak_tier"] = m.group(2)
        elif cur and (m := ENDED.search(line)):
            cur["duration_s"] = secs(m.group(1))
            cur["end_reason"] = m.group(2)
        elif cur and "end_reason" in cur and line.find(f"{cur['game']}: packet gaps") >= 0:
            if m := GAPS.search(line):
                cur["gap_p50_ms"], cur["gap_p99_ms"] = ms(m.group(1)), ms(m.group(2))
                cur["gap_longest_ms"], cur["stalls"] = m.group(3), m.group(4)
            d = DROPS.search(line)
            # game_socket_drops is blank before 0.3.1, or if bpfrag couldn't
            # read the game's sockets
            (cur["socket_drops"], cur["game_socket_drops"], cur["backlog_drops"],
             cur["nic_drops"]) = d.groups("") if d else (0, 0, 0, 0)
            q = SQUEEZE.search(line)
            cur["squeezed"] = q.group(1) if q else 0
            if q := QUEUE.search(line):
                cur["rx_queue"] = q.group(1).strip()
            if b := BULK.search(line):
                cur["bulk"] = b.group(1)
                cur["bulk_marked"] = b.group(2).replace(" marked ", "").strip(" ()")
            if e := EXPERIMENT.search(line):
                cur["experiment"], cur["arm"] = e.group(1), e.group(2)
            rows.append(cur)
            cur = None
    return rows


COMPARED = [
    ("gap_p99_ms", "99% gap ms"),
    ("gap_longest_ms", "longest ms"),
    ("stalls", "stalls"),
    ("game_socket_drops", "game drops"),
]


def num(r, k):
    try:
        return float(r[k])
    except (KeyError, TypeError, ValueError):
        return None


def permutation_p(a, b, rounds=20000, seed=1):
    """Two-sided p-value for the difference in medians: how often a random
    split of the same matches differs at least as much. Small samples and
    ties make it rough; treat p < 0.05 with 10+ matches a side as a lead,
    not proof."""
    observed = abs(statistics.median(a) - statistics.median(b))
    pool, n, rng, hits = a + b, len(a), random.Random(seed), 0
    for _ in range(rounds):
        rng.shuffle(pool)
        if abs(statistics.median(pool[:n]) - statistics.median(pool[n:])) >= observed:
            hits += 1
    return (hits + 1) / (rounds + 1)


def compare(rows, field, min_minutes):
    """Medians per group (an experiment arm, a label, tuned vs dry-run)."""
    rows = [r for r in rows if num(r, "duration_s") and num(r, "duration_s") >= min_minutes * 60
            and r.get("gap_p99_ms") not in (None, "")]
    groups = {}
    for r in rows:
        groups.setdefault(r.get(field) or "(none)", []).append(r)
    if not groups:
        print(f"no matches of {min_minutes} minutes or more with packet gaps measured")
        return
    names = sorted(groups)
    print(f"{field:<14} {'matches':>7}  " + "  ".join(f"{t:>12}" for _, t in COMPARED))
    for g in names:
        cells = []
        for k, _ in COMPARED:
            v = [x for x in (num(r, k) for r in groups[g]) if x is not None]
            cells.append(f"{statistics.median(v):>12g}" if v else f"{'-':>12}")
        print(f"{g:<14} {len(groups[g]):>7}  " + "  ".join(cells))
    if len(names) == 2:
        print()
        for k, title in COMPARED:
            a = [x for x in (num(r, k) for r in groups[names[0]]) if x is not None]
            b = [x for x in (num(r, k) for r in groups[names[1]]) if x is not None]
            if len(a) >= 3 and len(b) >= 3:
                print(f"{title}: p = {permutation_p(a, b):.3f} (difference in medians)")
            else:
                print(f"{title}: too few matches to test (3+ a side)")
        print("\nMatches of every arm should come from the same period, line and game.")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("log", nargs="?", help="'-' to read a log on stdin; default: the journal")
    ap.add_argument("--since", help="passed to journalctl --since")
    ap.add_argument("--until", help="passed to journalctl --until")
    ap.add_argument("--unit", default="bpfrag.service")
    ap.add_argument("--label", default="", help="a name for the condition under test")
    ap.add_argument("--no-header", action="store_true", help="for appending to a file")
    ap.add_argument("--compare", metavar="COLUMN",
                    help="print medians per value of COLUMN (arm, label, mode) instead of CSV")
    ap.add_argument("--min-minutes", type=float, default=5,
                    help="with --compare, skip matches shorter than this (default 5)")
    a = ap.parse_args()
    if a.log == "-":
        lines = sys.stdin
    elif a.log:
        lines = open(a.log, encoding="utf-8", errors="replace")
    else:
        cmd = ["journalctl", "-u", a.unit, "-o", "short-iso", "--no-pager"]
        if a.since:
            cmd += ["--since", a.since]
        if a.until:
            cmd += ["--until", a.until]
        lines = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.splitlines()
    if a.compare:
        compare(parse(lines, a.label), a.compare, a.min_minutes)
        return
    w = csv.DictWriter(sys.stdout, FIELDS, extrasaction="ignore")
    if not a.no_header:
        w.writeheader()
    for r in parse(lines, a.label):
        w.writerow(r)


if __name__ == "__main__":
    main()
