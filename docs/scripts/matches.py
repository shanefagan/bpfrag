#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One CSV row per match, from bpfrag's log.

Reads the journal (or a saved log on stdin) and prints a row for every
match: when, which game, whether bpfrag was tuning or only measuring
(--dry-run), the tiers, and the health line's numbers. See
docs/measuring.md.

    docs/scripts/matches.py --since 2026-11-01 --label wifi-ps-on > a.csv
    journalctl -u bpfrag -o short-iso | docs/scripts/matches.py -
    sudo bpfrag --dry-run 2>&1 | tee run.log; docs/scripts/matches.py - < run.log

Needs only the Python standard library.
"""
import argparse
import csv
import re
import subprocess
import sys

TIERS = ["CASUAL", "COMPETITIVE", "INTENSE"]
STAMP = re.compile(r"^(\d{4}-\d\d-\d\dT[\d:]+[+-]\d{4}|\d\d:\d\d:\d\d(?:\.\d+)?)")
STARTED = re.compile(r"bpfrag (\S+) started( in dry-run mode)?")
DETECTED = re.compile(r"Match detected: (.+?) \(pid \d+\) at ~(\d+) pkt/s .* -> (\w+) \[(.*)\]$")
RETIER = re.compile(r": traffic now ~\d+ pkt/s .*; (\w+) -> (\w+)$")
ENDED = re.compile(r"Match ended after (\S+) \((.*)\); settings restored")
GAPS = re.compile(
    r"packet gaps half (≤\d+|over \d+) ms, 99% (≤\d+|over \d+) ms, "
    r"longest (\d+) ms, (\d+) stalls? \(100 ms\+\)"
)
DROPS = re.compile(r"drops: (\d+) socket buffer, (\d+) backlog, (\d+) NIC")
SQUEEZE = re.compile(r"ran out of budget (\d+)x")
QUEUE = re.compile(r"arrives on ([^;]+)")
BULK = re.compile(r"bulk: (.*?)( marked \w+| \(not marked\))$")

FIELDS = [
    "label", "started", "game", "mode", "version", "start_tier", "peak_tier",
    "duration_s", "end_reason", "start_pps", "gap_p50_ms", "gap_p99_ms",
    "gap_longest_ms", "stalls", "socket_drops", "backlog_drops", "nic_drops",
    "squeezed", "rx_queue", "bulk", "bulk_marked", "reason",
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
            cur["socket_drops"], cur["backlog_drops"], cur["nic_drops"] = (
                d.groups() if d else (0, 0, 0)
            )
            q = SQUEEZE.search(line)
            cur["squeezed"] = q.group(1) if q else 0
            if q := QUEUE.search(line):
                cur["rx_queue"] = q.group(1).strip()
            if b := BULK.search(line):
                cur["bulk"] = b.group(1)
                cur["bulk_marked"] = b.group(2).replace(" marked ", "").strip(" ()")
            rows.append(cur)
            cur = None
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("log", nargs="?", help="'-' to read a log on stdin; default: the journal")
    ap.add_argument("--since", help="passed to journalctl --since")
    ap.add_argument("--until", help="passed to journalctl --until")
    ap.add_argument("--unit", default="bpfrag.service")
    ap.add_argument("--label", default="", help="a name for the condition under test")
    ap.add_argument("--no-header", action="store_true", help="for appending to a file")
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
    w = csv.DictWriter(sys.stdout, FIELDS, extrasaction="ignore")
    if not a.no_header:
        w.writeheader()
    for r in parse(lines, a.label):
        w.writerow(r)


if __name__ == "__main__":
    main()
