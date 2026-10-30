// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! A per-second record of one match, as CSV, with `[capture] timeline`:
//! for working out what a game's traffic does over a match. Where one game
//! ends and the next starts when the game never goes quiet in between, when
//! the server sends at half its usual rate, what the traffic looks like
//! around a stall: the end-of-match line can't show any of that.
//!
//! One file per match in `<state_dir>/captures`, named by its start time
//! and the game, with a `#` comment line on top (bpfrag version, game,
//! experiment arm) and then one row a second:
//!
//! | column | meaning |
//! |---|---|
//! | `t`, `unix` | seconds since the match started; the time |
//! | `tier` | the tier in effect |
//! | `udp_tx_pps`, `udp_rx_pps` | the game's UDP datagrams a second, every socket |
//! | `udp_tx_bytes_s`, `udp_rx_bytes_s` | the same in bytes |
//! | `tcp_tx_bytes_s`, `tcp_rx_bytes_s` | the game's own TCP |
//! | `server`, `server_pps` | who the game receives from ([`super::peers`]): a letter per address, and the port; its packets a second |
//! | `peers` | remote addresses and ports that sent anything this second |
//! | `port` | the game's local port that received the most this second |
//! | `gaps`, `gap_p50_ms`, `gap_p99_ms`, `gap_max_ms` | arrival gaps this second on the ports carrying the match (1 ms buckets; 64 is over 63 ms) |
//! | `stalls` | stalls the meter finished counting this second |
//! | `events` | match start and end, tier and server changes |
//!
//! Addresses aren't written, only letters, so a timeline can be shared.
//! Timelines live in the run directory (`/run/bpfrag`, in memory), so a
//! row a second costs no disk writes, and they go at reboot.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::{BUCKETS, Gaps};
use crate::bpf_intf;
use crate::detect::Sample;

const HEADER: &str = "t,unix,tier,udp_tx_pps,udp_rx_pps,udp_tx_bytes_s,udp_rx_bytes_s,\
tcp_tx_bytes_s,tcp_rx_bytes_s,server,server_pps,peers,port,gaps,gap_p50_ms,gap_p99_ms,\
gap_max_ms,stalls,events";

/// What one row reports, besides the time.
#[derive(Default)]
pub struct Row<'a> {
    pub tier: &'a str,
    /// The game's cumulative counters, if it's still running.
    pub sample: Option<&'a Sample>,
    /// The meter's per-port statistics (cumulative).
    pub ports: &'a [(u16, bpf_intf::port_rx)],
    /// The current server's label and packets a second.
    pub server: Option<(String, f64)>,
    pub peers: usize,
}

pub struct Timeline {
    out: BufWriter<File>,
    path: PathBuf,
    start: Instant,
    last: Instant,
    prev: Option<Sample>,
    /// Each port's packets, histogram and stall count at the last row.
    prev_ports: HashMap<u16, (u64, [u64; BUCKETS], u64)>,
    events: Vec<String>,
}

impl Timeline {
    /// Start a timeline in `dir` for a match by `game` that started at
    /// `unix`, keeping the newest `keep` files there.
    pub fn create(
        dir: &Path,
        keep: usize,
        unix: u64,
        game: &str,
        about: &str,
    ) -> io::Result<Timeline> {
        fs::create_dir_all(dir)?;
        let path = dir.join(file_name(unix, game));
        let mut out = BufWriter::new(File::create(&path)?);
        writeln!(out, "# {}", about.replace('\n', " "))?;
        writeln!(out, "{HEADER}")?;
        out.flush()?;
        prune(dir, keep);
        let now = Instant::now();
        Ok(Timeline {
            out,
            path,
            start: now,
            last: now,
            prev: None,
            prev_ports: HashMap::new(),
            events: Vec::new(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Note something that happened; it goes in the next row.
    pub fn event(&mut self, e: impl Into<String>) {
        self.events.push(e.into());
    }

    /// Write one row: rates since the last row.
    pub fn row(&mut self, r: &Row) -> io::Result<()> {
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64().max(0.001);
        self.last = now;
        let rate = |a: u64, b: u64| format!("{:.0}", a.saturating_sub(b) as f64 / dt);
        let rates = match (r.sample, self.prev.as_ref()) {
            (Some(s), Some(p)) => [
                rate(s.tx_pkts, p.tx_pkts),
                rate(s.rx_pkts, p.rx_pkts),
                rate(s.tx_bytes, p.tx_bytes),
                rate(s.rx_bytes, p.rx_bytes),
                rate(s.tcp_tx_bytes, p.tcp_tx_bytes),
                rate(s.tcp_rx_bytes, p.tcp_rx_bytes),
            ],
            _ => Default::default(),
        };
        if let Some(s) = r.sample {
            self.prev = Some(*s);
        }
        let gaps = self.gaps_since_last(r.ports);
        let (server, server_pps) = match &r.server {
            Some((label, pps)) => (label.clone(), format!("{pps:.0}")),
            None => (String::new(), String::new()),
        };
        let unix = crate::stats::now_unix();
        let events = std::mem::take(&mut self.events).join("; ");
        writeln!(
            self.out,
            "{:.1},{unix},{},{},{server},{server_pps},{},{},{}",
            now.duration_since(self.start).as_secs_f64(),
            r.tier,
            rates.join(","),
            r.peers,
            gaps,
            csv_field(&events),
        )?;
        self.out.flush()
    }

    /// The match is over.
    pub fn finish(mut self) -> io::Result<PathBuf> {
        self.out.flush()?;
        Ok(self.path)
    }

    /// "port,gaps,p50,p99,max,stalls" since the last row, over the ports
    /// that received at least a tenth of what the busiest did this second.
    fn gaps_since_last(&mut self, ports: &[(u16, bpf_intf::port_rx)]) -> String {
        let mut now = HashMap::with_capacity(ports.len());
        let mut deltas = Vec::with_capacity(ports.len());
        for (port, r) in ports {
            let g = Gaps::from_bpf(*port, r);
            let (pkts, hist, stalls) = match self.prev_ports.get(port) {
                // an entry the LRU map dropped and made again starts over
                Some(&(p, h, s)) if p <= g.pkts => (p, h, s),
                _ => (0, [0u64; BUCKETS], 0),
            };
            let mut d = [0u64; BUCKETS];
            for (x, (a, b)) in d.iter_mut().zip(g.hist.iter().zip(hist.iter())) {
                *x = a.saturating_sub(*b);
            }
            deltas.push((*port, g.pkts - pkts, d, g.stalls.saturating_sub(stalls)));
            now.insert(*port, (g.pkts, g.hist, g.stalls));
        }
        self.prev_ports = now;
        let Some(&(port, most, _, _)) = deltas.iter().max_by_key(|d| d.1).filter(|d| d.1 > 0)
        else {
            return ",0,,,,0".into();
        };
        let mut hist = [0u64; BUCKETS];
        let mut stalls = 0;
        for (_, _, d, s) in deltas.iter().filter(|d| d.1.saturating_mul(10) >= most) {
            for (h, x) in hist.iter_mut().zip(d.iter()) {
                *h += x;
            }
            stalls += s;
        }
        let this = Gaps {
            port,
            pkts: most,
            hist,
            max_gap_ns: 0,
            stalls,
            napi_id: 0,
        };
        let n: u64 = hist.iter().sum();
        let q = |v: Option<u32>| v.map(|x| x.to_string()).unwrap_or_default();
        let max = hist
            .iter()
            .rposition(|c| *c > 0)
            .map(|i| (i + 1).to_string())
            .unwrap_or_default();
        format!(
            "{port},{n},{},{},{max},{stalls}",
            q(this.quantile_ms(0.5)),
            q(this.quantile_ms(0.99))
        )
    }
}

/// "2026-10-29_19-28-31_Deadlock.csv": sorts by time.
fn file_name(unix: u64, game: &str) -> String {
    let mut name: String = game
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .take(40)
        .collect();
    if name.is_empty() {
        name = "game".into();
    }
    format!("{}_{name}.csv", crate::util::local_stamp(unix as i64))
}

/// Remove the oldest timelines beyond `keep`.
fn prune(dir: &Path, keep: usize) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "csv"))
        .collect();
    files.sort();
    let extra = files.len().saturating_sub(keep);
    for f in &files[..extra] {
        let _ = fs::remove_file(f);
    }
}

/// Quote a field if it needs it.
fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\"").replace('\n', " "))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bpfrag-timeline-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn port(pkts: u64, hist: &[(usize, u32)], stalls: u32) -> bpf_intf::port_rx {
        let mut r = bpf_intf::port_rx {
            pkts,
            stalls,
            ..Default::default()
        };
        for &(i, n) in hist {
            r.hist[i] = n;
        }
        r
    }

    #[test]
    fn rows_hold_per_second_rates_and_gaps() {
        let dir = tmp("rows");
        let mut t = Timeline::create(&dir, 5, 1_793_300_000, "Dead lock/x", "bpfrag test").unwrap();
        assert!(
            t.path()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .ends_with("_Dead-lock-x.csv")
        );
        let mut s = Sample {
            tgid: 7,
            ..Default::default()
        };
        t.event("match detected (INTENSE)");
        t.row(&Row {
            tier: "INTENSE",
            sample: Some(&s),
            ports: &[(27015, port(64, &[(15, 63)], 0))],
            server: Some(("A:27031".into(), 64.0)),
            peers: 2,
        })
        .unwrap();
        s.tx_pkts += 64;
        s.rx_pkts += 64;
        t.event("server A:27031 -> B:27031");
        t.row(&Row {
            tier: "INTENSE",
            sample: Some(&s),
            // a 120 ms stall finished, and 60 more 16 ms gaps
            ports: &[(27015, port(125, &[(15, 123), (63, 1)], 1))],
            server: Some(("B:27031".into(), 61.0)),
            peers: 1,
        })
        .unwrap();
        t.row(&Row::default()).unwrap();
        let path = t.path().to_path_buf();
        assert_eq!(t.finish().unwrap(), path);
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "# bpfrag test");
        assert_eq!(lines[1], HEADER);
        let cols = |l: &str| l.split(',').map(str::to_string).collect::<Vec<_>>();
        let head = cols(HEADER);
        let at =
            |row: &[String], name: &str| row[head.iter().position(|h| h == name).unwrap()].clone();
        let r1 = cols(lines[2]);
        assert_eq!(r1.len(), head.len());
        assert_eq!(at(&r1, "udp_tx_pps"), "", "no rate before a second reading");
        assert_eq!(at(&r1, "server"), "A:27031");
        assert_eq!(at(&r1, "gaps"), "63");
        assert_eq!(at(&r1, "gap_p50_ms"), "16");
        assert_eq!(at(&r1, "events"), "match detected (INTENSE)");
        let r2 = cols(lines[3]);
        assert_eq!(at(&r2, "gaps"), "61", "only this second's gaps");
        assert_eq!(at(&r2, "gap_max_ms"), "64");
        assert_eq!(at(&r2, "stalls"), "1");
        assert_eq!(at(&r2, "peers"), "1");
        assert_eq!(at(&r2, "port"), "27015");
        assert!(at(&r2, "udp_rx_pps").parse::<f64>().unwrap() > 0.0);
        let r3 = cols(lines[4]);
        assert_eq!(r3.len(), head.len(), "an empty row keeps its columns");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_the_newest_are_kept() {
        let dir = tmp("prune");
        for i in 0..4u64 {
            Timeline::create(&dir, 2, 1_793_300_000 + i * 60, "g", "x").unwrap();
        }
        let mut names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names.len(), 2);
        assert!(names[1] > names[0]);
        assert_eq!(
            names[1],
            file_name(1_793_300_000 + 180, "g"),
            "the newest survives"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fields_with_commas_are_quoted() {
        assert_eq!(csv_field("a, b"), "\"a, b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("plain"), "plain");
    }
}
