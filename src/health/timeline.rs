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
//! | `server`, `server_pps` | who the game receives from ([`super::peers`]): a letter per address, and the port; its packets that second |
//! | `peers` | remote addresses and ports that sent anything this second |
//! | `port` | the game's local port that received the most this second |
//! | `gaps`, `gap_p50_ms`, `gap_p99_ms`, `gap_max_ms` | arrival gaps this second on the ports carrying the match (1 ms buckets; a longest gap over 63 ms is its exact length, or 64 if the meter didn't time it) |
//! | `stalls` | stalls the meter finished counting this second |
//! | `send_gap_max_ms`, `send_stalls` | the game's own sending, timed as it sends: its longest gap that second (ms) and stalls (100 ms to 2 s) ended in it; a stall in `stalls` with none here is the network or the server |
//! | `jitter_us` | how much each gap at game rate differed from the one before, on average, to the microsecond |
//! | `tcp_tx_msgs_s`, `tcp_rx_msgs_s` | the game's TCP send and receive calls this second |
//! | `tcp_retransmits` | segments its TCP connections sent again this second (a game that talks TCP; empty otherwise) |
//! | `events` | match start and end, tier and server changes, outages, the server's packets arriving on a link the game doesn't send on |
//!
//! For a game that talks TCP (the first line says "over TCP"), the gap
//! columns are between the game's receives on its TCP connections, keyed
//! by local port like a UDP game's, and the server columns are empty.
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

/// A port's counters at the last row.
#[derive(Clone, Copy)]
struct PortSoFar {
    pkts: u64,
    updates: u64,
    hist: [u64; BUCKETS],
    stalls: u64,
    jitter_n: u64,
    jitter_ns: u64,
}

impl Default for PortSoFar {
    fn default() -> Self {
        PortSoFar {
            pkts: 0,
            updates: 0,
            hist: [0; BUCKETS],
            stalls: 0,
            jitter_n: 0,
            jitter_ns: 0,
        }
    }
}

/// What a port received since the last row.
struct PortDelta {
    pkts: u64,
    updates: u64,
    hist: [u64; BUCKETS],
    stalls: u64,
    longest_ns: u64,
    jitter_n: u64,
    jitter_ns: u64,
}

const HEADER: &str = "t,unix,tier,udp_tx_pps,udp_rx_pps,udp_tx_bytes_s,udp_rx_bytes_s,\
tcp_tx_bytes_s,tcp_rx_bytes_s,server,server_pps,peers,port,gaps,gap_p50_ms,gap_p99_ms,\
gap_max_ms,stalls,jitter_us,send_gap_max_ms,send_stalls,tcp_tx_msgs_s,tcp_rx_msgs_s,\
tcp_retransmits,events";

/// What one row reports, besides the time.
#[derive(Default)]
pub struct Row<'a> {
    pub tier: &'a str,
    /// The game's cumulative counters, if it's still running.
    pub sample: Option<&'a Sample>,
    /// Seconds since the previous sample was read: what the rates are
    /// per. The daemon reads its counters at the start of a tick and
    /// writes the row near its end, after work that can take a fifth of a
    /// second (listing /proc), so the time between rows isn't the time
    /// between samples. None: the time since the last row.
    pub dt: Option<f64>,
    /// The meter's per-port statistics (cumulative).
    pub ports: &'a [(u16, bpf_intf::port_rx)],
    /// The current server's label and packets a second.
    pub server: Option<(String, f64)>,
    pub peers: usize,
    /// The meter's reading for this row (`maps::next_reading`), whose
    /// longest gap each port carries.
    pub reading: Option<u32>,
    /// The game's sending: stalls so far, and this reading's longest gap
    /// (ns), as health gets them.
    pub send: Option<(u64, u64)>,
    /// Segments the game's TCP connections have sent again so far (a game
    /// that talks TCP), as a running count.
    pub tcp_retransmits: Option<u64>,
}

pub struct Timeline {
    out: BufWriter<File>,
    path: PathBuf,
    start: Instant,
    last: Instant,
    prev: Option<Sample>,
    /// Each port's counters at the last row.
    prev_ports: HashMap<u16, PortSoFar>,
    prev_send_stalls: Option<u64>,
    prev_retrans: Option<u64>,
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
        // One cell starting with '#', whatever the game is called: a comma
        // would split it, and a cell starting with = is a formula to a
        // spreadsheet.
        writeln!(
            out,
            "# {}",
            about.replace(['\n', '\r'], " ").replace(',', ";")
        )?;
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
            prev_send_stalls: None,
            prev_retrans: None,
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

    /// Write one row: rates since the last row, per `r.dt`.
    pub fn row(&mut self, r: &Row) -> io::Result<()> {
        let now = Instant::now();
        let dt =
            r.dt.filter(|d| *d > 0.0)
                .unwrap_or_else(|| now.duration_since(self.last).as_secs_f64())
                .max(0.001);
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
        let tcp_msgs = match (r.sample, self.prev.as_ref()) {
            (Some(s), Some(p)) => format!(
                "{},{}",
                rate(s.tcp_tx_msgs, p.tcp_tx_msgs),
                rate(s.tcp_rx_msgs, p.tcp_rx_msgs)
            ),
            _ => ",".into(),
        };
        let retrans = match r.tcp_retransmits {
            Some(n) => {
                let d = n.saturating_sub(self.prev_retrans.unwrap_or(n));
                self.prev_retrans = Some(n);
                d.to_string()
            }
            None => String::new(),
        };
        if let Some(s) = r.sample {
            self.prev = Some(*s);
        }
        let gaps = self.gaps_since_last(r.ports, r.reading);
        let send = match r.send {
            Some((stalls, max_ns)) => {
                let d = stalls.saturating_sub(self.prev_send_stalls.unwrap_or(stalls));
                self.prev_send_stalls = Some(stalls);
                let max = if max_ns > 0 {
                    format!("{:.0}", max_ns as f64 / 1e6)
                } else {
                    String::new()
                };
                format!("{max},{d}")
            }
            None => ",".into(),
        };
        let (server, server_pps) = match &r.server {
            Some((label, pps)) => (label.clone(), format!("{pps:.0}")),
            None => (String::new(), String::new()),
        };
        let unix = crate::stats::now_unix();
        let events = std::mem::take(&mut self.events).join("; ");
        writeln!(
            self.out,
            "{:.1},{unix},{},{},{server},{server_pps},{},{},{send},{tcp_msgs},{retrans},{}",
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

    /// "port,gaps,p50,p99,max,stalls,jitter" since the last row, over the ports
    /// that received at least a tenth of the updates the busiest did this
    /// second, as the health meter counts them. Packets would leave out a
    /// relay's new port in the second the game moves to it: its first
    /// updates come a packet each, against the old port's two or three, and
    /// the gap the move cost (97 to 99 ms on 27 November) is on the new port.
    fn gaps_since_last(
        &mut self,
        ports: &[(u16, bpf_intf::port_rx)],
        reading: Option<u32>,
    ) -> String {
        let mut now = HashMap::with_capacity(ports.len());
        let mut deltas = Vec::with_capacity(ports.len());
        for (port, r) in ports {
            let g = Gaps::from_bpf(*port, r);
            let was = match self.prev_ports.get(port) {
                // an entry the LRU map dropped and made again starts over
                Some(was) if was.pkts <= g.pkts => *was,
                _ => PortSoFar::default(),
            };
            let mut hist = [0u64; BUCKETS];
            for (x, (a, b)) in hist.iter_mut().zip(g.hist.iter().zip(was.hist.iter())) {
                *x = a.saturating_sub(*b);
            }
            // this reading's longest gap, timed exactly, if the port had one
            let longest_ns = reading
                .filter(|n| r.reading == *n)
                .map_or(0, |_| r.reading_max_ns);
            deltas.push((
                *port,
                PortDelta {
                    pkts: g.pkts - was.pkts,
                    updates: g.updates.saturating_sub(was.updates),
                    hist,
                    stalls: g.stalls.saturating_sub(was.stalls),
                    longest_ns,
                    jitter_n: g.jitter_n.saturating_sub(was.jitter_n),
                    jitter_ns: g.sum_jitter_ns.saturating_sub(was.jitter_ns),
                },
            ));
            now.insert(
                *port,
                PortSoFar {
                    pkts: g.pkts,
                    updates: g.updates,
                    hist: g.hist,
                    stalls: g.stalls,
                    jitter_n: g.jitter_n,
                    jitter_ns: g.sum_jitter_ns,
                },
            );
        }
        self.prev_ports = now;
        // the port column and its packets are the busiest port's
        let Some((port, most)) = deltas
            .iter()
            .map(|(p, d)| (*p, d.pkts))
            .max_by_key(|&(_, n)| n)
            .filter(|&(_, n)| n > 0)
        else {
            return ",0,,,,0,".into();
        };
        // updates where the meter counted them, packets otherwise
        let busiest_updates = deltas.iter().map(|(_, d)| d.updates).max().unwrap_or(0);
        let counts = |d: &PortDelta| {
            if busiest_updates > 0 {
                (d.updates, busiest_updates)
            } else {
                (d.pkts, most)
            }
        };
        let mut hist = [0u64; BUCKETS];
        let mut stalls = 0;
        let mut longest_ns = 0;
        let (mut jitter_n, mut jitter_ns) = (0, 0);
        for (_, d) in deltas.iter().filter(|(_, d)| {
            let (n, busiest) = counts(d);
            n.saturating_mul(10) >= busiest
        }) {
            for (h, x) in hist.iter_mut().zip(d.hist.iter()) {
                *h += x;
            }
            stalls += d.stalls;
            longest_ns = longest_ns.max(d.longest_ns);
            jitter_n += d.jitter_n;
            jitter_ns += d.jitter_ns;
        }
        let this = Gaps {
            port,
            pkts: most,
            updates: 0,
            hist,
            max_gap_ns: 0,
            stalls,
            napi_id: 0,
            fine_n: 0,
            sum_gap_ns: 0,
            jitter_n,
            sum_jitter_ns: jitter_ns,
        };
        let jitter = this
            .jitter_us()
            .map(|j| format!("{j:.0}"))
            .unwrap_or_default();
        let n: u64 = hist.iter().sum();
        let q = |v: Option<u32>| v.map(|x| x.to_string()).unwrap_or_default();
        // The last bucket holds every gap over 63 ms: a relay change
        // (about 70 ms) and a stall (100 ms+) read the same there, so
        // use the meter's exact longest gap when it has one.
        let max = hist
            .iter()
            .rposition(|c| *c > 0)
            .map(|i| {
                if i + 1 == BUCKETS && longest_ns > 63_000_000 {
                    format!("{:.0}", longest_ns as f64 / 1e6)
                } else {
                    (i + 1).to_string()
                }
            })
            .unwrap_or_default();
        format!(
            "{port},{n},{},{},{max},{stalls},{jitter}",
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
    // A spreadsheet runs a cell starting with one of these as a formula
    // (OWASP's CSV injection); a leading ' keeps it text.
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\"").replace('\n', " "))
    } else {
        s
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
    fn cells_are_never_formulas() {
        assert_eq!(csv_field("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_field("-2+3"), "'-2+3");
        assert_eq!(csv_field("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(
            csv_field("server A:27031 -> B:27031"),
            "server A:27031 -> B:27031"
        );
        let dir = std::env::temp_dir().join(format!("bpfrag-tl-formula-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let t = Timeline::create(&dir, 3, 1, "x", "bpfrag 1; a,=1+1,b (pid 2)").unwrap();
        let text = std::fs::read_to_string(t.path()).unwrap();
        assert_eq!(text.lines().next().unwrap(), "# bpfrag 1; a;=1+1;b (pid 2)");
        let _ = std::fs::remove_dir_all(&dir);
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
            ..Default::default()
        })
        .unwrap();
        s.tx_pkts += 64;
        s.rx_pkts += 64;
        t.event("server A:27031 -> B:27031");
        t.row(&Row {
            tier: "INTENSE",
            sample: Some(&s),
            // the counters were read a second apart, whenever the row is
            // written
            dt: Some(1.0),
            // a 120 ms stall finished, and 60 more 16 ms gaps
            ports: &[(27015, port(125, &[(15, 123), (63, 1)], 1))],
            server: Some(("B:27031".into(), 61.0)),
            peers: 1,
            ..Default::default()
        })
        .unwrap();
        // a 72 ms gap the meter timed in this reading, and 62 more
        let mut timed = port(188, &[(15, 185), (63, 2)], 1);
        timed.reading = 9;
        timed.reading_max_ns = 72_400_000;
        t.row(&Row {
            tier: "INTENSE",
            sample: Some(&s),
            ports: &[(27015, timed)],
            reading: Some(9),
            ..Default::default()
        })
        .unwrap();
        // the same port, but the meter's longest is an older reading's
        timed.pkts += 63;
        timed.hist[15] += 62;
        timed.hist[63] += 1;
        t.row(&Row {
            tier: "INTENSE",
            sample: Some(&s),
            ports: &[(27015, timed)],
            reading: Some(10),
            ..Default::default()
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
        assert_eq!(at(&r2, "udp_rx_pps"), "64", "per second between samples");
        assert_eq!(at(&cols(lines[4]), "gap_max_ms"), "72", "timed exactly");
        assert_eq!(
            at(&cols(lines[5]), "gap_max_ms"),
            "64",
            "not timed this reading"
        );
        let r3 = cols(lines[6]);
        assert_eq!(r3.len(), head.len(), "an empty row keeps its columns");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_relays_new_port_counts_by_updates_like_the_health_meter() {
        let dir = tmp("new-port");
        let mut t = Timeline::create(&dir, 5, 1_793_300_000, "Deadlock", "bpfrag test").unwrap();
        // 27 November, 11:46: the second Deadlock moved to a relay's new
        // port. The old one still had most of it, 138 packets in 60
        // updates; the new one 8 packets, 8 updates, and the 99 ms gap the
        // move cost. Under a tenth of the packets, over a tenth of the
        // updates: the health meter counted that gap, so the row must too.
        let mut old = port(138, &[(15, 59)], 0);
        old.updates = 60;
        old.reading = 4;
        old.reading_max_ns = 18_000_000;
        let mut new = port(8, &[(15, 6), (63, 1)], 0);
        new.updates = 8;
        new.reading = 4;
        new.reading_max_ns = 99_000_000;
        t.row(&Row {
            tier: "COMPETITIVE",
            ports: &[(44826, old), (39782, new)],
            reading: Some(4),
            ..Default::default()
        })
        .unwrap();
        let path = t.path().to_path_buf();
        t.finish().unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let head: Vec<&str> = HEADER.split(',').collect();
        let row: Vec<&str> = text.lines().nth(2).unwrap().split(',').collect();
        let at = |name: &str| row[head.iter().position(|h| *h == name).unwrap()];
        assert_eq!(at("port"), "44826", "the port column is still the busiest");
        assert_eq!(at("gap_max_ms"), "99");
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
