// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan
//
// Metrics, shared between the daemon (writes /run/bpfrag/stats.json every
// tick, prints a line with --stats) and `bpfrag --monitor` (reads it).

use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionMetrics {
    pub tgid: u32,
    pub name: String,
    pub reason: String,
    pub tier: String,
    pub pps: f64,
    pub since_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppliedMetric {
    pub knob: String,
    pub value: String,
    pub baseline: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DscpMetrics {
    pub class: String,
    pub interfaces: Vec<String>,
    pub ports: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TopProc {
    pub tgid: u32,
    pub name: String,
    pub pps: f64,
    pub tx_pps: f64,
    pub rx_pps: f64,
    pub avg_size: f64,
    pub jitter: f64,
    pub verdict: String,
}

/// Global BPF counters (cumulative), mirrors enum stat_idx.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    /// UDP processes currently tracked, and their total packets/s
    pub udp_procs: usize,
    pub udp_pps: f64,
    pub tc_seen: u64,
    pub dscp_marked: u64,
    pub dscp_kept: u64,
    pub exits: u64,
    pub events_dropped: u64,
}

/// A finished match, newest first in `Metrics::recent`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecentMatch {
    pub name: String,
    pub peak_tier: String,
    pub peak_pps: f64,
    pub duration_secs: u64,
    pub ended: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metrics {
    pub version: String,
    pub pid: u32,
    pub updated: u64,
    pub hook: String,
    pub dry_run: bool,
    pub session: Option<SessionMetrics>,
    pub applied: Vec<AppliedMetric>,
    pub dscp: Option<DscpMetrics>,
    pub counters: Counters,
    /// Notes about other tuners sharing the machine (bpftune, ...).
    pub neighbours: Vec<String>,
    pub top: Vec<TopProc>,
    /// Last few finished matches.
    #[serde(default)]
    pub recent: Vec<RecentMatch>,
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn fmt_dur(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs / 60) % 60, secs % 60);
    if h > 0 {
        format!("{h}h{m:02}m{s:02}s")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}

const FILE: &str = "stats.json";

pub fn write(run_dir: &Path, m: &Metrics) -> Result<()> {
    let tmp = run_dir.join("stats.json.tmp");
    let mut f = fs::File::create(&tmp)?;
    f.write_all(serde_json::to_string_pretty(m)?.as_bytes())?;
    fs::rename(&tmp, run_dir.join(FILE))?;
    Ok(())
}

pub fn remove(run_dir: &Path) {
    let _ = fs::remove_file(run_dir.join(FILE));
}

pub fn read(run_dir: &Path) -> Result<Metrics> {
    let path = run_dir.join(FILE);
    let text = fs::read_to_string(&path)
        .with_context(|| format!("{} not found: is bpfrag running?", path.display()))?;
    Ok(serde_json::from_str(&text)?)
}

impl Metrics {
    /// One line for the daemon log (--stats).
    pub fn line(&self) -> String {
        let sess = match &self.session {
            Some(s) => format!(
                "{} {} {:.0}pps {}",
                s.name,
                s.tier,
                s.pps,
                fmt_dur(s.since_secs)
            ),
            None => "idle".into(),
        };
        format!(
            "[bpfrag] {sess} | udp {:.0} pkt/s over {} procs | dscp marked {} kept {} | knobs {}",
            self.counters.udp_pps,
            self.counters.udp_procs,
            self.counters.dscp_marked,
            self.counters.dscp_kept,
            self.applied.len()
        )
    }

    pub fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        let age = now_unix().saturating_sub(self.updated);
        let alive = unsafe { libc::kill(self.pid as i32, 0) } == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
        writeln!(
            w,
            "bpfrag {} | pid {}{} | {} | updated {age}s ago{}",
            self.version,
            self.pid,
            if alive { "" } else { " (NOT RUNNING)" },
            self.hook,
            if self.dry_run {
                " | DRY RUN, nothing is changed"
            } else {
                ""
            },
        )?;
        match &self.session {
            Some(s) => writeln!(
                w,
                "\nIn a match: {} (pid {}) - {} @ {:.0} pkt/s for {}\n  why it's a game: {}",
                s.name,
                s.tgid,
                s.tier,
                s.pps,
                fmt_dur(s.since_secs),
                s.reason
            )?,
            None => writeln!(w, "\nNo match in progress; baseline settings active.")?,
        }
        if !self.applied.is_empty() {
            writeln!(w, "\nApplied:")?;
            let width = self.applied.iter().map(|a| a.knob.len()).max().unwrap_or(0);
            for a in &self.applied {
                if a.baseline.is_empty() {
                    writeln!(w, "  {:<width$}  {}", a.knob, a.value)?;
                } else {
                    writeln!(w, "  {:<width$}  {}  (was {})", a.knob, a.value, a.baseline)?;
                }
            }
        }
        if let Some(d) = &self.dscp {
            writeln!(
                w,
                "\nDSCP {} on {}: {} game port(s)",
                d.class,
                if d.interfaces.is_empty() {
                    "-".into()
                } else {
                    d.interfaces.join(", ")
                },
                d.ports
            )?;
        }
        let c = &self.counters;
        writeln!(
            w,
            "\nCounters: udp {:.0} pkt/s over {} procs | dscp marked {} kept {} | exits {} | ringbuf drops {}",
            c.udp_pps, c.udp_procs, c.dscp_marked, c.dscp_kept, c.exits, c.events_dropped
        )?;
        for n in &self.neighbours {
            writeln!(w, "Note: {n}")?;
        }
        if !self.recent.is_empty() {
            writeln!(w, "\nRecent matches:")?;
            let now = now_unix();
            for r in &self.recent {
                writeln!(
                    w,
                    "  {:<16} peak {} @ {:.0} pkt/s, {} ({}), {} ago",
                    r.name.chars().take(16).collect::<String>(),
                    r.peak_tier,
                    r.peak_pps,
                    fmt_dur(r.duration_secs),
                    r.reason,
                    fmt_dur(now.saturating_sub(r.ended))
                )?;
            }
        }
        if !self.top.is_empty() {
            writeln!(w, "\nBusiest UDP processes:")?;
            writeln!(
                w,
                "  {:>7}  {:<16} {:>7} {:>11} {:>6} {:>6}  VERDICT",
                "PID", "NAME", "PKT/S", "TX/RX", "AVG B", "JITTER"
            )?;
            for p in &self.top {
                let jit = if p.jitter >= 0.0 {
                    format!("{:.2}", p.jitter)
                } else {
                    "-".into()
                };
                writeln!(
                    w,
                    "  {:>7}  {:<16} {:>7.0} {:>11} {:>6.0} {:>6}  {}",
                    p.tgid,
                    p.name.chars().take(16).collect::<String>(),
                    p.pps,
                    format!("{:.0}/{:.0}", p.tx_pps, p.rx_pps),
                    p.avg_size,
                    jit,
                    p.verdict
                )?;
            }
        }
        Ok(())
    }
}

fn pid_alive(pid: u32) -> bool {
    let ok = unsafe { libc::kill(pid as i32, 0) } == 0;
    ok || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// One line of JSON for a Waybar (or Polybar/i3blocks) custom module.
/// `text` is empty outside a match, which hides the module.
pub fn waybar(run_dir: &Path) -> String {
    let m = match read(run_dir) {
        Ok(m) if pid_alive(m.pid) => m,
        _ => {
            return serde_json::json!({
                "text": "", "alt": "off", "class": "off",
                "tooltip": "bpfrag is not running",
            })
            .to_string();
        }
    };
    let last = m.recent.first().map(|r| {
        format!(
            "\nLast match: {} {} for {} ({})",
            r.name,
            r.peak_tier,
            fmt_dur(r.duration_secs),
            r.reason
        )
    });
    let Some(s) = &m.session else {
        return serde_json::json!({
            "text": "", "alt": "idle", "class": "idle",
            "tooltip": format!("bpfrag: waiting for a match{}", last.unwrap_or_default()),
        })
        .to_string();
    };
    let mut tip = format!(
        "{} (pid {}): {} @ {:.0} pkt/s for {}\nwhy: {}",
        s.name,
        s.tgid,
        s.tier,
        s.pps,
        fmt_dur(s.since_secs),
        s.reason
    );
    if let Some(d) = &m.dscp {
        tip += &format!("\nDSCP {} on {}", d.class, d.interfaces.join(", "));
    }
    for a in &m.applied {
        tip += &format!("\n{} = {}", a.knob, a.value);
    }
    if m.dry_run {
        tip += "\n(dry run: nothing applied)";
    }
    let lower = s.tier.to_lowercase();
    serde_json::json!({
        "text": s.tier, "alt": lower, "class": lower, "tooltip": tip,
    })
    .to_string()
}

/// `bpfrag --monitor N`: print the running instance's metrics every N
/// seconds (once if N is 0).
pub fn monitor(run_dir: &Path, interval: f64, shutdown: Arc<AtomicBool>) -> Result<()> {
    loop {
        let m = read(run_dir)?;
        let mut out = std::io::stdout().lock();
        if interval > 0.0 {
            write!(out, "\x1b[2J\x1b[H")?;
        }
        m.format(&mut out)?;
        out.flush()?;
        drop(out);
        if interval <= 0.0 {
            return Ok(());
        }
        let until = std::time::Instant::now() + Duration::from_secs_f64(interval);
        while std::time::Instant::now() < until {
            if shutdown.load(Ordering::Relaxed) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}
