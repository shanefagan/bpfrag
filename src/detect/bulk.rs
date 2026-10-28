// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Which processes are moving bulk data while a match is on: a Steam
//! download, a torrent client, a cloud sync. Their packets can then be
//! marked low priority (`bulk.class`, LE by default) so CAKE or a QoS
//! router serves the game first.
//!
//! A process is bulk once it has moved at least `min_mbps` (sent plus
//! received, UDP and TCP) for `secs` windows in a row, and stops being bulk
//! after `release_secs` windows below that. Processes on the "never" list
//! (streaming, voice, VPN clients) and the game itself are never bulk;
//! processes on the "always" list (torrent clients) are bulk whenever they
//! move anything. Pure logic: the caller supplies samples and names.

use std::collections::{HashMap, HashSet};

use super::Sample;
use crate::config::Bulk;
use crate::util::first_match;

/// How a process's names matched the bulk lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Listed {
    Never,
    Always,
    Neither,
}

#[derive(Debug)]
struct Track {
    prev_total: u64,
    listed: Listed,
    name: String,
    /// Consecutive windows at or above the rate / below it.
    above: u32,
    below: u32,
    bulk: bool,
    /// Bits per second over the last window.
    bps: f64,
}

/// A process currently treated as bulk.
#[derive(Clone, Debug, PartialEq)]
pub struct BulkProc {
    pub tgid: u32,
    pub name: String,
    /// Megabits per second over the last window.
    pub mbps: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum BulkEvent {
    Started(BulkProc),
    Stopped { tgid: u32, name: String },
}

/// Names for a process: its display name, then every name the lists are
/// matched against (comm, exe name). None if it's gone.
pub type NameLookup<'a> = dyn FnMut(u32) -> Option<(String, Vec<String>)> + 'a;

pub struct BulkDetector {
    min_bps: f64,
    secs: u32,
    release_secs: u32,
    never: Vec<String>,
    always: Vec<String>,
    tracks: HashMap<u32, Track>,
    /// Bytes each process (by name) moved while bulk, this match.
    moved: HashMap<String, u64>,
}

impl BulkDetector {
    pub fn new(cfg: &Bulk) -> Self {
        Self {
            min_bps: cfg.min_mbps * 1e6,
            secs: cfg.secs,
            release_secs: cfg.release_secs,
            never: cfg.never_list(),
            always: cfg.always_list(),
            tracks: HashMap::new(),
            moved: HashMap::new(),
        }
    }

    /// Forget everything (between matches).
    pub fn reset(&mut self) -> Vec<BulkEvent> {
        self.moved.clear();
        self.tracks
            .drain()
            .filter(|(_, t)| t.bulk)
            .map(|(tgid, t)| BulkEvent::Stopped { tgid, name: t.name })
            .collect()
    }

    /// Feed one window. `dt` is its length in seconds; `exclude` are the
    /// game's processes.
    pub fn tick(
        &mut self,
        dt: f64,
        samples: &[Sample],
        exclude: &[u32],
        names: &mut NameLookup,
    ) -> Vec<BulkEvent> {
        let dt = dt.max(0.001);
        let mut events = Vec::new();
        let mut seen = HashSet::new();
        for s in samples {
            if exclude.contains(&s.tgid) {
                continue;
            }
            seen.insert(s.tgid);
            let total = s.total_bytes();
            let Some(t) = self.tracks.get_mut(&s.tgid) else {
                // First sight: the counters cover the process's whole life,
                // so take a baseline. Names are looked up once it moves data.
                self.tracks.insert(
                    s.tgid,
                    Track {
                        prev_total: total,
                        listed: Listed::Neither,
                        name: String::new(),
                        above: 0,
                        below: 0,
                        bulk: false,
                        bps: 0.0,
                    },
                );
                continue;
            };
            if total < t.prev_total {
                // the map entry was recreated: a reused pid
                if t.bulk {
                    events.push(BulkEvent::Stopped {
                        tgid: s.tgid,
                        name: std::mem::take(&mut t.name),
                    });
                }
                *t = Track {
                    prev_total: total,
                    listed: Listed::Neither,
                    name: String::new(),
                    above: 0,
                    below: 0,
                    bulk: false,
                    bps: 0.0,
                };
                continue;
            }
            let delta = total - t.prev_total;
            t.prev_total = total;
            t.bps = delta as f64 * 8.0 / dt;
            if delta > 0 && t.name.is_empty() {
                match names(s.tgid) {
                    Some((display, all)) => {
                        let all: Vec<&str> = all.iter().map(String::as_str).collect();
                        t.listed = if first_match(&self.never, &all).is_some() {
                            Listed::Never
                        } else if first_match(&self.always, &all).is_some() {
                            Listed::Always
                        } else {
                            Listed::Neither
                        };
                        t.name = display;
                    }
                    None => continue,
                }
            }
            let (moving, need) = match t.listed {
                Listed::Never => continue,
                Listed::Always => (delta > 0, 1),
                Listed::Neither => (t.bps >= self.min_bps, self.secs),
            };
            if moving {
                t.above += 1;
                t.below = 0;
            } else {
                t.below += 1;
                t.above = 0;
            }
            if !t.bulk && t.above >= need {
                t.bulk = true;
                events.push(BulkEvent::Started(BulkProc {
                    tgid: s.tgid,
                    name: t.name.clone(),
                    mbps: t.bps / 1e6,
                }));
            } else if t.bulk && t.below >= self.release_secs {
                t.bulk = false;
                events.push(BulkEvent::Stopped {
                    tgid: s.tgid,
                    name: t.name.clone(),
                });
            }
            if t.bulk {
                *self.moved.entry(t.name.clone()).or_default() += delta;
            }
        }
        // processes that exited (BPF removed their entry)
        let gone: Vec<u32> = self
            .tracks
            .keys()
            .copied()
            .filter(|k| !seen.contains(k))
            .collect();
        for tgid in gone {
            if let Some(t) = self.tracks.remove(&tgid).filter(|t| t.bulk) {
                events.push(BulkEvent::Stopped { tgid, name: t.name });
            }
        }
        events
    }

    /// (name, bytes) each process moved while bulk this match, most first.
    pub fn moved(&self) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = self
            .moved
            .iter()
            .filter(|(_, b)| **b > 0)
            .map(|(n, b)| (n.clone(), *b))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    }

    /// Processes currently bulk, busiest first.
    pub fn bulk(&self) -> Vec<BulkProc> {
        let mut v: Vec<BulkProc> = self
            .tracks
            .iter()
            .filter(|(_, t)| t.bulk)
            .map(|(&tgid, t)| BulkProc {
                tgid,
                name: t.name.clone(),
                mbps: t.bps / 1e6,
            })
            .collect();
        v.sort_by(|a, b| b.mbps.total_cmp(&a.mbps));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feeds per-window byte counts to the detector.
    struct Sim {
        det: BulkDetector,
        totals: HashMap<u32, u64>,
        names: HashMap<u32, &'static str>,
    }

    impl Sim {
        fn new(cfg: Bulk) -> Self {
            Self {
                det: BulkDetector::new(&cfg),
                totals: HashMap::new(),
                names: HashMap::new(),
            }
        }

        fn proc(&mut self, tgid: u32, name: &'static str) {
            self.names.insert(tgid, name);
            self.totals.insert(tgid, 0);
        }

        /// One second in which each process moves `mbps` (TCP received).
        fn step(&mut self, mbps: &[(u32, f64)], exclude: &[u32]) -> Vec<BulkEvent> {
            for &(tgid, m) in mbps {
                *self.totals.entry(tgid).or_default() += (m * 1e6 / 8.0) as u64;
            }
            let samples: Vec<Sample> = self
                .totals
                .iter()
                .map(|(&tgid, &b)| Sample {
                    tgid,
                    tcp_rx_bytes: b,
                    ..Default::default()
                })
                .collect();
            let names = self.names.clone();
            let mut lookup = |tgid: u32| {
                names
                    .get(&tgid)
                    .map(|n| (n.to_string(), vec![n.to_string()]))
            };
            self.det.tick(1.0, &samples, exclude, &mut lookup)
        }

        fn run(&mut self, secs: usize, mbps: &[(u32, f64)], exclude: &[u32]) -> Vec<BulkEvent> {
            (0..secs).flat_map(|_| self.step(mbps, exclude)).collect()
        }
    }

    fn started(ev: &[BulkEvent]) -> Vec<&str> {
        ev.iter()
            .filter_map(|e| match e {
                BulkEvent::Started(p) => Some(p.name.as_str()),
                _ => None,
            })
            .collect()
    }

    fn stopped(ev: &[BulkEvent]) -> Vec<&str> {
        ev.iter()
            .filter_map(|e| match e {
                BulkEvent::Stopped { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_sustained_download_becomes_bulk_and_is_released() {
        let mut sim = Sim::new(Bulk::default());
        sim.proc(10, "steam");
        // baseline, then 4 windows at 40 Mbit/s: not yet (needs 5)
        assert!(started(&sim.run(5, &[(10, 40.0)], &[])).is_empty());
        let ev = sim.step(&[(10, 40.0)], &[]);
        assert_eq!(started(&ev), ["steam"]);
        // the window it became bulk in counts: 40 Mbit/s for 1 s = 5 MB
        sim.step(&[(10, 40.0)], &[]);
        assert_eq!(sim.det.moved(), [("steam".to_string(), 10_000_000)]);
        let b = sim.det.bulk();
        assert_eq!(b.len(), 1);
        assert!((b[0].mbps - 40.0).abs() < 0.1, "{b:?}");
        // a short pause doesn't release it, 10 quiet seconds do
        assert!(stopped(&sim.run(9, &[], &[])).is_empty());
        assert_eq!(sim.det.moved()[0].1, 10_000_000);
        assert_eq!(stopped(&sim.step(&[], &[])), ["steam"]);
        assert!(sim.det.bulk().is_empty());
    }

    #[test]
    fn small_flows_never_qualify() {
        let mut sim = Sim::new(Bulk::default());
        sim.proc(11, "firefox");
        // a page load now and then, 1 Mbit/s of chatter
        assert!(started(&sim.run(30, &[(11, 1.0)], &[])).is_empty());
        // one big burst isn't sustained either
        let ev = sim.run(1, &[(11, 100.0)], &[]);
        let ev2 = sim.run(3, &[(11, 1.0)], &[]);
        assert!(started(&ev).is_empty() && started(&ev2).is_empty());
    }

    #[test]
    fn never_list_game_and_always_list() {
        let mut sim = Sim::new(Bulk::default());
        sim.proc(20, "obs");
        sim.proc(21, "cs2");
        sim.proc(22, "qbittorrent");
        let rates = [(20, 6.0), (21, 3.0), (22, 0.1)];
        let ev = sim.run(10, &rates, &[21]);
        // OBS uploading and the game are left alone; the torrent client is
        // bulk as soon as it moves anything
        assert_eq!(started(&ev), ["qbittorrent"]);
    }

    #[test]
    fn user_lists_extend_the_builtin_ones() {
        let cfg = Bulk {
            never: vec!["rclone".into()],
            always: vec!["my-sync*".into()],
            ..Default::default()
        };
        let mut sim = Sim::new(cfg);
        sim.proc(30, "rclone");
        sim.proc(31, "my-sync-daemon");
        sim.proc(32, "obs");
        let ev = sim.run(8, &[(30, 50.0), (31, 0.2), (32, 50.0)], &[]);
        assert_eq!(started(&ev), ["my-sync-daemon"]);
    }

    #[test]
    fn exit_and_reset_report_stops() {
        let mut sim = Sim::new(Bulk::default());
        sim.proc(40, "steam");
        sim.proc(41, "aria2c");
        sim.run(7, &[(40, 30.0), (41, 30.0)], &[]);
        assert_eq!(sim.det.bulk().len(), 2);
        // aria2c exits: BPF drops its entry
        sim.totals.remove(&41);
        assert_eq!(stopped(&sim.step(&[(40, 30.0)], &[])), ["aria2c"]);
        // the match ends
        assert_eq!(stopped(&sim.det.reset()), ["steam"]);
        assert!(sim.det.bulk().is_empty());
    }

    #[test]
    fn a_reused_pid_starts_over() {
        let mut sim = Sim::new(Bulk::default());
        sim.proc(50, "steam");
        sim.run(7, &[(50, 30.0)], &[]);
        assert_eq!(sim.det.bulk().len(), 1);
        // a new process with the same pid: counters start from zero again
        sim.totals.insert(50, 0);
        assert_eq!(stopped(&sim.step(&[], &[])), ["steam"]);
        assert!(sim.det.bulk().is_empty());
    }
}
