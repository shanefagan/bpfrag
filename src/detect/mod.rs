// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Match detection: deciding from per-process UDP counters when a game's
//! netcode is running, which tier it is in, and when the match is over.
//!
//! - this file: the [`Detector`], fed one window of counters per tick;
//! - [`classify`]: "is this process a game?";
//! - [`egress`]: which network links the game's packets actually use.
//!
//! The detector is the userspace port of the window/hysteresis logic from
//! the original bpftune gaming tuner's BPF program, with two structural
//! changes:
//!
//!  * it runs per process instead of on one global UDP counter, so a torrent
//!    client or a browser can't push someone else over the threshold, and the
//!    process we attribute a session to is the one that actually sent it;
//!  * a process must also pass the classifier ([`classify`]) before a
//!    session starts.
//!
//! Kept from the original: packets-per-second smoothing over a short history,
//! a variance gate, CASUAL/COMPETITIVE/INTENSE tiers with a hysteresis margin,
//! asymmetric confidence for up/down changes, a dwell time between changes,
//! and "never fall back to CASUAL while traffic is still flowing".

pub mod classify;
pub mod egress;

use std::collections::{HashMap, VecDeque};

use crate::config::{Detect, Tier};
use classify::Verdict;

/// Consecutive windows that must agree on a new tier before it is applied:
/// moving up is quick, moving down slower, and back to CASUAL slowest.
const CONFIDENCE_UP: u32 = 3;
const CONFIDENCE_DOWN: u32 = 4;
const CONFIDENCE_TO_CASUAL: u32 = 6;

/// Cumulative per-process counters as read from the BPF map.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sample {
    pub tgid: u32,
    pub tx_pkts: u64,
    pub rx_pkts: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub ifindex: u32,
}

/// One sampling window for one process.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Window {
    pub tx_pps: f64,
    pub rx_pps: f64,
    pub avg_size: f64,
}

impl Window {
    pub fn total(&self) -> f64 {
        self.tx_pps + self.rx_pps
    }
}

#[derive(Debug)]
struct Track {
    prev: Sample,
    hist: VecDeque<Window>,
    steady: u32,
    idle_ticks: u32,
    ifindex: u32,
}

impl Track {
    fn new(s: Sample) -> Self {
        Self {
            prev: s,
            hist: VecDeque::new(),
            steady: 0,
            idle_ticks: 0,
            ifindex: s.ifindex,
        }
    }

    fn last(&self) -> Window {
        self.hist.back().copied().unwrap_or_default()
    }

    /// Mean total pps over the history.
    fn smooth(&self) -> f64 {
        if self.hist.is_empty() {
            return 0.0;
        }
        self.hist.iter().map(Window::total).sum::<f64>() / self.hist.len() as f64
    }

    /// Mean payload size over the history, weighted by packets.
    fn smooth_size(&self) -> f64 {
        let pkts: f64 = self.hist.iter().map(Window::total).sum();
        if pkts <= 0.0 {
            return 0.0;
        }
        self.hist
            .iter()
            .map(|w| w.avg_size * w.total())
            .sum::<f64>()
            / pkts
    }

    /// Mean tx / rx pps over the history.
    fn smooth_dirs(&self) -> (f64, f64) {
        if self.hist.is_empty() {
            return (0.0, 0.0);
        }
        let n = self.hist.len() as f64;
        (
            self.hist.iter().map(|w| w.tx_pps).sum::<f64>() / n,
            self.hist.iter().map(|w| w.rx_pps).sum::<f64>() / n,
        )
    }

    /// Mean absolute deviation relative to the mean (0 = metronome).
    fn jitter(&self) -> f64 {
        let m = self.smooth();
        if m <= 0.0 {
            return f64::INFINITY;
        }
        let mad =
            self.hist.iter().map(|w| (w.total() - m).abs()).sum::<f64>() / self.hist.len() as f64;
        mad / m
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SessionInfo {
    pub tgid: u32,
    pub name: String,
    /// Why the classifier called it a game.
    pub reason: String,
    pub tier: Tier,
    /// Smoothed packets/s, and per direction (pps = tx + rx).
    pub pps: f64,
    pub tx_pps: f64,
    pub rx_pps: f64,
    /// Egress device of a connected socket, if the BPF side saw one.
    pub ifindex: u32,
    /// Highest tier and rate so far in this match.
    pub peak_tier: Tier,
    pub peak_pps: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    Start(SessionInfo),
    Retier {
        from: Tier,
        to: Tier,
    },
    /// The match is over; `session` is its final state.
    End {
        session: SessionInfo,
        reason: String,
    },
    /// Candidate rejected by the classifier (reported once per process).
    Ignored {
        tgid: u32,
        name: String,
        reason: String,
        pps: f64,
        /// Deliberately excluded (deny list, BPFRAG_GAME=0) rather than
        /// just lacking game signals.
        excluded: bool,
    },
}

#[derive(Debug)]
struct Session {
    info: SessionInfo,
    candidate: Tier,
    confidence: u32,
    last_change: f64,
    quiet_secs: f64,
}

/// What the detector needs to know about a process. In the daemon this is
/// [`classify::ProcfsLookup`]; tests use a fake, so the detector itself
/// never touches /proc.
pub trait ProcessLookup {
    /// Is this process a game, and what should we call it?
    fn verdict(&mut self, tgid: u32) -> (Verdict, String);
    /// Does the process still exist?
    fn alive(&mut self, tgid: u32) -> bool;
}

/// Edges of the hysteresis bands, in smoothed pkt/s: a tier is entered at
/// its `_up` rate and left at its `_down` rate.
#[derive(Debug, PartialEq)]
struct Thresholds {
    competitive_up: f64,
    competitive_down: f64,
    intense_up: f64,
    intense_down: f64,
}

fn thresholds(cfg: &Detect) -> Thresholds {
    let c = cfg.competitive_pps as f64;
    let i = cfg.intense_pps as f64;
    let m = cfg.margin as f64;
    Thresholds {
        competitive_up: c + m,
        competitive_down: if c > m { c - m } else { cfg.min_pps as f64 },
        intense_up: i + m,
        intense_down: if i > m { i - m } else { c + m },
    }
}

/// Port of gaming_determine_intensity(): hysteresis around each threshold.
fn tier_for(cfg: &Detect, current: Tier, pps: f64) -> Tier {
    let t = thresholds(cfg);
    match current {
        Tier::Intense if pps <= t.intense_down => Tier::Competitive,
        Tier::Intense => Tier::Intense,
        _ if pps >= t.intense_up => Tier::Intense,
        Tier::Competitive if pps <= t.competitive_down => Tier::Casual,
        Tier::Competitive => Tier::Competitive,
        Tier::Casual if pps >= t.competitive_up => Tier::Competitive,
        Tier::Casual => Tier::Casual,
    }
}

pub struct Detector {
    cfg: Detect,
    tracks: HashMap<u32, Track>,
    session: Option<Session>,
    ignored: HashMap<u32, f64>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ProcView {
    pub tgid: u32,
    pub pps: f64,
    pub tx_pps: f64,
    pub rx_pps: f64,
    pub avg_size: f64,
    pub jitter: f64,
    pub steady: u32,
}

impl Detector {
    pub fn new(cfg: Detect) -> Self {
        Self {
            cfg,
            tracks: HashMap::new(),
            session: None,
            ignored: HashMap::new(),
        }
    }

    pub fn session(&self) -> Option<&SessionInfo> {
        self.session.as_ref().map(|s| &s.info)
    }

    /// (processes with recent UDP traffic, their total smoothed pps)
    pub fn totals(&self) -> (usize, f64) {
        self.tracks
            .values()
            .map(Track::smooth)
            .filter(|p| *p > 0.0)
            .fold((0, 0.0), |(n, s), p| (n + 1, s + p))
    }

    /// Top talkers, for status output. Every column is averaged over the
    /// same history window.
    pub fn view(&self, n: usize) -> Vec<ProcView> {
        let mut v: Vec<ProcView> = self
            .tracks
            .iter()
            .filter(|(_, t)| !t.hist.is_empty())
            .map(|(&tgid, t)| {
                let (tx_pps, rx_pps) = t.smooth_dirs();
                ProcView {
                    tgid,
                    pps: t.smooth(),
                    tx_pps,
                    rx_pps,
                    avg_size: t.smooth_size(),
                    jitter: t.jitter(),
                    steady: t.steady,
                }
            })
            .filter(|p| p.pps > 0.0)
            .collect();
        v.sort_by(|a, b| b.pps.total_cmp(&a.pps));
        v.truncate(n);
        v
    }

    /// Feed one window of samples. `now` is monotonic seconds, `dt` the
    /// window length in seconds.
    pub fn tick(
        &mut self,
        now: f64,
        dt: f64,
        samples: &[Sample],
        procs: &mut dyn ProcessLookup,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let dt = dt.max(0.001);
        let hist_len = self.cfg.history;

        // 1. Update every track with this window's deltas.
        let mut seen = std::collections::HashSet::new();
        for s in samples {
            seen.insert(s.tgid);
            let Some(t) = self.tracks.get_mut(&s.tgid) else {
                // First sight: counters cover the whole process lifetime so
                // far, so just take a baseline and measure from the next tick.
                self.tracks.insert(s.tgid, Track::new(*s));
                continue;
            };
            // Counters went backwards: the map entry was recreated, i.e. the
            // pid was reused between two ticks. Treat it as a new process:
            // no inherited history, steadiness or "ignored" verdict.
            if s.tx_pkts < t.prev.tx_pkts || s.rx_pkts < t.prev.rx_pkts {
                *t = Track::new(*s);
                self.ignored.remove(&s.tgid);
                continue;
            }
            let prev = t.prev;
            let dtx = s.tx_pkts - prev.tx_pkts;
            let drx = s.rx_pkts - prev.rx_pkts;
            let dbytes = (s.tx_bytes.saturating_sub(prev.tx_bytes))
                + (s.rx_bytes.saturating_sub(prev.rx_bytes));
            let pkts = dtx + drx;
            let w = Window {
                tx_pps: dtx as f64 / dt,
                rx_pps: drx as f64 / dt,
                avg_size: if pkts > 0 {
                    dbytes as f64 / pkts as f64
                } else {
                    0.0
                },
            };
            t.prev = *s;
            if s.ifindex != 0 {
                t.ifindex = s.ifindex;
            }
            t.hist.push_back(w);
            while t.hist.len() > hist_len {
                t.hist.pop_front();
            }
            t.idle_ticks = if pkts == 0 { t.idle_ticks + 1 } else { 0 };
        }
        // The BPF exit hook deletes a process's map entry, so a track that
        // vanished belongs to a process that exited. Forget it at once, so a
        // later process reusing the pid starts from scratch. The session's
        // own process is kept: the session logic decides when it is over.
        let session_tgid = self.session.as_ref().map(|s| s.info.tgid);
        let gone: Vec<u32> = self
            .tracks
            .keys()
            .copied()
            .filter(|tgid| !seen.contains(tgid) && Some(*tgid) != session_tgid)
            .collect();
        for tgid in gone {
            self.tracks.remove(&tgid);
            self.ignored.remove(&tgid);
        }
        if let Some(t) = session_tgid
            .filter(|tgid| !seen.contains(tgid))
            .and_then(|tgid| self.tracks.get_mut(&tgid))
        {
            t.hist.push_back(Window::default());
            while t.hist.len() > hist_len {
                t.hist.pop_front();
            }
            t.idle_ticks += 1;
        }
        self.tracks
            .retain(|tgid, t| Some(*tgid) == session_tgid || t.idle_ticks < 60);
        self.ignored.retain(|_, until| *until > now);

        // 2. Advance the active session, if any.
        if let Some(a) = self.advance_session(now, dt, procs) {
            actions.push(a);
        }

        // 3. Look for a new session.
        let cfg = &self.cfg;
        let mut candidates = Vec::new();
        for (&tgid, t) in self.tracks.iter_mut() {
            let l = t.last();
            let steady_now = !t.hist.is_empty()
                && t.smooth() >= cfg.min_pps as f64
                && l.tx_pps >= cfg.min_dir_pps as f64
                && l.rx_pps >= cfg.min_dir_pps as f64
                && l.avg_size <= cfg.max_avg_packet as f64
                && t.jitter() <= cfg.max_jitter;
            t.steady = if steady_now { t.steady + 1 } else { 0 };
            if t.steady >= cfg.steady_windows && Some(tgid) != session_tgid {
                candidates.push((tgid, t.smooth(), t.smooth_dirs(), t.ifindex));
            }
        }
        if self.session.is_some() {
            return actions;
        }
        // Busiest candidate first.
        candidates.sort_by(|a, b| b.1.total_cmp(&a.1));
        for (tgid, pps, (tx_pps, rx_pps), ifindex) in candidates {
            if self.ignored.contains_key(&tgid) {
                continue;
            }
            let (verdict, name) = procs.verdict(tgid);
            let excluded = matches!(verdict, Verdict::Excluded(_));
            match verdict {
                Verdict::Game(reason) => {
                    let tier = self
                        .cfg
                        .pin_tier
                        .unwrap_or_else(|| tier_for(&self.cfg, Tier::Casual, pps));
                    let info = SessionInfo {
                        tgid,
                        name,
                        reason,
                        tier,
                        pps,
                        tx_pps,
                        rx_pps,
                        ifindex,
                        peak_tier: tier,
                        peak_pps: pps,
                    };
                    self.session = Some(Session {
                        info: info.clone(),
                        candidate: tier,
                        confidence: 1,
                        last_change: now,
                        quiet_secs: 0.0,
                    });
                    actions.push(Action::Start(info));
                    break;
                }
                Verdict::NotGame(reason) | Verdict::Excluded(reason) => {
                    // Don't re-ask the classifier every second.
                    self.ignored.insert(tgid, now + 30.0);
                    actions.push(Action::Ignored {
                        tgid,
                        name,
                        reason,
                        pps,
                        excluded,
                    });
                }
            }
        }
        actions
    }

    /// Close the session, handing its final state to the caller.
    fn end(&mut self, reason: String) -> Option<Action> {
        let s = self.session.take()?;
        Some(Action::End {
            session: s.info,
            reason,
        })
    }

    fn advance_session(
        &mut self,
        now: f64,
        dt: f64,
        procs: &mut dyn ProcessLookup,
    ) -> Option<Action> {
        let sess = self.session.as_mut()?;
        let tgid = sess.info.tgid;
        let Some(t) = self.tracks.get(&tgid) else {
            return self.end("process gone".into());
        };
        let last = t.last();
        let pps = t.smooth();
        let idle = t.idle_ticks > 0;
        sess.info.pps = pps;
        sess.info.peak_pps = sess.info.peak_pps.max(pps);
        (sess.info.tx_pps, sess.info.rx_pps) = t.smooth_dirs();
        if t.ifindex != 0 {
            sess.info.ifindex = t.ifindex;
        }

        if last.total() <= self.cfg.idle_pps as f64 {
            sess.quiet_secs += dt;
            let quiet = sess.quiet_secs;
            if idle && !procs.alive(tgid) {
                return self.end("game exited".into());
            }
            if quiet >= self.cfg.linger_secs as f64 {
                return self.end(format!("netcode quiet for {}s", quiet.round()));
            }
            return None;
        }
        sess.quiet_secs = 0.0;
        if self.cfg.pin_tier.is_some() {
            return None;
        }

        let reported = sess.info.tier;
        let mut cand = tier_for(&self.cfg, reported, pps);
        // Still playing: don't drop back to CASUAL mid-match.
        if cand == Tier::Casual && reported > Tier::Casual && pps > self.cfg.idle_pps as f64 {
            cand = reported;
        }
        if cand != sess.candidate {
            sess.candidate = cand;
            sess.confidence = 1;
        } else if sess.confidence < CONFIDENCE_TO_CASUAL {
            sess.confidence += 1;
        }
        if cand == reported || now - sess.last_change < self.cfg.dwell_secs as f64 {
            return None;
        }
        let required = if cand > reported {
            CONFIDENCE_UP
        } else if cand == Tier::Casual {
            CONFIDENCE_TO_CASUAL
        } else {
            CONFIDENCE_DOWN
        };
        if sess.confidence < required {
            return None;
        }
        sess.info.tier = cand;
        sess.info.peak_tier = sess.info.peak_tier.max(cand);
        sess.last_change = now;
        Some(Action::Retier {
            from: reported,
            to: cand,
        })
    }

    /// The BPF exit hook fired for a watched process.
    pub fn on_exit(&mut self, tgid: u32) -> Option<Action> {
        self.tracks.remove(&tgid);
        if self.session()?.tgid != tgid {
            return None;
        }
        self.end("game exited".into())
    }

    /// Drop the session without an End action (used on shutdown).
    pub fn take_session(&mut self) -> Option<SessionInfo> {
        self.session.take().map(|s| s.info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeProcs {
        games: Vec<u32>,
        excluded: Vec<u32>,
        dead: Vec<u32>,
    }

    impl ProcessLookup for FakeProcs {
        fn verdict(&mut self, tgid: u32) -> (Verdict, String) {
            if self.games.contains(&tgid) {
                (Verdict::Game("test".into()), format!("game{tgid}"))
            } else if self.excluded.contains(&tgid) {
                (Verdict::Excluded("test".into()), format!("proc{tgid}"))
            } else {
                (Verdict::NotGame("test".into()), format!("proc{tgid}"))
            }
        }
        fn alive(&mut self, tgid: u32) -> bool {
            !self.dead.contains(&tgid)
        }
    }

    /// Drive the detector with constant per-second rates.
    struct Sim {
        det: Detector,
        now: f64,
        counters: HashMap<u32, Sample>,
        procs: FakeProcs,
    }

    impl Sim {
        fn new(games: &[u32]) -> Self {
            Self {
                det: Detector::new(Detect::default()),
                now: 0.0,
                counters: HashMap::new(),
                procs: FakeProcs {
                    games: games.to_vec(),
                    excluded: vec![],
                    dead: vec![],
                },
            }
        }

        /// rates: (tgid, tx_pps, rx_pps, payload bytes)
        fn step(&mut self, rates: &[(u32, u64, u64, u64)]) -> Vec<Action> {
            for &(tgid, tx, rx, size) in rates {
                let c = self.counters.entry(tgid).or_insert(Sample {
                    tgid,
                    ..Default::default()
                });
                c.tx_pkts += tx;
                c.rx_pkts += rx;
                c.tx_bytes += tx * size;
                c.rx_bytes += rx * size;
            }
            self.now += 1.0;
            let samples: Vec<Sample> = self.counters.values().copied().collect();
            self.det.tick(self.now, 1.0, &samples, &mut self.procs)
        }

        fn run(&mut self, secs: usize, rates: &[(u32, u64, u64, u64)]) -> Vec<Action> {
            (0..secs).flat_map(|_| self.step(rates)).collect()
        }

        /// The process exits: BPF deletes its map entry.
        fn exit(&mut self, tgid: u32) {
            self.counters.remove(&tgid);
        }
    }

    fn starts(a: &[Action]) -> Vec<&SessionInfo> {
        a.iter()
            .filter_map(|a| match a {
                Action::Start(i) => Some(i),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn tick_rate_game_starts_competitive_session() {
        let mut sim = Sim::new(&[42]);
        // 64-tick shooter: 64 up, 64 down, ~180 byte payloads
        // first tick is a baseline, then 3 steady windows
        assert!(starts(&sim.run(3, &[(42, 64, 64, 180)])).is_empty());
        let a = sim.run(1, &[(42, 64, 64, 180)]);
        let s = starts(&a);
        assert_eq!(s.len(), 1, "{a:?}");
        assert_eq!(s[0].tgid, 42);
        assert_eq!(s[0].tier, Tier::Competitive); // 128 pps total
    }

    #[test]
    fn high_tick_goes_intense_and_quiet_ends() {
        let mut sim = Sim::new(&[7]);
        let a = sim.run(4, &[(7, 128, 128, 120)]);
        assert_eq!(starts(&a).len(), 1, "{a:?}");
        assert_eq!(starts(&a)[0].tier, Tier::Intense);
        // match over: back in menus with a trickle
        let a = sim.run(20, &[(7, 1, 1, 80)]);
        assert!(a.iter().any(|x| matches!(x, Action::End { .. })), "{a:?}");
        assert!(sim.det.session().is_none());
    }

    #[test]
    fn discord_like_traffic_is_ignored_not_started() {
        let mut sim = Sim::new(&[]);
        // 50 pkt/s each way Opus: steady, small, bidirectional
        let a = sim.run(5, &[(99, 50, 50, 120)]);
        assert!(starts(&a).is_empty());
        let ign: Vec<_> = a
            .iter()
            .filter(|x| matches!(x, Action::Ignored { .. }))
            .collect();
        assert_eq!(ign.len(), 1, "should be logged once: {a:?}");
    }

    #[test]
    fn bulk_and_one_way_traffic_never_qualify() {
        let mut sim = Sim::new(&[1, 2, 3]);
        // QUIC download: big packets
        // mDNS-ish: one way only
        // bursty: on/off
        let mut acts = Vec::new();
        for i in 0..10 {
            let burst = if i % 2 == 0 { 400 } else { 0 };
            acts.extend(sim.step(&[(1, 40, 900, 1350), (2, 60, 0, 90), (3, burst, burst, 200)]));
        }
        assert!(starts(&acts).is_empty(), "{acts:?}");
    }

    #[test]
    fn tier_moves_up_with_confidence_and_dwell_and_never_to_casual() {
        let mut sim = Sim::new(&[5]);
        let a = sim.run(4, &[(5, 50, 50, 150)]);
        assert_eq!(starts(&a)[0].tier, Tier::Competitive);
        // jump to 300 pps: should need dwell (5s) + 3 confident windows
        let a = sim.run(2, &[(5, 150, 150, 150)]);
        assert!(!a.iter().any(|x| matches!(x, Action::Retier { .. })));
        let a = sim.run(6, &[(5, 150, 150, 150)]);
        assert!(
            a.iter().any(|x| matches!(
                x,
                Action::Retier {
                    from: Tier::Competitive,
                    to: Tier::Intense
                }
            )),
            "{a:?}"
        );
        // drop to 30 pps (would be CASUAL): only falls to COMPETITIVE
        let a = sim.run(20, &[(5, 15, 15, 150)]);
        assert!(
            a.iter().any(|x| matches!(
                x,
                Action::Retier {
                    from: Tier::Intense,
                    to: Tier::Competitive
                }
            )),
            "{a:?}"
        );
        assert!(
            !a.iter().any(|x| matches!(
                x,
                Action::Retier {
                    to: Tier::Casual,
                    ..
                }
            )),
            "{a:?}"
        );
        assert_eq!(sim.det.session().unwrap().tier, Tier::Competitive);
    }

    #[test]
    fn exit_event_ends_immediately() {
        let mut sim = Sim::new(&[8]);
        sim.run(4, &[(8, 64, 64, 100)]);
        assert!(sim.det.session().is_some());
        assert!(matches!(sim.det.on_exit(8), Some(Action::End { .. })));
        assert!(sim.det.on_exit(8).is_none());
    }

    #[test]
    fn busiest_game_wins_and_other_noise_does_not_matter() {
        let mut sim = Sim::new(&[10, 11]);
        let a = sim.run(
            4,
            &[(10, 30, 30, 100), (11, 64, 64, 100), (12, 5000, 5000, 1300)],
        );
        let s = starts(&a);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].tgid, 11);
    }

    #[test]
    fn reused_pid_starts_fresh() {
        // pid 77: a busy non-game (rejected), then it exits and a game that
        // happens to get the same pid starts at a casual 60 pkt/s.
        let mut sim = Sim::new(&[]);
        let a = sim.run(5, &[(77, 100, 100, 150)]);
        assert!(a.iter().any(|x| matches!(x, Action::Ignored { .. })));
        sim.exit(77);
        sim.run(1, &[]);
        sim.procs.games.push(77);
        // baseline tick + 3 steady windows; no stale history or ignore entry
        assert!(starts(&sim.run(3, &[(77, 30, 30, 150)])).is_empty());
        let a = sim.run(1, &[(77, 30, 30, 150)]);
        let s = starts(&a);
        assert_eq!(s.len(), 1, "{a:?}");
        assert_eq!(
            s[0].tier,
            Tier::Casual,
            "must not inherit the old process's 200 pkt/s"
        );
        assert!((s[0].pps - 60.0).abs() < 1.0, "{}", s[0].pps);
    }

    #[test]
    fn pid_reused_within_one_tick_resets_via_counter_regression() {
        let mut sim = Sim::new(&[]);
        sim.run(5, &[(88, 100, 100, 150)]);
        // entry deleted and recreated between two reads: counters go backwards
        sim.counters.insert(
            88,
            Sample {
                tgid: 88,
                tx_pkts: 3,
                rx_pkts: 3,
                tx_bytes: 300,
                rx_bytes: 300,
                ifindex: 0,
            },
        );
        sim.procs.games.push(88);
        sim.now += 1.0;
        let samples: Vec<Sample> = sim.counters.values().copied().collect();
        assert!(
            sim.det
                .tick(sim.now, 1.0, &samples, &mut sim.procs)
                .is_empty()
        );
        assert!(starts(&sim.run(2, &[(88, 30, 30, 150)])).is_empty());
        let s = sim.run(1, &[(88, 30, 30, 150)]);
        assert_eq!(starts(&s).len(), 1, "{s:?}");
        assert_eq!(starts(&s)[0].tier, Tier::Casual);
    }

    #[test]
    fn pinned_tier_sticks() {
        let mut sim = Sim::new(&[3]);
        sim.det = Detector::new(Detect {
            pin_tier: Some(Tier::Intense),
            ..Detect::default()
        });
        let a = sim.run(4, &[(3, 30, 30, 100)]);
        assert_eq!(starts(&a)[0].tier, Tier::Intense);
        let a = sim.run(10, &[(3, 15, 15, 100)]);
        assert!(!a.iter().any(|x| matches!(x, Action::Retier { .. })));
    }

    #[test]
    fn hysteresis_matches_original_thresholds() {
        let cfg = Detect::default();
        assert_eq!(
            thresholds(&cfg),
            Thresholds {
                competitive_up: 85.0,
                competitive_down: 55.0,
                intense_up: 155.0,
                intense_down: 125.0,
            }
        );
        use Tier::*;
        for (current, pps, want) in [
            (Casual, 84.0, Casual),
            (Casual, 85.0, Competitive),
            (Casual, 155.0, Intense),
            (Competitive, 60.0, Competitive),
            (Competitive, 55.0, Casual),
            (Competitive, 155.0, Intense),
            (Intense, 130.0, Intense),
            (Intense, 125.0, Competitive),
        ] {
            assert_eq!(tier_for(&cfg, current, pps), want, "{current} @ {pps}");
        }
    }

    #[test]
    fn end_carries_the_final_session_and_its_peak() {
        let mut sim = Sim::new(&[9]);
        sim.run(4, &[(9, 50, 50, 150)]);
        sim.run(12, &[(9, 150, 150, 150)]);
        let a = sim.run(1, &[(9, 50, 50, 150)]);
        assert!(a.is_empty(), "{a:?}");
        sim.procs.dead.push(9);
        sim.exit(9);
        let a = sim.run(1, &[]);
        match &a[..] {
            [Action::End { session, reason }] => {
                assert_eq!(session.tgid, 9);
                assert_eq!(session.peak_tier, Tier::Intense);
                assert!(session.peak_pps >= 290.0, "{}", session.peak_pps);
                assert_eq!(reason, "game exited");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn excluded_processes_are_flagged() {
        let mut sim = Sim::new(&[]);
        sim.procs.excluded.push(99);
        let a = sim.run(5, &[(99, 50, 50, 120), (98, 50, 50, 120)]);
        let flags: Vec<(u32, bool)> = a
            .iter()
            .filter_map(|x| match x {
                Action::Ignored { tgid, excluded, .. } => Some((*tgid, *excluded)),
                _ => None,
            })
            .collect();
        assert!(
            flags.contains(&(99, true)) && flags.contains(&(98, false)),
            "{flags:?}"
        );
    }
}
