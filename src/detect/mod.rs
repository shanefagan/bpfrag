// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Match detection: deciding from per-process UDP counters when a game's
//! netcode is running, which tier it is in, and when the match is over.
//!
//! - this file: the [`Detector`], fed one window of counters per tick;
//! - `track`: each process's traffic over the last few windows;
//! - [`classify`]: "is this process a game?";
//! - [`egress`]: which network links the game's packets actually use.
//! - [`observe`] and [`tagged`]: TCP games (`tcp = "tune"` or "observe")
//!   and processes tagged `BPFRAG_OBSERVE=1`.
//!
//! A game that talks TCP (Path of Exile 2) has no UDP for any of the below.
//! The daemon's TCP observer decides that its traffic looks like a
//! multiplayer game's, and [`Detector::start_tcp`] makes it a match at the
//! competitive tier, with none of the UDP logic: it lasts until the game
//! exits or its TCP goes quiet ([`Detector::end_tcp`]).
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
//! And one more check, with [`Detector::with_paths`]: a game's traffic only
//! counts if it reaches the network. Some games talk to a server of their
//! own over loopback in their menus and between matches (Deadlock does,
//! about 128 packets a second each way), which looks like a match by rate
//! alone. So a candidate is first *watched*: the daemon feeds the arrival
//! meter's counts ([`Arrivals`]: from outside, and on loopback), and only
//! traffic from outside starts a match. A match whose traffic stays on the
//! machine for 6 seconds (or `linger_secs` if shorter) ends, and the game
//! goes back to being watched
//! until outside traffic returns, so back-to-back games are separate
//! matches and menu time isn't tuned.
//!
//! Kept from the original: packets-per-second smoothing over a short history,
//! a variance gate, CASUAL/COMPETITIVE/INTENSE tiers with a hysteresis margin,
//! asymmetric confidence for up/down changes, a dwell time between changes,
//! and "never fall back to CASUAL while traffic is still flowing".

pub mod bulk;
pub mod classify;
pub mod egress;
pub mod observe;
pub mod tagged;
mod track;

use std::collections::{HashMap, VecDeque};

use crate::config::{Detect, Tier};
use classify::Verdict;
pub use track::{Sample, Window};
use track::{Track, tick_pps};

/// Windows whose median decides whether the game has gone quiet (back in
/// the menus): enough that short bursts of relay pings don't count.
const QUIET_WINDOWS: usize = 5;

/// Windows a watched game gets before its traffic counts as local...
const CONFIRM_WINDOWS: u32 = 3;
/// ...or, if the meter sees it nowhere, as a match anyway (the rate alone
/// decides, as before paths were checked).
const UNSEEN_WINDOWS: u32 = 2;

/// Seconds of the match's traffic staying on this machine (the game back
/// in its menu) that end a match: shorter than `linger_secs`, since the
/// next game can start 12 seconds later (2026-11-02, Deadlock: two games
/// counted as one when the menu was quicker than 15 s). Relay changes
/// mid-game don't go through loopback at all.
const LOCAL_END_SECS: f64 = 6.0;
/// The game's own TCP in a second that means it's loading, and how long
/// after the last such second quiet UDP doesn't end the match.
const LOAD_BPS: f64 = 1_000_000.0;
const LOAD_GRACE_SECS: f64 = 30.0;

/// Seconds a game whose menu was set aside for another game isn't taken
/// up again: two games in their menus would otherwise swap places every
/// few seconds.
const PASS_OVER_SECS: f64 = 60.0;

/// Readings in a row with traffic before a quiet spell counts as over.
const RESUME_WINDOWS: usize = 3;

/// Seconds a process the classifier turned down isn't asked about again.
const IGNORE_SECS: f64 = 30.0;

/// Windows without a packet after which a process's history is dropped.
const FORGET_IDLE_WINDOWS: u32 = 60;

/// Consecutive windows that must agree on a higher tier before it is
/// applied. Tiers only go up within a match.
const CONFIDENCE_UP: u32 = 3;

/// Where one window of the watched game's traffic arrived, per the arrival
/// meter: packets a second from outside (a real interface) and on loopback.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Arrivals {
    pub outside_pps: f64,
    pub local_pps: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Where {
    /// Traffic from outside: a match.
    Outside,
    /// The game talking to itself.
    Local,
    /// The meter sees neither (not measured, or a path it isn't on).
    Unknown,
}

/// Where the last `n` windows of traffic went, by their medians.
fn where_now(paths: &VecDeque<Arrivals>, n: usize, idle_pps: f64) -> Where {
    let med = |f: fn(&Arrivals) -> f64| {
        let mut v: Vec<f64> = paths.iter().rev().take(n).map(f).collect();
        if v.is_empty() {
            return 0.0;
        }
        v.sort_by(f64::total_cmp);
        v[v.len() / 2]
    };
    if med(|p| p.outside_pps) >= idle_pps {
        Where::Outside
    } else if med(|p| p.local_pps) >= idle_pps {
        Where::Local
    } else {
        Where::Unknown
    }
}

/// How the match's game talks to its server.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Transport {
    #[default]
    Udp,
    /// A game that talks TCP: detected by the TCP observer, not the UDP
    /// logic, and held at one tier until it stops.
    Tcp,
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Transport::Udp => "UDP",
            Transport::Tcp => "TCP",
        })
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
    /// When the match's traffic began, and when it was last seen, on the
    /// detector's clock (`now`). Both are earlier than the Start and End
    /// actions, which wait for the traffic to settle: a recording can be
    /// cut by these.
    pub began: f64,
    pub last_seen: f64,
    pub transport: Transport,
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
    /// A game's traffic: watch where it goes (the arrival meter on its
    /// ports, nothing tuned) before calling it a match. `ifindex` is its
    /// connected socket's device, if known.
    Watch {
        tgid: u32,
        name: String,
        ifindex: u32,
    },
    /// Stop watching it: it exited, or went quiet.
    Unwatch {
        tgid: u32,
    },
    /// A watched game's traffic stays on this machine: no match until
    /// traffic from outside starts.
    Local {
        tgid: u32,
        name: String,
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
    /// When the game last loaded something over TCP (a megabyte or more
    /// in a second), on the detector's clock.
    last_load: f64,
    /// Seconds the match's traffic has stayed on this machine.
    local_secs: f64,
    /// Traffic from outside has been measured in this match, so it's what
    /// `last_seen` follows.
    saw_outside: bool,
}

/// A game being watched, not (yet) a match.
#[derive(Debug)]
struct Watched {
    tgid: u32,
    name: String,
    reason: String,
    /// Windows since watching started.
    windows: u32,
    /// Its traffic was found to stay on this machine.
    local: bool,
    quiet_secs: f64,
    /// When its steady traffic began, and the current run of windows with
    /// traffic from outside, on the detector's clock.
    since: f64,
    outside_since: Option<f64>,
}

/// A process whose traffic has looked like netcode for long enough to ask
/// the classifier about.
struct Candidate {
    tgid: u32,
    /// Mean packets a second over its history, and the same per direction
    /// (sent, received).
    pps: f64,
    dirs: (f64, f64),
    ifindex: u32,
    /// When its steady traffic began (monotonic seconds).
    began: f64,
}

/// What the detector needs to know about a process. In the daemon this is
/// [`classify::ProcfsLookup`]; tests use a fake, so the detector itself
/// never touches /proc.
pub trait ProcessLookup {
    /// Is this process a game, and what should we call it?
    fn verdict(&mut self, tgid: u32) -> (Verdict, String);
    /// Does the process still exist?
    fn alive(&mut self, tgid: u32) -> bool;
    /// Seconds since the process started, if known.
    fn age_secs(&mut self, _tgid: u32) -> Option<f64> {
        None
    }
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
    /// Watch candidates' paths before starting a match.
    check_paths: bool,
    watched: Option<Watched>,
    /// The watched game's or the match's recent paths.
    paths: VecDeque<Arrivals>,
    pending_paths: Option<Arrivals>,
    /// The match's traffic with peers other than its server, for the
    /// next window ([`Detector::others`]).
    pending_others: f64,
    /// Games whose menu was set aside for another game, and until when.
    passed_over: HashMap<u32, f64>,
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
            check_paths: false,
            watched: None,
            paths: VecDeque::new(),
            pending_paths: None,
            pending_others: 0.0,
            passed_over: HashMap::new(),
        }
    }

    /// Only start a match on traffic from outside: candidates are watched
    /// first, and fed [`Detector::paths`] every window.
    pub fn with_paths(mut self) -> Self {
        self.check_paths = true;
        self
    }

    pub fn session(&self) -> Option<&SessionInfo> {
        self.session.as_ref().map(|s| &s.info)
    }

    /// The game being watched without a match, and whether its traffic was
    /// found to stay on this machine.
    pub fn watched(&self) -> Option<(u32, &str, bool)> {
        self.watched
            .as_ref()
            .map(|w| (w.tgid, w.name.as_str(), w.local))
    }

    /// Does the detector want this window's [`Arrivals`]?
    pub fn wants_paths(&self) -> bool {
        self.check_paths && (self.session.is_some() || self.watched.is_some())
    }

    /// Packets a second the match exchanged with peers other than its
    /// server ([`crate::health::Tracker::others_pps`]), before
    /// [`Detector::tick`]: left out of the rate its tier is judged on.
    pub fn others(&mut self, pps: f64) {
        self.pending_others = pps;
    }

    /// This window's paths for the watched game or the match, before
    /// [`Detector::tick`].
    pub fn paths(&mut self, p: Arrivals) {
        self.pending_paths = Some(p);
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
        let dt = dt.max(0.001);
        if let Some(mut p) = self.pending_paths.take() {
            // During a match, what arrives from peers other than its server
            // (a relay the game left, still pinging it) isn't the match:
            // judged as outside traffic, it held a match open on the end
            // screen (2026-11-11 12:59).
            if self.session.is_some() {
                p.outside_pps = (p.outside_pps - self.pending_others).max(0.0);
            }
            self.paths.push_back(p);
            while self.paths.len() > 2 * QUIET_WINDOWS {
                self.paths.pop_front();
            }
        }
        self.update_tracks(now, dt, samples);
        let mut actions = self.advance_session(now, dt, procs);
        actions.extend(self.advance_watch(now, dt, procs));
        let candidates = self.candidates(now, dt);
        actions.extend(self.consider(now, candidates, procs));
        actions
    }

    /// The process of the match, or failing that of the watched game.
    fn current_tgid(&self) -> Option<u32> {
        self.session
            .as_ref()
            .map(|s| s.info.tgid)
            .or(self.watched.as_ref().map(|w| w.tgid))
    }

    /// Step 1 of a tick: every process's history gets this window, and
    /// processes that have gone are forgotten.
    fn update_tracks(&mut self, now: f64, dt: f64, samples: &[Sample]) {
        let hist_len = self.cfg.history;
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
            // Packets to and from peers other than the server are only
            // known for the game of the match.
            let others_pps = if self.session.as_ref().is_some_and(|x| x.info.tgid == s.tgid) {
                std::mem::take(&mut self.pending_others)
            } else {
                0.0
            };
            t.advance(s, dt, others_pps, hist_len);
        }
        // The BPF exit hook deletes a process's map entry, so a track that
        // vanished belongs to a process that exited. Forget it at once, so a
        // later process reusing the pid starts from scratch. The session's
        // own process is kept: the session logic decides when it is over.
        let current = self.current_tgid();
        let gone: Vec<u32> = self
            .tracks
            .keys()
            .copied()
            .filter(|tgid| !seen.contains(tgid) && Some(*tgid) != current)
            .collect();
        for tgid in gone {
            self.tracks.remove(&tgid);
            self.ignored.remove(&tgid);
        }
        if let Some(t) = current
            .filter(|tgid| !seen.contains(tgid))
            .and_then(|tgid| self.tracks.get_mut(&tgid))
        {
            t.push(Window::default(), hist_len);
            t.idle_ticks += 1;
        }
        self.tracks
            .retain(|tgid, t| Some(*tgid) == current || t.idle_ticks < FORGET_IDLE_WINDOWS);
        self.ignored.retain(|_, until| *until > now);
    }

    /// Step 3 of a tick, first half: the processes whose traffic has looked
    /// like netcode for long enough, other than the one already in hand.
    fn candidates(&mut self, now: f64, dt: f64) -> Vec<Candidate> {
        let current = self.current_tgid();
        let cfg = &self.cfg;
        let mut candidates = Vec::new();
        for (&tgid, t) in self.tracks.iter_mut() {
            t.steady = if t.looks_like_netcode(cfg) {
                t.steady + 1
            } else {
                0
            };
            if t.steady >= cfg.steady_windows && Some(tgid) != current {
                candidates.push(Candidate {
                    tgid,
                    pps: t.smooth(),
                    dirs: t.smooth_dirs(),
                    ifindex: t.ifindex,
                    began: now - f64::from(t.steady) * dt,
                });
            }
        }
        // Busiest first.
        candidates.sort_by(|a, b| b.pps.total_cmp(&a.pps));
        candidates
    }

    /// Step 3 of a tick, second half: ask the classifier about each
    /// candidate, and watch (or start a match for) the first that is a game.
    fn consider(
        &mut self,
        now: f64,
        candidates: Vec<Candidate>,
        procs: &mut dyn ProcessLookup,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        // A game sitting in its menu (its traffic stays on this machine) is
        // watched for as long as it runs; another game with traffic of its
        // own can take the watch from it, or only the first game opened
        // would ever be tuned.
        let menu_only = self.watched.as_ref().is_some_and(|w| w.local);
        if self.session.is_some() || (self.watched.is_some() && !menu_only) {
            return actions;
        }
        self.passed_over.retain(|_, until| *until > now);
        for c in candidates {
            let tgid = c.tgid;
            if self.ignored.contains_key(&tgid) || self.passed_over.contains_key(&tgid) {
                continue;
            }
            let (verdict, name) = procs.verdict(tgid);
            let excluded = matches!(verdict, Verdict::Excluded(_));
            match verdict {
                Verdict::Game(reason) if self.check_paths => {
                    if let Some(old) = self.watched.take() {
                        self.passed_over.insert(old.tgid, now + PASS_OVER_SECS);
                        actions.push(Action::Unwatch { tgid: old.tgid });
                    }
                    self.paths.clear();
                    self.watched = Some(Watched {
                        tgid,
                        name: name.clone(),
                        reason,
                        windows: 0,
                        local: false,
                        quiet_secs: 0.0,
                        since: c.began,
                        outside_since: None,
                    });
                    actions.push(Action::Watch {
                        tgid,
                        name,
                        ifindex: c.ifindex,
                    });
                    break;
                }
                Verdict::Game(reason) => {
                    actions.push(
                        self.start(now, c.began, tgid, name, reason, c.pps, c.dirs, c.ifindex),
                    );
                    break;
                }
                Verdict::NotGame(reason) | Verdict::Excluded(reason) => {
                    // Don't re-ask the classifier every second.
                    self.ignored.insert(tgid, now + IGNORE_SECS);
                    actions.push(Action::Ignored {
                        tgid,
                        name,
                        reason,
                        pps: c.pps,
                        excluded,
                    });
                }
            }
        }
        actions
    }

    #[allow(clippy::too_many_arguments)]
    fn start(
        &mut self,
        now: f64,
        began: f64,
        tgid: u32,
        name: String,
        reason: String,
        pps: f64,
        (tx_pps, rx_pps): (f64, f64),
        ifindex: u32,
    ) -> Action {
        let tier = self.cfg.pin_tier.unwrap_or_else(|| {
            let rate = self
                .tracks
                .get(&tgid)
                .map_or_else(|| tick_pps((tx_pps, rx_pps)), Track::tick_rate);
            tier_for(&self.cfg, Tier::Casual, rate)
        });
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
            began,
            last_seen: now,
            transport: Transport::Udp,
        };
        self.paths.clear();
        self.session = Some(Session {
            info: info.clone(),
            candidate: tier,
            confidence: 1,
            last_change: now,
            quiet_secs: 0.0,
            last_load: f64::NEG_INFINITY,
            local_secs: 0.0,
            saw_outside: false,
        });
        Action::Start(info)
    }

    /// The watched game: start a match once traffic arrives from outside,
    /// note when it stays on this machine, let it go when it exits or goes
    /// quiet.
    fn advance_watch(&mut self, now: f64, dt: f64, procs: &mut dyn ProcessLookup) -> Vec<Action> {
        let idle = self.cfg.idle_pps as f64;
        let Some(w) = self.watched.as_mut() else {
            return Vec::new();
        };
        let tgid = w.tgid;
        let unwatch = |me: &mut Self| {
            me.watched = None;
            me.paths.clear();
            vec![Action::Unwatch { tgid }]
        };
        let Some(t) = self.tracks.get(&tgid) else {
            return unwatch(self);
        };
        if t.idle_ticks > 0 && !procs.alive(tgid) {
            return unwatch(self);
        }
        w.windows += 1;
        if t.recent_median(QUIET_WINDOWS) <= idle {
            w.quiet_secs += dt;
            if w.quiet_secs >= self.cfg.linger_secs as f64 {
                return unwatch(self);
            }
        } else {
            w.quiet_secs = 0.0;
        }
        let latest = self.paths.back().copied().unwrap_or_default();
        if latest.outside_pps >= idle {
            w.outside_since.get_or_insert(now - dt);
        } else {
            w.outside_since = None;
        }
        // Traffic from outside in two of the last three windows, and more
        // of it than the game sends itself over loopback: Deadlock checks
        // in with Steam's relays as it starts, for a second or two, while
        // its menu runs at 128 a second over loopback (a 10-second
        // "match" on 2026-11-04). In a match the menu server is quiet.
        let outside_windows = self
            .paths
            .iter()
            .rev()
            .take(3)
            .filter(|p| p.outside_pps >= idle && p.outside_pps >= p.local_pps)
            .count();
        let go = if w.local {
            // back from a menu: two windows in three from outside
            outside_windows >= 2
        } else if outside_windows >= 2 {
            true
        } else if outside_windows == 1 {
            false
        } else {
            match where_now(&self.paths, w.windows as usize, idle) {
                Where::Local if w.windows >= CONFIRM_WINDOWS => {
                    w.local = true;
                    return vec![Action::Local {
                        tgid,
                        name: w.name.clone(),
                    }];
                }
                Where::Local => false,
                // traffic the meter can't see at all: the old rule
                Where::Unknown => w.windows >= UNSEEN_WINDOWS,
                // some from outside, but less than over loopback
                Where::Outside => false,
            }
        };
        if !go {
            return Vec::new();
        }
        // Deadlock pings a few of Steam's relays for a few seconds as it
        // launches, sometimes before its menu server is up, so there's
        // no loopback to outweigh them (a 10-second "match" at 11:18 on
        // 2026-11-06). No game is in a match seconds after starting.
        if procs
            .age_secs(tgid)
            .is_some_and(|a| a < self.cfg.launch_secs as f64)
        {
            return Vec::new();
        }
        let w = self.watched.take().expect("watched");
        // Traffic from outside began with this run of windows; a game the
        // meter can't see began when its steady traffic did.
        let began = w
            .outside_since
            .unwrap_or(if w.local { now - dt } else { w.since });
        // The match starts with this window: earlier ones may be the game
        // talking to itself (a menu at 256 pkt/s would make it INTENSE).
        let Some(t) = self.tracks.get_mut(&tgid) else {
            return Vec::new();
        };
        while t.hist.len() > 1 {
            t.hist.pop_front();
        }
        let pps = t.smooth();
        let dirs = t.smooth_dirs();
        let ifindex = t.ifindex;
        vec![self.start(now, began, tgid, w.name, w.reason, pps, dirs, ifindex)]
    }

    /// Close the session, handing its final state to the caller.
    fn end(&mut self, reason: String) -> Option<Action> {
        let s = self.session.take()?;
        Some(Action::End {
            session: s.info,
            reason,
        })
    }

    fn advance_session(&mut self, now: f64, dt: f64, procs: &mut dyn ProcessLookup) -> Vec<Action> {
        let idle_pps = self.cfg.idle_pps as f64;
        let linger = (self.cfg.linger_secs as f64).min(LOCAL_END_SECS);
        let Some(sess) = self.session.as_mut() else {
            return Vec::new();
        };
        if sess.info.transport == Transport::Tcp {
            // Ended by end_tcp() or on_exit(), or by the game starting UDP
            // that looks like a match (TCP in its menus, UDP in play): its
            // UDP then decides, from the next window.
            let tgid = sess.info.tgid;
            let udp = self
                .tracks
                .get(&tgid)
                .is_some_and(|t| t.steady >= self.cfg.steady_windows);
            return if udp {
                self.end("it started talking UDP like a match".into())
                    .into_iter()
                    .collect()
            } else {
                Vec::new()
            };
        }
        let tgid = sess.info.tgid;
        // The match's traffic has stayed on this machine (a menu, a local
        // server): the match is over, but the game is still worth watching.
        if self.check_paths
            && self.paths.len() >= QUIET_WINDOWS
            && where_now(&self.paths, QUIET_WINDOWS, idle_pps) == Where::Local
        {
            sess.local_secs += dt;
            if sess.local_secs >= linger {
                let secs = sess.local_secs.round();
                let (name, reason) = (sess.info.name.clone(), sess.info.reason.clone());
                let mut out: Vec<Action> = self
                    .end(format!(
                        "its traffic stayed on this machine for {secs}s: a menu or a local server"
                    ))
                    .into_iter()
                    .collect();
                self.paths.clear();
                self.watched = Some(Watched {
                    tgid,
                    name: name.clone(),
                    reason,
                    windows: 0,
                    local: true,
                    quiet_secs: 0.0,
                    since: now,
                    outside_since: None,
                });
                let ifindex = self.tracks.get(&tgid).map_or(0, |t| t.ifindex);
                out.push(Action::Watch {
                    tgid,
                    name,
                    ifindex,
                });
                return out;
            }
        } else {
            sess.local_secs = 0.0;
        }
        self.advance_match(now, dt, procs).into_iter().collect()
    }

    fn advance_match(
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
        let pps = t.smooth();
        let idle = t.idle_ticks > 0;
        // The match's traffic: from outside once that's been measured,
        // otherwise any.
        let outside = self.paths.back().map(|p| p.outside_pps);
        let idle_pps = self.cfg.idle_pps as f64;
        if self.check_paths && outside.is_some_and(|o| o >= idle_pps) {
            sess.saw_outside = true;
        }
        let seen = if sess.saw_outside {
            outside.is_some_and(|o| o >= idle_pps)
        } else {
            t.last().total() >= idle_pps
        };
        if seen {
            sess.info.last_seen = now;
        }
        sess.info.pps = pps;
        sess.info.peak_pps = sess.info.peak_pps.max(pps);
        (sess.info.tx_pps, sess.info.rx_pps) = t.smooth_dirs();
        if t.ifindex != 0 {
            sess.info.ifindex = t.ifindex;
        }

        if idle && !procs.alive(tgid) {
            return self.end("game exited".into());
        }
        if t.last().tcp_rx_bps >= LOAD_BPS {
            sess.last_load = now;
        }
        if t.recent_median(QUIET_WINDOWS) <= self.cfg.idle_pps as f64 {
            // the median lags: a window with traffic again doesn't add
            if t.last().total() < self.cfg.idle_pps as f64 {
                sess.quiet_secs += dt;
            }
            let quiet = sess.quiet_secs;
            // A game loading a map over TCP isn't gone: Trackmania went 16
            // seconds without UDP after a 49 MB load, and the session was
            // cut in two (2026-11-07 11:09:18, 2026-11-08 13:44:54).
            let loading = now - sess.last_load < LOAD_GRACE_SECS;
            if quiet >= self.cfg.linger_secs as f64 && !loading {
                return self.end(format!("netcode quiet for {}s", quiet.round()));
            }
            return None;
        }
        // Traffic again. A burst a reading or two long in a quiet spell
        // isn't play resuming (relay pings in a menu come every few seconds,
        // and one burst can fall across two readings): the countdown only
        // starts over once traffic has stayed for RESUME_WINDOWS readings.
        if t.recent_min(RESUME_WINDOWS) > self.cfg.idle_pps as f64 {
            sess.quiet_secs = 0.0;
        }
        if self.cfg.pin_tier.is_some() {
            return None;
        }
        // The game's traffic isn't arriving from outside right now (back in
        // its menu, say): what it sends itself says nothing about the match.
        if sess.saw_outside && !seen {
            return None;
        }

        // Tiers only go up within a match. A game's rate dips with what's
        // happening in it (Deadlock: short stretches at 32 updates a second
        // while the player is dead), so following it down re-applied
        // settings every couple of minutes for nothing; the settings cost
        // nothing to keep until the end.
        let reported = sess.info.tier;
        let cand = tier_for(&self.cfg, reported, t.tick_rate()).max(reported);
        if cand != sess.candidate {
            sess.candidate = cand;
            sess.confidence = 1;
        } else if sess.confidence < CONFIDENCE_UP {
            sess.confidence += 1;
        }
        if cand == reported || now - sess.last_change < self.cfg.dwell_secs as f64 {
            return None;
        }
        if sess.confidence < CONFIDENCE_UP {
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

    /// A game whose TCP looks like a multiplayer game's (the daemon's TCP
    /// observer decides): a match at the competitive tier (or `pin_tier`),
    /// unless there already is one, a UDP game is being checked, or the
    /// process has UDP traffic of its own (a UDP game's side TCP, such as
    /// Deadlock's in its menu: its UDP decides). Taking over from a game
    /// sitting in its menu, the actions are Unwatch, then Start.
    #[allow(clippy::too_many_arguments)]
    pub fn start_tcp(
        &mut self,
        now: f64,
        began: f64,
        tgid: u32,
        name: String,
        reason: String,
        (tx_per_s, rx_per_s): (f64, f64),
        ifindex: u32,
    ) -> Vec<Action> {
        let mut out = Vec::new();
        if self.session.is_some() {
            return out;
        }
        let idle = self.cfg.idle_pps as f64;
        if self
            .tracks
            .get(&tgid)
            .is_some_and(|t| t.recent_median(QUIET_WINDOWS) > idle)
        {
            return out;
        }
        match &self.watched {
            Some(w) if w.tgid == tgid || !w.local => return out,
            Some(w) => {
                out.push(Action::Unwatch { tgid: w.tgid });
                self.watched = None;
            }
            None => {}
        }
        let tier = self.cfg.pin_tier.unwrap_or(Tier::Competitive);
        let pps = tx_per_s + rx_per_s;
        let info = SessionInfo {
            tgid,
            name,
            reason,
            tier,
            pps,
            tx_pps: tx_per_s,
            rx_pps: rx_per_s,
            ifindex,
            peak_tier: tier,
            peak_pps: pps,
            began,
            last_seen: now,
            transport: Transport::Tcp,
        };
        self.paths.clear();
        self.session = Some(Session {
            info: info.clone(),
            candidate: tier,
            confidence: 1,
            last_change: now,
            quiet_secs: 0.0,
            last_load: f64::NEG_INFINITY,
            local_secs: 0.0,
            saw_outside: false,
        });
        out.push(Action::Start(info));
        out
    }

    /// The TCP match's game went quiet (the TCP observer decides): End.
    pub fn end_tcp(&mut self, tgid: u32, reason: String) -> Option<Action> {
        let s = self.session.as_ref()?;
        if s.info.tgid != tgid || s.info.transport != Transport::Tcp {
            return None;
        }
        self.end(reason)
    }

    /// The BPF exit hook fired for a watched process.
    pub fn on_exit(&mut self, tgid: u32) -> Option<Action> {
        self.tracks.remove(&tgid);
        if self.watched.as_ref().is_some_and(|w| w.tgid == tgid) {
            self.watched = None;
            self.paths.clear();
            return Some(Action::Unwatch { tgid });
        }
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
mod tests;
