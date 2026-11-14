// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Watching a game's traffic without tuning anything, so there is data to
//! decide whether, and how, to detect and tune games like it later.
//!
//! - `[detect] tcp = "observe"` or `"tune"`: games that talk TCP (Path of
//!   Exile 2, World of Warcraft, older games). A process counts when the
//!   classifier says it's a game (a launcher parent, a Steam app, a game
//!   path, the allow list) and it keeps talking TCP both ways for
//!   `SEEN_SECS`. With "tune", the daemon then asks [`Observer::recent`]
//!   every second whether its traffic looks like a multiplayer game's
//!   ([`Summary::looks_multiplayer`]), and tunes it like a match if so.
//! - `BPFRAG_OBSERVE=1` in a process's environment ([`super::tagged`]):
//!   its UDP and its TCP, whatever they look like, one way or both. A
//!   session is reported once it has had traffic for `SEEN_SECS`, or when
//!   it moved a lot in less (a map download, say).
//!
//! A session ends after `QUIET_SECS` without traffic, or when the process
//! exits, with a summary: how long, its typical message rates each way,
//! message sizes and how even the rate was. Rates are of send/receive
//! calls, not packets: a TCP call can carry several segments, and one read
//! several messages (a UDP call is one datagram).

use std::collections::{HashMap, HashSet};

use super::Sample;

/// Active seconds before a session is reported.
const SEEN_SECS: u32 = 10;
/// Seconds without traffic before a session is summed up.
pub const QUIET_SECS: u32 = 30;
/// Processes tracked at once; more than this and the rest wait.
const MAX_TRACKED: usize = 64;
/// Per-second rates kept for a session's summary (two hours' worth).
const MAX_SECONDS: usize = 7200;
/// Seconds of a TCP game's traffic judged for "looks like a multiplayer
/// game".
pub const SHAPE_SECS: usize = 10;

/// What a multiplayer game's TCP looks like, from Path of Exile 2
/// (2026-11-14, 21 minutes: the server 30 messages a second of about 160
/// bytes, the client 13 of about 11, rate variation 0.09). A patch or map
/// download moves kilobytes a call and swings in rate; a launcher's or an
/// overlay's connection talks a few times a minute.
const MP_MIN_RX_PER_S: f64 = 5.0;
const MP_MIN_TX_PER_S: f64 = 1.0;
const MP_MAX_SIZE: f64 = 1500.0;
const MP_MAX_VARIATION: f64 = 0.5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Udp,
    Tcp,
}

impl Proto {
    pub fn name(self) -> &'static str {
        match self {
            Proto::Udp => "UDP",
            Proto::Tcp => "TCP",
        }
    }

    /// (send calls, receive calls, bytes sent, bytes received) so far.
    fn counts(self, s: &Sample) -> [u64; 4] {
        match self {
            Proto::Udp => [s.tx_pkts, s.rx_pkts, s.tx_bytes, s.rx_bytes],
            Proto::Tcp => [s.tcp_tx_msgs, s.tcp_rx_msgs, s.tcp_tx_bytes, s.tcp_rx_bytes],
        }
    }
}

/// What an observer watches, and what counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rules {
    pub proto: Proto,
    /// A second is active only with traffic both ways...
    pub two_way: bool,
    /// ...and at least this many calls in total.
    pub min_calls: u64,
    /// Also sum up a session that never reached `SEEN_SECS` if it moved
    /// at least this many bytes.
    pub report_bytes: Option<u64>,
}

impl Rules {
    /// `tcp = "observe"`: steady two-way TCP, like a game's, not a
    /// download's.
    pub const TCP_GAMES: Rules = Rules {
        proto: Proto::Tcp,
        two_way: true,
        min_calls: 2,
        report_bytes: None,
    };

    /// `BPFRAG_OBSERVE=1`: everything the process sends or receives over
    /// `proto`, steady or not, and short transfers of a megabyte or more.
    pub fn tagged(proto: Proto) -> Rules {
        Rules {
            proto,
            two_way: false,
            min_calls: 1,
            report_bytes: Some(1_000_000),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ObsEvent {
    /// A session has been active for `SEEN_SECS`.
    Seen {
        tgid: u32,
        name: String,
        reason: String,
        tx_per_s: f64,
        rx_per_s: f64,
    },
    /// Its session is over.
    Ended { tgid: u32, summary: Summary },
}

/// A session, summed up.
#[derive(Clone, Debug, PartialEq)]
pub struct Summary {
    pub name: String,
    /// Active seconds.
    pub secs: u64,
    /// Median calls per second each way, over the active seconds.
    pub tx_per_s: f64,
    pub rx_per_s: f64,
    /// Mean bytes per call each way.
    pub tx_size: f64,
    pub rx_size: f64,
    /// Mean absolute deviation of the total rate, relative to its mean:
    /// 0 is a metronome (a tick-driven game), a download is far above 1.
    pub jitter: f64,
    pub bytes: u64,
}

impl Summary {
    /// Does this look like a multiplayer game's traffic: messages coming in
    /// several times a second and going out at least once, small, at a
    /// steady rate?
    pub fn looks_multiplayer(&self) -> bool {
        self.rx_per_s >= MP_MIN_RX_PER_S
            && self.tx_per_s >= MP_MIN_TX_PER_S
            && self.rx_size <= MP_MAX_SIZE
            && self.tx_size <= MP_MAX_SIZE
            && self.jitter <= MP_MAX_VARIATION
    }

    /// "Wow.exe for 1h12m03s: typically ...".
    pub fn describe(&self) -> String {
        format!("{} {}", self.name, self.details())
    }

    /// "for 1h12m03s: typically ...", without the name.
    pub fn details(&self) -> String {
        format!(
            "for {}: typically {:.0} sends/s and {:.0} receives/s, {:.0} and {:.0} bytes \
             each, rate variation {:.2}, {} in all",
            crate::stats::fmt_dur(self.secs),
            self.tx_per_s,
            self.rx_per_s,
            self.tx_size,
            self.rx_size,
            self.jitter,
            mb(self.bytes)
        )
    }
}

fn mb(bytes: u64) -> String {
    let mb = bytes as f64 / 1e6;
    if mb >= 1000.0 {
        format!("{:.1} GB", mb / 1000.0)
    } else if mb >= 1.0 {
        format!("{mb:.0} MB")
    } else {
        "<1 MB".into()
    }
}

#[derive(Debug)]
struct Track {
    /// None until classified; Some(None) when not a game.
    game: Option<Option<(String, String)>>,
    prev: [u64; 4],
    active_run: u32,
    quiet_run: u32,
    seen: bool,
    secs: u64,
    /// Per active second: calls each way, and bytes each way.
    tx: Vec<f64>,
    rx: Vec<f64>,
    txb: Vec<f64>,
    rxb: Vec<f64>,
    tx_calls: u64,
    rx_calls: u64,
    tx_bytes: u64,
    rx_bytes: u64,
}

impl Track {
    fn new(prev: [u64; 4]) -> Self {
        Self {
            game: None,
            prev,
            active_run: 0,
            quiet_run: 0,
            seen: false,
            secs: 0,
            tx: Vec::new(),
            rx: Vec::new(),
            txb: Vec::new(),
            rxb: Vec::new(),
            tx_calls: 0,
            rx_calls: 0,
            tx_bytes: 0,
            rx_bytes: 0,
        }
    }

    /// Worth a summary when its session ends.
    fn reportable(&self, rules: &Rules) -> bool {
        self.seen
            || rules
                .report_bytes
                .is_some_and(|b| self.tx_bytes + self.rx_bytes >= b)
    }

    fn summary(&self) -> Summary {
        let per = |b: u64, c: u64| if c == 0 { 0.0 } else { b as f64 / c as f64 };
        Summary {
            secs: self.secs,
            tx_size: per(self.tx_bytes, self.tx_calls),
            rx_size: per(self.rx_bytes, self.rx_calls),
            bytes: self.tx_bytes + self.rx_bytes,
            ..self.shape(&self.tx, &self.rx)
        }
    }

    /// The last `n` active seconds (fewer if the session is shorter; the
    /// per-second record stops growing after MAX_SECONDS, so for a session
    /// longer than that, the last `n` it kept).
    fn recent(&self, n: usize) -> Summary {
        let from = self.tx.len().saturating_sub(n);
        let sum = |v: &[f64]| v[from..].iter().sum::<f64>();
        let per = |b: f64, c: f64| if c <= 0.0 { 0.0 } else { b / c };
        let (tx, rx) = (sum(&self.tx), sum(&self.rx));
        Summary {
            secs: (self.tx.len() - from) as u64,
            tx_size: per(sum(&self.txb), tx),
            rx_size: per(sum(&self.rxb), rx),
            bytes: (sum(&self.txb) + sum(&self.rxb)) as u64,
            ..self.shape(&self.tx[from..], &self.rx[from..])
        }
    }

    /// Name, median rates and rate variation over these seconds.
    fn shape(&self, tx: &[f64], rx: &[f64]) -> Summary {
        let (name, _) = self.game.clone().flatten().unwrap_or_default();
        let totals: Vec<f64> = tx.iter().zip(rx).map(|(a, b)| a + b).collect();
        let mean = totals.iter().sum::<f64>() / totals.len().max(1) as f64;
        let jitter = if mean > 0.0 {
            totals.iter().map(|t| (t - mean).abs()).sum::<f64>() / totals.len() as f64 / mean
        } else {
            0.0
        };
        Summary {
            name,
            secs: 0,
            tx_per_s: median(tx),
            rx_per_s: median(rx),
            tx_size: 0.0,
            rx_size: 0.0,
            jitter,
            bytes: 0,
        }
    }
}

fn median(v: &[f64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    let mut s = v.to_vec();
    s.sort_by(f64::total_cmp);
    s[s.len() / 2]
}

#[derive(Debug)]
pub struct Observer {
    rules: Rules,
    tracks: HashMap<u32, Track>,
    /// Processes classified as not games: no track, so they don't take
    /// the slots a game needs. Dropped when the process goes.
    not_games: HashSet<u32>,
}

impl Observer {
    pub fn new(rules: Rules) -> Self {
        Self {
            rules,
            tracks: HashMap::new(),
            not_games: HashSet::new(),
        }
    }

    /// One sampling window (`dt` seconds). `exclude` lists processes
    /// reported elsewhere (the current UDP match's game has its own
    /// report); `classify` returns Some((name, reason)) for a process to
    /// watch, None otherwise. A process missing from `samples` has exited.
    pub fn tick(
        &mut self,
        dt: f64,
        samples: &[Sample],
        exclude: &[u32],
        mut classify: impl FnMut(u32) -> Option<(String, String)>,
    ) -> Vec<ObsEvent> {
        let mut events = Vec::new();
        let dt = dt.max(0.001);
        let proto = self.rules.proto;
        let mut present = Vec::with_capacity(samples.len());
        for s in samples {
            present.push(s.tgid);
            if exclude.contains(&s.tgid) || self.not_games.contains(&s.tgid) {
                continue;
            }
            let now = proto.counts(s);
            if !self.tracks.contains_key(&s.tgid) {
                // only processes with traffic of this kind are worth a track
                if now[0] + now[1] == 0 || self.tracks.len() >= MAX_TRACKED {
                    continue;
                }
                self.tracks.insert(s.tgid, Track::new(now));
                continue;
            }
            let Some(t) = self.tracks.get_mut(&s.tgid) else {
                continue;
            };
            let [tx, rx, txb, rxb] = [0, 1, 2, 3].map(|i| now[i].saturating_sub(t.prev[i]));
            t.prev = now;
            let active = tx + rx >= self.rules.min_calls.max(1)
                && (!self.rules.two_way || (tx > 0 && rx > 0));
            if active && t.game.is_none() {
                let g = classify(s.tgid);
                if g.is_none() {
                    self.tracks.remove(&s.tgid);
                    self.not_games.insert(s.tgid);
                    continue;
                }
                t.game = Some(g);
            }
            if t.game.is_none() {
                continue; // not active yet, so not classified yet
            }
            if active {
                t.active_run += 1;
                t.quiet_run = 0;
                t.secs += dt.round() as u64;
                if t.tx.len() < MAX_SECONDS {
                    t.tx.push(tx as f64 / dt);
                    t.rx.push(rx as f64 / dt);
                    t.txb.push(txb as f64 / dt);
                    t.rxb.push(rxb as f64 / dt);
                }
                t.tx_calls += tx;
                t.rx_calls += rx;
                t.tx_bytes += txb;
                t.rx_bytes += rxb;
                if !t.seen && t.active_run >= SEEN_SECS {
                    t.seen = true;
                    let (name, reason) = t.game.clone().flatten().unwrap_or_default();
                    let n = t.tx.len().min(SEEN_SECS as usize);
                    events.push(ObsEvent::Seen {
                        tgid: s.tgid,
                        name,
                        reason,
                        tx_per_s: median(&t.tx[t.tx.len() - n..]),
                        rx_per_s: median(&t.rx[t.rx.len() - n..]),
                    });
                }
            } else {
                t.active_run = 0;
                t.quiet_run += 1;
                if t.quiet_run >= QUIET_SECS {
                    if t.reportable(&self.rules) {
                        events.push(ObsEvent::Ended {
                            tgid: s.tgid,
                            summary: t.summary(),
                        });
                    }
                    // start afresh: the next session is its own
                    let g = t.game.take();
                    *t = Track::new(now);
                    t.game = g;
                }
            }
        }
        self.not_games.retain(|t| present.contains(t));
        // processes that exited: sum up the ones that were reported
        let gone: Vec<u32> = self
            .tracks
            .keys()
            .copied()
            .filter(|k| !present.contains(k))
            .collect();
        for tgid in gone {
            if let Some(t) = self.tracks.remove(&tgid) {
                if t.reportable(&self.rules) {
                    events.push(ObsEvent::Ended {
                        tgid,
                        summary: t.summary(),
                    });
                }
            }
        }
        events
    }

    pub fn proto(&self) -> Proto {
        self.rules.proto
    }

    /// The last `n` active seconds of a reported session that has had at
    /// least that many.
    pub fn recent(&self, tgid: u32, n: usize) -> Option<Summary> {
        self.tracks
            .get(&tgid)
            .filter(|t| t.seen && t.tx.len() >= n)
            .map(|t| t.recent(n))
    }

    /// A reported session so far, as its summary will read.
    pub fn current(&self, tgid: u32) -> Option<Summary> {
        self.tracks
            .get(&tgid)
            .filter(|t| t.seen)
            .map(Track::summary)
    }

    /// (pid, name) of the processes whose sessions have been reported
    /// and are still going.
    pub fn watching(&self) -> Vec<(u32, String)> {
        let mut v: Vec<(u32, String)> = self
            .tracks
            .iter()
            .filter(|(_, t)| t.seen)
            .filter_map(|(tgid, t)| Some((*tgid, t.game.clone().flatten()?.0)))
            .collect();
        v.sort();
        v
    }

    /// Sum up whatever is being reported, on the way out.
    pub fn finish(&mut self) -> Vec<ObsEvent> {
        let rules = self.rules;
        self.tracks
            .drain()
            .filter(|(_, t)| t.reportable(&rules))
            .map(|(tgid, t)| ObsEvent::Ended {
                tgid,
                summary: t.summary(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Sim {
        obs: Observer,
        counters: HashMap<u32, Sample>,
    }

    impl Sim {
        fn new() -> Self {
            Self {
                obs: Observer::new(Rules::TCP_GAMES),
                counters: HashMap::new(),
            }
        }

        /// One second: (tgid, sends, receives, bytes per call).
        fn step(&mut self, rates: &[(u32, u64, u64, u64)]) -> Vec<ObsEvent> {
            for &(tgid, tx, rx, size) in rates {
                let c = self.counters.entry(tgid).or_insert(Sample {
                    tgid,
                    ..Default::default()
                });
                c.tcp_tx_msgs += tx;
                c.tcp_rx_msgs += rx;
                c.tcp_tx_bytes += tx * size;
                c.tcp_rx_bytes += rx * size;
            }
            let samples: Vec<Sample> = self.counters.values().copied().collect();
            self.obs.tick(1.0, &samples, &[], |tgid| {
                (tgid == 7).then(|| ("Wow.exe".to_string(), "launched by lutris".to_string()))
            })
        }

        fn run(&mut self, secs: usize, rates: &[(u32, u64, u64, u64)]) -> Vec<ObsEvent> {
            (0..secs).flat_map(|_| self.step(rates)).collect()
        }

        /// One second with each direction's message size: (tgid, sends,
        /// receives, bytes per send, bytes per receive).
        fn step_sized(&mut self, rates: &[(u32, u64, u64, u64, u64)]) -> Vec<ObsEvent> {
            for &(tgid, tx, rx, tx_size, rx_size) in rates {
                let c = self.counters.entry(tgid).or_insert(Sample {
                    tgid,
                    ..Default::default()
                });
                c.tcp_tx_msgs += tx;
                c.tcp_rx_msgs += rx;
                c.tcp_tx_bytes += tx * tx_size;
                c.tcp_rx_bytes += rx * rx_size;
            }
            let samples: Vec<Sample> = self.counters.values().copied().collect();
            self.obs.tick(1.0, &samples, &[], |tgid| {
                (tgid == 7).then(|| ("PathOfExileSteam".to_string(), "Steam app".to_string()))
            })
        }
    }

    /// Path of Exile 2, 2026-11-14: 13 sends of about 11 bytes and 30
    /// receives of about 158 a second.
    const POE2: (u32, u64, u64, u64, u64) = (7, 13, 30, 11, 158);

    #[test]
    fn path_of_exile_2_looks_like_a_multiplayer_game() {
        let mut sim = Sim::new();
        // the first sample is a baseline; ten seconds of traffic after it
        for _ in 0..10 {
            sim.step_sized(&[POE2]);
        }
        assert!(
            sim.obs.recent(7, SHAPE_SECS).is_none(),
            "not ten seconds yet"
        );
        sim.step_sized(&[POE2]);
        let s = sim.obs.recent(7, SHAPE_SECS).unwrap();
        assert!(s.looks_multiplayer(), "{s:?}");
        assert_eq!((s.tx_per_s, s.rx_per_s), (13.0, 30.0));
        assert_eq!((s.tx_size, s.rx_size), (11.0, 158.0));
        assert_eq!(s.secs, 10);
        assert!(sim.obs.current(7).is_some());
    }

    #[test]
    fn downloads_and_launchers_dont_look_like_multiplayer_games() {
        // a patch download: hundreds of 16 KB reads a second, swinging
        let mut sim = Sim::new();
        for i in 0..12 {
            let rx = if i % 2 == 0 { 300 } else { 60 };
            sim.step_sized(&[(7, 2, rx, 100, 16_000)]);
        }
        let s = sim.obs.recent(7, SHAPE_SECS).unwrap();
        assert!(!s.looks_multiplayer(), "{s:?}");
        // a launcher's connection: a couple of small messages a second
        let mut sim = Sim::new();
        for _ in 0..12 {
            sim.step_sized(&[(7, 1, 2, 60, 200)]);
        }
        let s = sim.obs.recent(7, SHAPE_SECS).unwrap();
        assert!(!s.looks_multiplayer(), "{s:?}");
        // the same rates as Path of Exile 2, but bursty: 0 and 80 in turn
        let mut sim = Sim::new();
        for i in 0..12 {
            let rx = if i % 2 == 0 { 1 } else { 80 };
            sim.step_sized(&[(7, 13, rx, 11, 158)]);
        }
        let s = sim.obs.recent(7, SHAPE_SECS).unwrap();
        assert!(!s.looks_multiplayer(), "{s:?}");
    }

    #[test]
    fn play_after_a_download_is_judged_on_the_play() {
        let mut sim = Sim::new();
        for _ in 0..30 {
            sim.step_sized(&[(7, 2, 200, 100, 16_000)]);
        }
        assert!(!sim.obs.recent(7, SHAPE_SECS).unwrap().looks_multiplayer());
        for _ in 0..9 {
            sim.step_sized(&[POE2]);
        }
        assert!(
            !sim.obs.recent(7, SHAPE_SECS).unwrap().looks_multiplayer(),
            "a second of the download is still in the window"
        );
        sim.step_sized(&[POE2]);
        assert!(sim.obs.recent(7, SHAPE_SECS).unwrap().looks_multiplayer());
    }

    #[test]
    fn a_tcp_game_is_seen_and_summed_up() {
        let mut sim = Sim::new();
        // WoW-ish: ~20 small messages a second each way
        let a = sim.run(12, &[(7, 20, 25, 90)]);
        let seen: Vec<_> = a
            .iter()
            .filter(|e| matches!(e, ObsEvent::Seen { .. }))
            .collect();
        assert_eq!(seen.len(), 1, "{a:?}");
        match seen[0] {
            ObsEvent::Seen {
                name,
                tx_per_s,
                rx_per_s,
                ..
            } => {
                assert_eq!(name, "Wow.exe");
                assert_eq!((*tx_per_s, *rx_per_s), (20.0, 25.0));
            }
            _ => unreachable!(),
        }
        // more play, then the client closes
        sim.run(50, &[(7, 20, 25, 90)]);
        sim.counters.remove(&7);
        let a = sim.step(&[]);
        match &a[..] {
            [ObsEvent::Ended { summary, .. }] => {
                assert_eq!(summary.name, "Wow.exe");
                assert!(summary.secs >= 60, "{summary:?}");
                assert_eq!(summary.tx_size, 90.0);
                assert!(summary.jitter < 0.01);
                assert!(
                    summary
                        .describe()
                        .contains("Wow.exe for 1m01s: typically 20 sends/s and 25 receives/s")
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn non_games_dont_crowd_out_the_game() {
        let mut sim = Sim::new();
        // a browser's worth of busy non-game processes, then the game
        let busy: Vec<(u32, u64, u64, u64)> = (100..100 + MAX_TRACKED as u32 + 10)
            .map(|t| (t, 5, 5, 500))
            .collect();
        sim.run(3, &busy);
        let mut all = busy.clone();
        all.push((7, 20, 20, 90));
        let a = sim.run(13, &all);
        assert!(
            a.iter()
                .any(|e| matches!(e, ObsEvent::Seen { name, .. } if name == "Wow.exe")),
            "{a:?}"
        );
    }

    #[test]
    fn only_games_and_only_two_way_traffic() {
        let mut sim = Sim::new();
        // 8: not a game; 7: a game that only downloads (one way)
        let a = sim.run(30, &[(8, 20, 20, 90), (7, 0, 50, 1400)]);
        assert!(a.is_empty(), "{a:?}");
    }

    #[test]
    fn a_quiet_spell_ends_the_session_and_a_new_one_can_start() {
        let mut sim = Sim::new();
        sim.run(12, &[(7, 10, 10, 100)]);
        // in the character screen: nothing for a while
        let a = sim.run(QUIET_SECS as usize, &[(7, 0, 0, 0)]);
        assert!(
            a.iter().any(|e| matches!(e, ObsEvent::Ended { .. })),
            "{a:?}"
        );
        let a = sim.run(12, &[(7, 10, 10, 100)]);
        assert!(
            a.iter().any(|e| matches!(e, ObsEvent::Seen { .. })),
            "{a:?}"
        );
    }

    #[test]
    fn excluded_processes_are_left_to_their_own_report() {
        let mut obs = Observer::new(Rules::TCP_GAMES);
        let s = |n| Sample {
            tgid: 7,
            tcp_tx_msgs: n,
            tcp_rx_msgs: n,
            ..Default::default()
        };
        let mut events = Vec::new();
        for i in 0..20 {
            events.extend(obs.tick(1.0, &[s(i * 10)], &[7], |_| Some(("g".into(), "r".into()))));
        }
        assert!(events.is_empty());
    }

    #[test]
    fn udp_rules_count_datagrams() {
        let mut obs = Observer::new(Rules {
            proto: Proto::Udp,
            two_way: true,
            min_calls: 2,
            report_bytes: None,
        });
        let mut c = Sample {
            tgid: 9,
            ..Default::default()
        };
        let mut events = Vec::new();
        for _ in 0..12 {
            c.tx_pkts += 64;
            c.rx_pkts += 64;
            c.tx_bytes += 64 * 120;
            c.rx_bytes += 64 * 300;
            // TCP from the same process doesn't count here
            c.tcp_tx_msgs += 5;
            events.extend(obs.tick(1.0, &[c], &[], |_| Some(("g".into(), "r".into()))));
        }
        assert!(
            events
                .iter()
                .any(|e| matches!(e, ObsEvent::Seen { tx_per_s, .. } if *tx_per_s == 64.0)),
            "{events:?}"
        );
        let end = obs.finish();
        match &end[..] {
            [ObsEvent::Ended { summary, .. }] => {
                assert_eq!((summary.tx_size, summary.rx_size), (120.0, 300.0));
                assert_eq!(summary.details().split(':').next(), Some("for 11s"));
            }
            other => panic!("{other:?}"),
        }
    }
    #[test]
    fn tagged_rules_take_one_way_traffic_and_short_downloads() {
        let tagged = |proto| {
            let mut obs = Observer::new(Rules::tagged(proto));
            let mut c = Sample {
                tgid: 5,
                ..Default::default()
            };
            let mut events = Vec::new();
            // a 4-second, 40 MB download over TCP, then quiet
            for i in 0..40 {
                if (1..5).contains(&i) {
                    c.tcp_rx_msgs += 1000;
                    c.tcp_rx_bytes += 10_000_000;
                }
                events.extend(obs.tick(1.0, &[c], &[], |_| {
                    Some(("Trackmania".into(), "tagged".into()))
                }));
            }
            events
        };
        let tcp = tagged(Proto::Tcp);
        match &tcp[..] {
            [ObsEvent::Ended { summary, .. }] => {
                assert_eq!(summary.bytes, 30_000_000, "first second sets the baseline");
                assert_eq!(summary.secs, 3);
                assert_eq!(summary.tx_per_s, 0.0);
            }
            other => panic!("{other:?}"),
        }
        // the same process seen through UDP rules has nothing to say
        assert!(tagged(Proto::Udp).is_empty());

        // under the TCP-games rules a one-way download is never a session
        let mut obs = Observer::new(Rules::TCP_GAMES);
        let mut c = Sample {
            tgid: 5,
            ..Default::default()
        };
        let mut events = Vec::new();
        for _ in 0..40 {
            c.tcp_rx_msgs += 1000;
            c.tcp_rx_bytes += 10_000_000;
            events.extend(obs.tick(1.0, &[c], &[], |_| Some(("g".into(), "r".into()))));
        }
        events.extend(obs.finish());
        assert!(events.is_empty(), "{events:?}");
    }

    #[test]
    fn watching_lists_reported_sessions() {
        let mut obs = Observer::new(Rules::tagged(Proto::Udp));
        let mut c = Sample {
            tgid: 5,
            ..Default::default()
        };
        for i in 0..12 {
            c.rx_pkts += 30;
            c.rx_bytes += 30 * 200;
            obs.tick(1.0, &[c], &[], |_| Some(("PoE2".into(), "tagged".into())));
            if i < 10 {
                assert!(obs.watching().is_empty());
            }
        }
        assert_eq!(obs.watching(), vec![(5, "PoE2".to_string())]);
        assert_eq!(obs.finish().len(), 1);
        assert!(obs.watching().is_empty());
    }
}
