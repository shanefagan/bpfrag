// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Watching a game's traffic without tuning anything, so there is data to
//! decide whether, and how, to detect and tune games like it later.
//!
//! `[detect] tcp = "observe"` uses it for games that talk TCP (World of
//! Warcraft, older games): a process counts when the classifier says it's a
//! game (a launcher parent, a Steam app, a game path, the allow list) and
//! it keeps talking TCP both ways for `SEEN_SECS`.
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
const QUIET_SECS: u32 = 30;
/// Processes tracked at once; more than this and the rest wait.
const MAX_TRACKED: usize = 64;
/// Per-second rates kept for a session's summary (two hours' worth).
const MAX_SECONDS: usize = 7200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Tcp,
}

impl Proto {
    /// (send calls, receive calls, bytes sent, bytes received) so far.
    fn counts(self, s: &Sample) -> [u64; 4] {
        match self {
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
}

impl Rules {
    /// `tcp = "observe"`: steady two-way TCP, like a game's, not a
    /// download's.
    pub const TCP_GAMES: Rules = Rules {
        proto: Proto::Tcp,
        two_way: true,
        min_calls: 2,
    };
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
    tx: Vec<f64>,
    rx: Vec<f64>,
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
            tx_calls: 0,
            rx_calls: 0,
            tx_bytes: 0,
            rx_bytes: 0,
        }
    }

    fn summary(&self) -> Summary {
        let (name, _) = self.game.clone().flatten().unwrap_or_default();
        let totals: Vec<f64> = self.tx.iter().zip(&self.rx).map(|(a, b)| a + b).collect();
        let mean = totals.iter().sum::<f64>() / totals.len().max(1) as f64;
        let jitter = if mean > 0.0 {
            totals.iter().map(|t| (t - mean).abs()).sum::<f64>() / totals.len() as f64 / mean
        } else {
            0.0
        };
        let per = |b: u64, c: u64| if c == 0 { 0.0 } else { b as f64 / c as f64 };
        Summary {
            name,
            secs: self.secs,
            tx_per_s: median(&self.tx),
            rx_per_s: median(&self.rx),
            tx_size: per(self.tx_bytes, self.tx_calls),
            rx_size: per(self.rx_bytes, self.rx_calls),
            jitter,
            bytes: self.tx_bytes + self.rx_bytes,
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
                    if t.seen {
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
                if t.seen {
                    events.push(ObsEvent::Ended {
                        tgid,
                        summary: t.summary(),
                    });
                }
            }
        }
        events
    }

    /// Sum up whatever is being reported, on the way out.
    pub fn finish(&mut self) -> Vec<ObsEvent> {
        self.tracks
            .drain()
            .filter(|(_, t)| t.seen)
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
}
