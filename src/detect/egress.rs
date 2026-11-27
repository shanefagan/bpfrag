// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Which interfaces carry the game's traffic, from the DSCP marker's
//! per-interface packet counters. An interface counts once it carries a real
//! share of the game's packets, and stops counting only after a while
//! without one, so a few stray packets on a second link (relay pings, a
//! brief route flap) don't move per-interface settings back and forth.
//! Silence moves nothing: while the game sends nothing (loading, between
//! rounds) the interfaces it last used stay its path.
//!
//! Fed the arrival meter's counters instead, the same tracker says which
//! links the server's packets come in on, which needn't be the same ones
//! ([`arriving_elsewhere`]).

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Share of the game's packets an interface needs to count as its path.
const MIN_SHARE: f64 = 0.10;
/// How long an interface stays counted after its share drops.
const HOLD: Duration = Duration::from_secs(30);

/// Packets a second a link must take, besides its share, to count as one
/// the server's packets arrive on. The server sends 32 to 128 a second;
/// relay pings a handful. On 2026-11-26 a few ping replies on wlan0 as a
/// match ended, when little else was arriving, made a tenth of the window.
const ARRIVING_MIN_PPS: f64 = 20.0;

#[derive(Debug, Default)]
pub struct Egress {
    /// Cumulative counts at the last update.
    last: HashMap<u32, u64>,
    /// ifindex -> when it last carried at least MIN_SHARE.
    active: HashMap<u32, Instant>,
    /// The rate a link needs besides its share: 0 for the way out.
    min_pps: f64,
    /// When the counters were last read.
    last_at: Option<Instant>,
}

impl Egress {
    /// A tracker for the arrival meter's counters. A link needs
    /// ARRIVING_MIN_PPS besides its share, so a few relay pings answered on
    /// another link don't count, and the first read after a reset only sets
    /// the baseline: until then the counters hold everything since the
    /// meter went on, pings in the menu included.
    pub fn arrivals() -> Self {
        Egress {
            min_pps: ARRIVING_MIN_PPS,
            ..Egress::default()
        }
    }

    pub fn reset(&mut self) {
        self.last.clear();
        self.active.clear();
        self.last_at = None;
    }

    /// Feed the marker's cumulative (ifindex, game packets) counters.
    pub fn update(&mut self, counts: &[(u32, u64)], now: Instant) {
        let secs = self.last_at.map(|t| now.duration_since(t).as_secs_f64());
        self.last_at = Some(now);
        if self.min_pps > 0.0 && secs.is_none() {
            self.last = counts.iter().copied().collect();
            return;
        }
        let fast_enough = |d: u64| secs.is_none_or(|s| d as f64 >= self.min_pps * s);
        let deltas: Vec<(u32, u64)> = counts
            .iter()
            .map(|&(i, c)| {
                let prev = self.last.get(&i).copied().unwrap_or(0);
                // counters restart at zero when the marker re-attaches
                (i, if c >= prev { c - prev } else { c })
            })
            .collect();
        let total: u64 = deltas.iter().map(|(_, d)| d).sum();
        if total > 0 {
            for &(i, d) in &deltas {
                if d > 0 && d as f64 >= MIN_SHARE * total as f64 && fast_enough(d) {
                    self.active.insert(i, now);
                }
            }
        }
        // Interfaces the marker left (unplugged, route gone) drop at once;
        // others only once the game's packets have gone elsewhere for HOLD.
        self.active.retain(|i, seen| {
            counts.iter().any(|(c, _)| c == i) && (total == 0 || now.duration_since(*seen) < HOLD)
        });
        self.last = counts.iter().copied().collect();
    }

    /// Interfaces currently carrying the game, sorted by ifindex.
    pub fn ifaces(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.active.keys().copied().collect();
        v.sort_unstable();
        v
    }
}

/// Links the game's packets arrive on (an `Egress` fed by the arrival
/// meter's counters) that it doesn't send on. Empty while where it sends
/// isn't known: no marker in a dry run, or in an arm without DSCP.
pub fn arriving_elsewhere(sends: &[u32], arrives: &[u32]) -> Vec<u32> {
    if sends.is_empty() {
        return Vec::new();
    }
    arrives
        .iter()
        .copied()
        .filter(|i| !sends.contains(i))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stray_packets_on_a_second_link_do_not_count() {
        let t0 = Instant::now();
        let mut e = Egress::default();
        // eno1 (2) carries the match, wlan0 (3) sees a few relay pings
        e.update(&[(2, 600), (3, 4)], t0);
        assert_eq!(e.ifaces(), vec![2]);
        e.update(&[(2, 1200), (3, 9)], t0 + Duration::from_secs(2));
        assert_eq!(e.ifaces(), vec![2]);
    }

    #[test]
    fn a_real_move_is_followed_and_the_old_link_drops_after_the_hold() {
        let t0 = Instant::now();
        let mut e = Egress::default();
        e.update(&[(2, 600), (3, 0)], t0);
        // traffic moves to wlan0
        let t1 = t0 + Duration::from_secs(2);
        e.update(&[(2, 600), (3, 600)], t1);
        assert_eq!(e.ifaces(), vec![2, 3], "old link held for a while");
        let t2 = t1 + HOLD + Duration::from_secs(1);
        e.update(&[(2, 600), (3, 1200)], t2);
        assert_eq!(e.ifaces(), vec![3]);
    }

    #[test]
    fn a_quiet_spell_keeps_the_path() {
        let t0 = Instant::now();
        let mut e = Egress::default();
        e.update(&[(2, 600), (3, 0)], t0);
        // loading screen: nothing sent for longer than the hold
        let mut t = t0;
        for _ in 0..30 {
            t += Duration::from_secs(2);
            e.update(&[(2, 600), (3, 0)], t);
            assert_eq!(e.ifaces(), vec![2]);
        }
        // traffic comes back on the same link
        e.update(&[(2, 900), (3, 0)], t + Duration::from_secs(2));
        assert_eq!(e.ifaces(), vec![2]);
    }

    #[test]
    fn a_move_after_a_quiet_spell_drops_the_old_link() {
        let t0 = Instant::now();
        let mut e = Egress::default();
        e.update(&[(2, 600), (3, 0)], t0);
        let t1 = t0 + HOLD * 2;
        e.update(&[(2, 600), (3, 0)], t1);
        assert_eq!(e.ifaces(), vec![2]);
        // the next match goes out over wlan0 only
        e.update(&[(2, 600), (3, 300)], t1 + Duration::from_secs(2));
        assert_eq!(e.ifaces(), vec![3]);
    }

    #[test]
    fn replies_coming_in_on_another_link_are_found() {
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(2);
        let (mut out, mut back) = (Egress::default(), Egress::arrivals());
        // Deadlock on 22 November: sent on wlan0 (3), and over two seconds
        // the server's packets came back mostly on eno1 (2), some on wlan0
        out.update(&[(2, 0), (3, 130)], t1);
        back.update(&[(2, 0), (3, 0)], t0);
        back.update(&[(2, 170), (3, 30)], t1);
        assert_eq!(arriving_elsewhere(&out.ifaces(), &back.ifaces()), vec![2]);
    }

    #[test]
    fn replies_on_the_link_the_game_sends_on_are_not_news() {
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(2);
        let (mut out, mut back) = (Egress::default(), Egress::arrivals());
        out.update(&[(2, 130), (3, 0)], t1);
        back.update(&[(2, 0), (3, 0)], t0);
        back.update(&[(2, 200), (3, 3)], t1);
        assert!(arriving_elsewhere(&out.ifaces(), &back.ifaces()).is_empty());
        // nothing to compare with when no marker counted the way out
        assert!(arriving_elsewhere(&[], &[2]).is_empty());
    }

    #[test]
    fn a_few_pings_answered_on_another_link_as_the_match_ends_are_not_news() {
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(2);
        let (mut out, mut back) = (Egress::default(), Egress::arrivals());
        // 26 November, 22:28: the end screen's 32 updates a second fading
        // out on eno1 (2), and eight relay ping replies on wlan0 (3) in the
        // same two seconds: a sixth of the window, but four a second
        out.update(&[(2, 40), (3, 0)], t1);
        back.update(&[(2, 0), (3, 0)], t0);
        back.update(&[(2, 40), (3, 8)], t1);
        assert!(arriving_elsewhere(&out.ifaces(), &back.ifaces()).is_empty());
    }

    #[test]
    fn the_first_read_of_the_arrival_counters_only_sets_the_baseline() {
        let t0 = Instant::now();
        let mut back = Egress::arrivals();
        // everything since the meter went on, relay pings in the menu too
        back.update(&[(2, 10), (3, 500)], t0);
        assert!(back.ifaces().is_empty());
        back.update(&[(2, 210), (3, 500)], t0 + Duration::from_secs(2));
        assert_eq!(back.ifaces(), vec![2]);
    }

    #[test]
    fn detached_interfaces_drop_and_restarted_counters_are_handled() {
        let t0 = Instant::now();
        let mut e = Egress::default();
        e.update(&[(2, 600), (3, 500)], t0);
        assert_eq!(e.ifaces(), vec![2, 3]);
        // marker left 2, re-attached on 3 (counter restarted)
        e.update(&[(3, 40)], t0 + Duration::from_secs(2));
        assert_eq!(e.ifaces(), vec![3]);
        // a quiet window changes nothing
        e.update(&[(3, 40)], t0 + Duration::from_secs(4));
        assert_eq!(e.ifaces(), vec![3]);
    }
}
