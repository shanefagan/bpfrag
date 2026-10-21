// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan
//
// Which interfaces carry the game's traffic, from the DSCP marker's
// per-interface packet counters. An interface counts once it carries a real
// share of the game's packets, and stops counting only after a while
// without one, so a few stray packets on a second link (relay pings, a
// brief route flap) don't move per-interface settings back and forth.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Share of the game's packets an interface needs to count as its path.
const MIN_SHARE: f64 = 0.10;
/// How long an interface stays counted after its share drops.
const HOLD: Duration = Duration::from_secs(30);

#[derive(Debug, Default)]
pub struct Egress {
    /// Cumulative counts at the last update.
    last: HashMap<u32, u64>,
    /// ifindex -> when it last carried at least MIN_SHARE.
    active: HashMap<u32, Instant>,
}

impl Egress {
    pub fn reset(&mut self) {
        self.last.clear();
        self.active.clear();
    }

    /// Feed the marker's cumulative (ifindex, game packets) counters.
    pub fn update(&mut self, counts: &[(u32, u64)], now: Instant) {
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
                if d > 0 && d as f64 >= MIN_SHARE * total as f64 {
                    self.active.insert(i, now);
                }
            }
        }
        // Interfaces the marker left (unplugged, route gone) drop at once.
        self.active.retain(|i, seen| {
            counts.iter().any(|(c, _)| c == i) && now.duration_since(*seen) < HOLD
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
