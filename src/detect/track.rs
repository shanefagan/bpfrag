// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! One process's UDP traffic over the last few windows: the counters as
//! read ([`Sample`]), their rates per window ([`Window`]) and the short
//! history the detector judges ([`Track`]).

use std::collections::VecDeque;

use crate::config::Detect;

/// Cumulative per-process counters as read from the BPF map.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sample {
    pub tgid: u32,
    /// UDP only: what match detection looks at.
    pub tx_pkts: u64,
    pub rx_pkts: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub ifindex: u32,
    /// TCP bytes, for spotting bulk transfers.
    pub tcp_tx_bytes: u64,
    pub tcp_rx_bytes: u64,
    /// TCP send/receive calls, for watching TCP games.
    pub tcp_tx_msgs: u64,
    pub tcp_rx_msgs: u64,
}

impl Sample {
    /// Every byte this process has sent and received, UDP and TCP.
    pub fn total_bytes(&self) -> u64 {
        self.tx_bytes + self.rx_bytes + self.tcp_tx_bytes + self.tcp_rx_bytes
    }
}

/// One sampling window for one process.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Window {
    pub tx_pps: f64,
    pub rx_pps: f64,
    pub avg_size: f64,
    /// Of those, received from peers other than the game's server (and
    /// as many sent back): relay pings. Known only during a match.
    pub others_pps: f64,
    /// The game's own TCP received, bytes a second.
    pub tcp_rx_bps: f64,
}

impl Window {
    pub fn total(&self) -> f64 {
        self.tx_pps + self.rx_pps
    }
}

/// The rate tiers are judged on: twice the smaller of the send and receive
/// rates, about twice the tick rate. The total would count a server that
/// splits big updates into several packets as a faster one: Deadlock, a
/// 64-tick game, sends 64 a second but receives 50 to 150 as fights come
/// and go.
pub(super) fn tick_pps((tx_pps, rx_pps): (f64, f64)) -> f64 {
    2.0 * tx_pps.min(rx_pps)
}

/// What the detector keeps for each process it has seen send UDP.
#[derive(Debug)]
pub(super) struct Track {
    /// The counters at the last reading, to take rates from.
    pub(super) prev: Sample,
    /// The last few windows, oldest first (`[detect] history` of them).
    pub(super) hist: VecDeque<Window>,
    /// Windows in a row that looked like netcode.
    pub(super) steady: u32,
    /// Windows in a row with no packets.
    pub(super) idle_ticks: u32,
    /// The interface its packets last left by.
    pub(super) ifindex: u32,
}

impl Track {
    pub(super) fn new(s: Sample) -> Self {
        Self {
            prev: s,
            hist: VecDeque::new(),
            steady: 0,
            idle_ticks: 0,
            ifindex: s.ifindex,
        }
    }

    /// Add a window, keeping the last `keep`.
    pub(super) fn push(&mut self, w: Window, keep: usize) {
        self.hist.push_back(w);
        while self.hist.len() > keep {
            self.hist.pop_front();
        }
    }

    /// Take the next reading of the counters: the rates since the last one
    /// become a window. `others_pps` is what of it went to and came from
    /// peers other than the game's server.
    pub(super) fn advance(&mut self, s: &Sample, dt: f64, others_pps: f64, keep: usize) {
        let prev = self.prev;
        let dtx = s.tx_pkts - prev.tx_pkts;
        let drx = s.rx_pkts - prev.rx_pkts;
        let dbytes =
            s.tx_bytes.saturating_sub(prev.tx_bytes) + s.rx_bytes.saturating_sub(prev.rx_bytes);
        let pkts = dtx + drx;
        self.prev = *s;
        if s.ifindex != 0 {
            self.ifindex = s.ifindex;
        }
        self.push(
            Window {
                tx_pps: dtx as f64 / dt,
                rx_pps: drx as f64 / dt,
                avg_size: if pkts > 0 {
                    dbytes as f64 / pkts as f64
                } else {
                    0.0
                },
                others_pps,
                tcp_rx_bps: s.tcp_rx_bytes.saturating_sub(prev.tcp_rx_bytes) as f64 / dt,
            },
            keep,
        );
        self.idle_ticks = if pkts == 0 { self.idle_ticks + 1 } else { 0 };
    }

    /// Does the traffic look like a game's netcode right now: enough of
    /// it, both ways, in small packets, at an even rate?
    pub(super) fn looks_like_netcode(&self, cfg: &Detect) -> bool {
        let l = self.last();
        !self.hist.is_empty()
            && self.smooth() >= cfg.min_pps as f64
            && l.tx_pps >= cfg.min_dir_pps as f64
            && l.rx_pps >= cfg.min_dir_pps as f64
            && l.avg_size <= cfg.max_avg_packet as f64
            && self.jitter() <= cfg.max_jitter
    }

    pub(super) fn last(&self) -> Window {
        self.hist.back().copied().unwrap_or_default()
    }

    /// Median total pps over the last `n` windows. Unlike the latest window
    /// or the mean, a one- or two-second burst doesn't move it: menus and
    /// queues are mostly silent but ping relays in short bursts.
    pub(super) fn recent_median(&self, n: usize) -> f64 {
        let mut v: Vec<f64> = self.hist.iter().rev().take(n).map(Window::total).collect();
        if v.is_empty() {
            return 0.0;
        }
        v.sort_by(f64::total_cmp);
        v[v.len() / 2]
    }

    /// The quietest of the last `n` windows (total pps); 0 with fewer.
    pub(super) fn recent_min(&self, n: usize) -> f64 {
        if self.hist.len() < n {
            return 0.0;
        }
        self.hist
            .iter()
            .rev()
            .take(n)
            .map(Window::total)
            .fold(f64::INFINITY, f64::min)
    }

    /// Mean total pps over the history.
    pub(super) fn smooth(&self) -> f64 {
        if self.hist.is_empty() {
            return 0.0;
        }
        self.hist.iter().map(Window::total).sum::<f64>() / self.hist.len() as f64
    }

    /// Mean payload size over the history, weighted by packets.
    pub(super) fn smooth_size(&self) -> f64 {
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

    /// The update rate tiers are judged on ([`tick_pps`]), the median over
    /// the history: a game pinging Steam's relays every couple of minutes
    /// sends 100 more packets a second for a second or two, which raised
    /// the mean enough to move a 64-tick game to INTENSE (2026-11-02).
    /// Traffic with peers other than the server is left out too: Deadlock
    /// sometimes pings a handful of relays for half a minute, 20 more
    /// packets a second each way, longer than the median can ride out
    /// (two 64-tick matches went INTENSE that way, 2026-11-04 and -06).
    pub(super) fn tick_rate(&self) -> f64 {
        let mut v: Vec<f64> = self
            .hist
            .iter()
            .map(|w| {
                tick_pps((
                    (w.tx_pps - w.others_pps).max(0.0),
                    (w.rx_pps - w.others_pps).max(0.0),
                ))
            })
            .collect();
        if v.is_empty() {
            return 0.0;
        }
        v.sort_by(f64::total_cmp);
        v[v.len() / 2]
    }

    /// Mean tx / rx pps over the history.
    pub(super) fn smooth_dirs(&self) -> (f64, f64) {
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
    pub(super) fn jitter(&self) -> f64 {
        let m = self.smooth();
        if m <= 0.0 {
            return f64::INFINITY;
        }
        let mad =
            self.hist.iter().map(|w| (w.total() - m).abs()).sum::<f64>() / self.hist.len() as f64;
        mad / m
    }
}
