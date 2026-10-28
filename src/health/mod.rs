// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Per-match connection health: how evenly the game's packets arrive, and
//! whether anything on the receive path dropped packets. It is the
//! evidence for whether the tuning helps: compare matches, or run some
//! with `--dry-run` (which measures but changes nothing) for a baseline.
//!
//! - Packet gaps come from the arrival meter (`bpfrag_rx` at tc ingress):
//!   a histogram of the time between consecutive packets on each game
//!   port. The game's main flow is the port that received the most. A
//!   steady 64-tick server shows gaps of about 16 ms; spikes above that are
//!   what a player feels as rubber-banding. A stall is the flow going
//!   quiet for 100 ms to 2 s and coming back at game rate; the quiet
//!   stretch counts as one gap. Quiet for 2 s or more is a lobby, a menu
//!   or loading (games still send keepalives there) and isn't counted.
//! - Drops come from kernel counters, see [`counters`].
//! - The receive queue: the meter also records which NAPI instance (one
//!   per receive queue) handled the game's packets, shown as "eno1 rx
//!   queue 2, IRQ 140" (see [`crate::net::netdev`]).
//!
//! Most of the gap spread is the internet and the server, not this
//! machine, so expect tuning to move the drop counters more than the gaps.

pub mod counters;

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::bpf_intf;
use crate::net::Iface;
use crate::net::netdev::{self, RxQueue};
use crate::net::sockets;
use counters::{SysCounters, nic_overruns};

/// Histogram buckets: 1 ms each, the last one "that long or longer".
const BUCKETS: usize = bpf_intf::GAP_BUCKETS as usize;

/// Arrival gaps on one game port, as the meter recorded them.
#[derive(Clone, Debug, PartialEq)]
pub struct Gaps {
    pub port: u16,
    pub pkts: u64,
    /// `hist[i]`: gaps of i to i+1 ms; the last bucket holds longer ones.
    pub hist: [u64; BUCKETS],
    /// Longest gap counted (lobbies and other 2 s+ pauses aren't).
    pub max_gap_ns: u64,
    /// Quiet stretches of 100 ms up to 2 s, game rate on both sides.
    pub stalls: u64,
    /// NAPI instance of the latest packet; 0 if unknown.
    pub napi_id: u32,
}

impl Gaps {
    pub fn from_bpf(port: u16, r: &bpf_intf::port_rx) -> Self {
        let mut hist = [0u64; BUCKETS];
        for (h, v) in hist.iter_mut().zip(r.hist.iter()) {
            *h = u64::from(*v);
        }
        Self {
            port,
            pkts: r.pkts,
            hist,
            max_gap_ns: r.max_gap_ns,
            stalls: u64::from(r.stalls),
            napi_id: r.napi_id,
        }
    }

    /// The game's main flow: the port that received the most packets.
    /// (Games also ping relays and servers on other ports.)
    pub fn main_flow(ports: &[(u16, bpf_intf::port_rx)]) -> Option<Self> {
        ports
            .iter()
            .max_by_key(|(_, r)| r.pkts)
            .map(|(port, r)| Self::from_bpf(*port, r))
    }

    fn count(&self) -> u64 {
        self.hist.iter().sum()
    }

    /// The bucket bound (ms) at or under which a share `q` (0..=1) of the
    /// gaps fall. `BUCKETS` means longer than the histogram covers.
    pub fn quantile_ms(&self, q: f64) -> Option<u32> {
        let total = self.count();
        if total == 0 {
            return None;
        }
        let want = ((q * total as f64).ceil() as u64).max(1);
        let mut seen = 0;
        for (i, c) in self.hist.iter().enumerate() {
            seen += c;
            if seen >= want {
                return Some(i as u32 + 1);
            }
        }
        Some(BUCKETS as u32)
    }

    pub fn summary(&self) -> Option<GapSummary> {
        Some(GapSummary {
            port: self.port,
            pkts: self.pkts,
            p50_ms: self.quantile_ms(0.5)?,
            p99_ms: self.quantile_ms(0.99)?,
            max_ms: self.max_gap_ns as f64 / 1e6,
            stalls: self.stalls,
        })
    }
}

/// Packet gaps on the main flow, as reported.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GapSummary {
    pub port: u16,
    pub pkts: u64,
    /// Half the gaps are at most this long (ms).
    pub p50_ms: u32,
    /// 99% of the gaps are at most this long (ms).
    pub p99_ms: u32,
    pub max_ms: f64,
    /// Gaps of 100 ms or more.
    pub stalls: u64,
}

/// "≤16 ms", or "over 63 ms" for the histogram's last bucket.
fn at_most(ms: u32) -> String {
    if ms as usize >= BUCKETS {
        format!("over {} ms", BUCKETS - 1)
    } else {
        format!("≤{ms} ms")
    }
}

impl GapSummary {
    pub fn describe(&self) -> String {
        format!(
            "half {}, 99% {}, longest {:.0} ms, {} stall{} (100 ms+)",
            at_most(self.p50_ms),
            at_most(self.p99_ms),
            self.max_ms,
            self.stalls,
            if self.stalls == 1 { "" } else { "s" }
        )
    }
}

/// One match's health so far (or in the end).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Health {
    /// None if the meter couldn't attach (no tcx) or nothing arrived yet.
    pub gaps: Option<GapSummary>,
    /// UDP socket receive buffers overflowed, anywhere on the machine.
    pub socket_drops: u64,
    /// Of those, drops on the game's own sockets; None if they couldn't
    /// be read.
    #[serde(default)]
    pub game_socket_drops: Option<u64>,
    /// The per-CPU input backlog overflowed.
    pub backlog_drops: u64,
    /// The NIC's receive ring overflowed (on the game's interfaces).
    pub nic_drops: u64,
    /// Receive processing ran out of budget and was deferred.
    pub squeezed: u64,
    /// The receive queue the main flow arrives on, if known.
    #[serde(default)]
    pub rx_queue: Option<RxQueue>,
    /// (process, bytes) moved while bulk during the match.
    #[serde(default)]
    pub bulk: Vec<(String, u64)>,
    /// The class bulk packets were marked with; None if they weren't.
    #[serde(default)]
    pub bulk_class: Option<String>,
}

/// "412 MB", "1.3 GB".
fn size(bytes: u64) -> String {
    let mb = bytes as f64 / 1e6;
    if mb >= 1000.0 {
        format!("{:.1} GB", mb / 1000.0)
    } else if mb >= 1.0 {
        format!("{mb:.0} MB")
    } else {
        "<1 MB".into()
    }
}

impl Health {
    pub fn drops(&self) -> u64 {
        self.socket_drops + self.backlog_drops + self.nic_drops
    }

    fn drops_text(&self) -> String {
        if self.drops() == 0 {
            "no drops".into()
        } else {
            let game = match self.game_socket_drops {
                Some(g) if self.socket_drops > 0 => format!(" ({g} the game's)"),
                _ => String::new(),
            };
            format!(
                "drops: {} socket buffer{game}, {} backlog, {} NIC",
                self.socket_drops, self.backlog_drops, self.nic_drops
            )
        }
    }

    /// One line for the log and `--monitor`.
    pub fn summary(&self) -> String {
        let gaps = match &self.gaps {
            Some(g) => format!("packet gaps {}", g.describe()),
            None => "packet gaps not measured".into(),
        };
        let mut s = format!("{gaps}; {}", self.drops_text());
        if self.squeezed > 0 {
            s += &format!("; receive processing ran out of budget {}x", self.squeezed);
        }
        if let Some(q) = &self.rx_queue {
            s += &format!("; arrives on {}", q.describe());
        }
        if !self.bulk.is_empty() {
            let list: Vec<String> = self
                .bulk
                .iter()
                .map(|(n, b)| format!("{n} {}", size(*b)))
                .collect();
            s += &format!("; bulk: {}", list.join(", "));
            s += &match &self.bulk_class {
                Some(c) => format!(" marked {c}"),
                None => " (not marked)".into(),
            };
        }
        s
    }

    /// A few words for the recent-matches list and Waybar.
    pub fn short(&self) -> String {
        let gaps = match &self.gaps {
            Some(g) => format!("gaps 99% {}, longest {:.0} ms", at_most(g.p99_ms), g.max_ms),
            None => "gaps not measured".into(),
        };
        format!("{gaps}, {}", self.drops_text())
    }
}

/// Collects one match's health: counter baselines at the start, the
/// meter's histograms as it goes.
#[derive(Default)]
pub struct Tracker {
    base: Option<SysCounters>,
    /// interface -> NIC overrun count when it first carried the match
    nic_base: HashMap<String, u64>,
    latest: Option<Health>,
    /// The main flow's receive queue, looked up once per NAPI id.
    rx_queue: Option<RxQueue>,
    /// The game's UDP sockets: drops at the start (0 for sockets opened
    /// later) and at the latest reading, by inode.
    game: Option<GameSockets>,
}

/// Seconds between readings of the game's sockets (a Proton game can hold
/// thousands of fds, so not every tick).
const SOCKET_READ_EVERY: Duration = Duration::from_secs(5);

struct GameSockets {
    tgid: u32,
    base: HashMap<u64, u64>,
    last: HashMap<u64, u64>,
    read_at: Instant,
    readable: bool,
}

impl GameSockets {
    fn start(tgid: u32) -> Self {
        let now = sockets::udp_drops(Path::new("/proc"), tgid);
        Self {
            tgid,
            readable: now.is_some(),
            base: now.clone().unwrap_or_default(),
            last: now.unwrap_or_default(),
            read_at: Instant::now(),
        }
    }

    /// Read again if it's time. A socket that closes keeps its last count.
    fn refresh(&mut self) {
        if self.read_at.elapsed() < SOCKET_READ_EVERY {
            return;
        }
        self.read_at = Instant::now();
        if let Some(now) = sockets::udp_drops(Path::new("/proc"), self.tgid) {
            self.merge(now);
        }
    }

    fn merge(&mut self, now: HashMap<u64, u64>) {
        self.readable = true;
        for (inode, drops) in now {
            self.base.entry(inode).or_insert(0);
            self.last.insert(inode, drops);
        }
    }

    fn drops(&self) -> Option<u64> {
        self.readable.then(|| {
            self.last
                .iter()
                .map(|(i, d)| d.saturating_sub(self.base.get(i).copied().unwrap_or(0)))
                .sum()
        })
    }
}

impl Tracker {
    /// A match by process `tgid` starts on `ifaces`.
    pub fn start(&mut self, tgid: u32, ifaces: &[Iface]) {
        self.base = Some(SysCounters::read());
        self.game = Some(GameSockets::start(tgid));
        self.nic_base.clear();
        self.latest = None;
        self.rx_queue = None;
        self.watch(ifaces);
    }

    /// Take NIC baselines for interfaces not seen yet this match.
    pub fn watch(&mut self, ifaces: &[Iface]) {
        for i in ifaces {
            if !self.nic_base.contains_key(&i.name) {
                if let Some(n) = nic_overruns(&i.name) {
                    self.nic_base.insert(i.name.clone(), n);
                }
            }
        }
    }

    /// Recompute from the meter's per-port statistics and the counters.
    pub fn update(&mut self, ports: &[(u16, bpf_intf::port_rx)]) {
        let Some(base) = self.base else {
            return;
        };
        let sys = SysCounters::read().since(&base);
        let nic_drops = self
            .nic_base
            .iter()
            .map(|(name, b)| nic_overruns(name).map_or(0, |n| n.saturating_sub(*b)))
            .sum();
        if let Some(g) = self.game.as_mut() {
            g.refresh();
        }
        let main = Gaps::main_flow(ports);
        let napi_id = main.as_ref().map_or(0, |g| g.napi_id);
        if napi_id != 0 && self.rx_queue.as_ref().map(|q| q.napi_id) != Some(napi_id) {
            // a netlink round trip, so only when the flow's queue changes
            self.rx_queue = Some(netdev::rx_queue(napi_id));
        }
        self.latest = Some(Health {
            gaps: main.and_then(|g| g.summary()),
            socket_drops: sys.udp_rcvbuf,
            game_socket_drops: self.game.as_ref().and_then(GameSockets::drops),
            backlog_drops: sys.backlog_drops,
            nic_drops,
            squeezed: sys.squeezed,
            rx_queue: self.rx_queue.clone(),
            ..Default::default()
        });
    }

    pub fn latest(&self) -> Option<&Health> {
        self.latest.as_ref()
    }

    /// The match is over: hand back its final health and reset.
    pub fn finish(&mut self) -> Option<Health> {
        self.base = None;
        self.nic_base.clear();
        self.rx_queue = None;
        self.game = None;
        self.latest.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn port_rx(pkts: u64, gaps_ms: &[(usize, u32)]) -> bpf_intf::port_rx {
        let mut r = bpf_intf::port_rx {
            pkts,
            ..Default::default()
        };
        for &(ms, n) in gaps_ms {
            r.hist[ms] = n;
        }
        r
    }

    #[test]
    fn quantiles_of_a_64_tick_flow() {
        // 2000 gaps at ~15.6 ms, ten late ones at 30 ms, one 120 ms stall
        let r = port_rx(2012, &[(15, 2000), (30, 10), (63, 1)]);
        let g = Gaps::from_bpf(27015, &r);
        assert_eq!(g.quantile_ms(0.5), Some(16));
        assert_eq!(g.quantile_ms(0.99), Some(16));
        assert_eq!(g.quantile_ms(0.999), Some(31));
        assert_eq!(g.quantile_ms(1.0), Some(64));
        let empty = Gaps::from_bpf(1, &port_rx(1, &[]));
        assert_eq!(empty.quantile_ms(0.5), None);
        assert!(empty.summary().is_none());
    }

    #[test]
    fn main_flow_is_the_busiest_port() {
        let ports = [
            (40001, port_rx(30, &[(63, 29)])), // relay pings
            (27015, port_rx(5000, &[(15, 4999)])),
        ];
        let g = Gaps::main_flow(&ports).unwrap();
        assert_eq!(g.port, 27015);
        assert!(Gaps::main_flow(&[]).is_none());
    }

    #[test]
    fn game_socket_drops_count_from_the_start() {
        let mut g = GameSockets {
            tgid: 1,
            base: HashMap::from([(10, 300), (11, 0)]),
            last: HashMap::from([(10, 300), (11, 0)]),
            read_at: Instant::now(),
            readable: true,
        };
        assert_eq!(g.drops(), Some(0));
        // socket 10 drops 5, socket 12 opens mid-match and drops 2
        g.merge(HashMap::from([(10, 305), (12, 2)]));
        // socket 11 closed: its count stays as last seen
        assert_eq!(g.drops(), Some(7));
        let unreadable = GameSockets {
            readable: false,
            ..g
        };
        assert_eq!(unreadable.drops(), None);
    }

    #[test]
    fn summaries_read_plainly() {
        let h = Health {
            gaps: Some(GapSummary {
                port: 27015,
                pkts: 5000,
                p50_ms: 16,
                p99_ms: 64,
                max_ms: 48.4,
                stalls: 1,
            }),
            ..Default::default()
        };
        assert_eq!(
            h.summary(),
            "packet gaps half ≤16 ms, 99% over 63 ms, longest 48 ms, 1 stall (100 ms+); no drops"
        );
        let d = Health {
            socket_drops: 2,
            squeezed: 3,
            ..Default::default()
        };
        assert_eq!(
            d.summary(),
            "packet gaps not measured; drops: 2 socket buffer, 0 backlog, 0 NIC; \
             receive processing ran out of budget 3x"
        );
        let g = Health {
            socket_drops: 11401,
            game_socket_drops: Some(0),
            ..Default::default()
        };
        assert_eq!(
            g.summary(),
            "packet gaps not measured; drops: 11401 socket buffer (0 the game's), 0 backlog, 0 NIC"
        );
        assert_eq!(h.short(), "gaps 99% over 63 ms, longest 48 ms, no drops");
        let q = Health {
            rx_queue: Some(RxQueue {
                napi_id: 8194,
                ifname: Some("eno1".into()),
                queue: Some(1),
                irq: Some(140),
            }),
            ..h
        };
        assert!(
            q.summary()
                .ends_with("no drops; arrives on eno1 rx queue 1, IRQ 140"),
            "{}",
            q.summary()
        );
        let b = Health {
            bulk: vec![
                ("steam".into(), 412_300_000),
                ("aria2c".into(), 1_250_000_000),
            ],
            bulk_class: Some("LE".into()),
            ..Default::default()
        };
        assert!(
            b.summary()
                .ends_with("; bulk: steam 412 MB, aria2c 1.2 GB marked LE"),
            "{}",
            b.summary()
        );
    }
}
