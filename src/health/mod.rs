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
//!   The gaps, stalls and longest gap cover play only ([`Play`]): from
//!   a minute after the start to a few seconds before the last second at
//!   the game's usual rate (the end screen), leaving out seconds when the
//!   game was loading over its own TCP.
//! - Drops come from kernel counters, see [`counters`].
//! - The receive queue: the meter also records which NAPI instance (one
//!   per receive queue) handled the game's packets, shown as "eno1 rx
//!   queue 2, IRQ 140" (see [`crate::net::netdev`]).
//!
//! Most of the gap spread is the internet and the server, not this
//! machine, so expect tuning to move the drop counters more than the gaps.

pub mod counters;
pub mod peers;
pub mod timeline;

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::bpf_intf;
use crate::net::Iface;
use crate::net::netdev::{self, RxQueue};
use crate::net::sockets;
use counters::{SysCounters, nic_overruns};
use peers::{Peer, ServerEvent, Servers};

/// Histogram buckets: 1 ms each, the last one "that long or longer".
pub(crate) const BUCKETS: usize = bpf_intf::GAP_BUCKETS as usize;

/// Arrival gaps on one game port, as the meter recorded them.
#[derive(Clone, Debug, PartialEq)]
pub struct Gaps {
    pub port: u16,
    pub pkts: u64,
    /// Updates: a packet, or packets that arrived together (a server
    /// splitting a big update). The gaps are between updates.
    pub updates: u64,
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
            updates: r.updates,
            hist,
            max_gap_ns: r.max_gap_ns,
            stalls: u64::from(r.stalls),
            napi_id: r.napi_id,
        }
    }

    /// The match's traffic: every port that received at least a tenth of
    /// what the busiest one did, together (a game can move to a new socket
    /// mid-match), named after the busiest. Ports pinging relays and
    /// servers now and then fall under the tenth.
    pub fn match_flows(ports: &[(u16, bpf_intf::port_rx)]) -> Option<Self> {
        let (port, busiest) = ports.iter().max_by_key(|(_, r)| r.pkts)?;
        let mut g = Self::from_bpf(*port, busiest);
        for (p, r) in ports {
            if p == port || r.pkts.saturating_mul(10) < busiest.pkts {
                continue;
            }
            let other = Self::from_bpf(*p, r);
            g.pkts += other.pkts;
            g.updates += other.updates;
            for (h, o) in g.hist.iter_mut().zip(other.hist.iter()) {
                *h += o;
            }
            g.stalls += other.stalls;
            g.max_gap_ns = g.max_gap_ns.max(other.max_gap_ns);
        }
        Some(g)
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
    /// The `[experiment]` arm this match got, e.g. "busy_polling off".
    #[serde(default)]
    pub experiment: Option<String>,
    /// TCP the game itself moved during the match (map or replay
    /// downloads, voice through the game's servers).
    #[serde(default)]
    pub game_tcp_bytes: u64,
    /// Packets received by busy polling, anywhere on the machine. Some
    /// when busy polling was on at some point in the match (or the count
    /// moved anyway); None otherwise, or if the kernel doesn't report it.
    #[serde(default)]
    pub busy_polled: Option<u64>,
    /// Times the game moved to another server (`peers`) without going
    /// quiet: back-to-back games the detector saw as one match, or one
    /// game moving mid-match (Steam's relays route through new ones).
    #[serde(default)]
    pub server_changes: u32,
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
        if let Some(n) = self.busy_polled {
            s += &format!("; busy-polled packets: {n}");
        }
        if let Some(q) = &self.rx_queue {
            s += &format!("; arrives on {}", q.describe());
        }
        match self.server_changes {
            0 => {}
            1 => s += "; the game's server changed once",
            n => s += &format!("; the game's server changed {n} times"),
        }
        if self.game_tcp_bytes >= 1_000_000 {
            s += &format!("; the game's own TCP: {}", size(self.game_tcp_bytes));
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
        if let Some(e) = &self.experiment {
            s += &format!("; experiment: {e}");
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
    /// Busy polling was on (`busy_poll` or `busy_read` above 0) at some
    /// reading this match, whoever set it.
    busy_on: bool,
    /// Who the game receives from.
    servers: Servers,
    /// The part of the match the gap figures cover.
    play: Play,
}

/// Seconds after a match starts before its gaps count. Loading a map
/// arrives in bursts with pauses between (2026-11-02: every stall of 13
/// Deadlock matches fell in the first 50 seconds or the last one).
const SETTLE: Duration = Duration::from_secs(60);
/// Readings left out before the last one at the game's usual rate: the
/// last moments before the end screen.
const END_TRIM: usize = 5;
/// Readings of play before the game's usual rate and update interval are
/// trusted; until then every reading with updates counts.
const LEARN: usize = 10;
/// The game's own TCP received in one reading that means it's loading
/// (Trackmania pulls 10 to 65 MB a second of map and ghost data between
/// maps, and 160 KB while racing). Loading then lasts until a reading at
/// the usual rate (that one included: the stall is counted when the
/// traffic comes back), at least LOADING_HOLD readings and at most
/// LOADING_MAX: a load comes in bursts, with seconds of under a megabyte
/// between them (2026-11-04: 680 KB, and a stall, mid-load).
const LOADING_BYTES: u64 = 1_000_000;
const LOADING_HOLD: u32 = 3;
const LOADING_MAX: u32 = 60;

type PortReadings = Vec<(u16, bpf_intf::port_rx)>;

/// One reading of play: stalls that ended in it, its longest gap, and
/// whether the game was loading.
#[derive(Clone, Copy, Debug, Default)]
struct Reading {
    stalls: u64,
    max_ns: u64,
    loading: bool,
}

/// Which of the meter's readings the gap figures come from: play, not
/// loading. Until a minute in, and for matches that never get that far,
/// it's the whole match.
///
/// From then on each reading (a second) is judged on its own:
/// - **Loading:** from a reading in which the game's own TCP brought in a
///   megabyte or more to the first one back at the usual rate (Trackmania
///   loads each map while the session carries on, and six of its seven
///   stalls in an hour were loads). Left out of everything.
/// - **Usual rate:** Deadlock sends 32 updates a second instead of 64
///   while the player is dead and on the end screen; at more than 1% of
///   the gaps those stretches set the 99% figure. The half and 99% figures
///   come from usual-rate readings only.
/// - Stalls and the longest gap cover every reading that isn't loading,
///   up to END_TRIM readings before the last usual-rate one (the end
///   screen); a hiccup can make its second look slow, so they don't need
///   the usual rate.
#[derive(Default)]
struct Play {
    started: Option<Instant>,
    /// The reading play starts from.
    base: Option<PortReadings>,
    /// The previous reading, for each reading's own gaps.
    prev: Option<PortReadings>,
    /// The game's own TCP received, at the previous reading.
    prev_tcp: Option<u64>,
    /// Readings the current load still lasts at least, and at most.
    loading_left: u32,
    loading_max: u32,
    /// Every reading of play, and the last one the figures go up to
    /// (END_TRIM before the latest usual-rate one).
    readings: Vec<Reading>,
    upto: Option<usize>,
    /// Updates in each reading of play that had any, and each one's median
    /// gap (ms): what "usual" is.
    rates: Vec<u64>,
    intervals: Vec<u32>,
    /// Usual-rate readings' gaps: counted, and the latest END_TRIM, which
    /// are counted once later ones come.
    counted: Option<Gaps>,
    pending: VecDeque<Gaps>,
}

/// The middle value (the upper one of an even count); None if empty.
fn median<T: Copy + Ord>(v: &[T]) -> Option<T> {
    let mut v = v.to_vec();
    if v.is_empty() {
        return None;
    }
    let mid = v.len() / 2;
    Some(*v.select_nth_unstable(mid).1)
}

impl Play {
    fn start(&mut self) {
        *self = Play {
            started: Some(Instant::now()),
            ..Play::default()
        };
    }

    fn settle_due(&self) -> bool {
        self.base.is_none() && self.started.is_some_and(|t| t.elapsed() >= SETTLE)
    }

    fn settle(&mut self, ports: &[(u16, bpf_intf::port_rx)]) {
        let (started, prev_tcp) = (self.started, self.prev_tcp);
        *self = Play {
            started,
            prev_tcp,
            base: Some(ports.to_vec()),
            prev: Some(ports.to_vec()),
            ..Play::default()
        };
    }

    /// Is this reading at the game's usual rate: at least half its usual
    /// updates, and gaps no longer than half as long again as usual?
    fn usual(&self, d: &Gaps, interval: Option<u32>) -> bool {
        if d.updates == 0 {
            return false;
        }
        if self.rates.len() < LEARN {
            return true;
        }
        let rate = median(&self.rates).unwrap_or(0);
        let usual_ms = median(&self.intervals).unwrap_or(0);
        d.updates * 2 >= rate && interval.is_some_and(|ms| ms * 2 <= usual_ms * 3)
    }

    /// One reading: the meter's per-port statistics, which reading of the
    /// meter it was (`reading`, for each port's longest gap in it), and the
    /// game's own TCP received so far. Returns the gap figures as they
    /// stand.
    fn update(
        &mut self,
        ports: &[(u16, bpf_intf::port_rx)],
        reading: u32,
        game_tcp_rx: Option<u64>,
    ) -> Option<Gaps> {
        let tcp = game_tcp_rx.map(|now| {
            let d = now.saturating_sub(self.prev_tcp.unwrap_or(now));
            self.prev_tcp = Some(now);
            d
        });
        let burst = tcp.is_some_and(|d| d >= LOADING_BYTES);
        if burst {
            self.loading_left = LOADING_HOLD + 1;
            self.loading_max = LOADING_MAX + 1;
        }

        let Some(prev) = self.prev.replace(ports.to_vec()) else {
            return Gaps::match_flows(ports);
        };
        if self.base.is_none() {
            return Gaps::match_flows(ports);
        }
        let delta = since(ports, &prev);
        let gaps = Gaps::match_flows(&delta);
        // Loading lasts its minimum, then until a reading at the usual
        // rate, which is the last one.
        let back = !burst
            && gaps
                .as_ref()
                .is_some_and(|d| self.usual(d, d.quantile_ms(0.5)));
        let loading = self.loading_max > 0;
        self.loading_left = self.loading_left.saturating_sub(1);
        self.loading_max = if self.loading_left == 0 && back {
            0
        } else {
            self.loading_max.saturating_sub(1)
        };
        // the match's ports this reading: a tenth of the busiest or more
        let busiest = delta.iter().map(|(_, r)| r.updates).max().unwrap_or(0);
        let mut rec = Reading {
            loading,
            ..Reading::default()
        };
        for ((_, d), (_, r)) in delta.iter().zip(ports) {
            if busiest == 0 || d.updates.saturating_mul(10) < busiest {
                continue;
            }
            rec.stalls += u64::from(d.stalls);
            if r.reading == reading {
                rec.max_ns = rec.max_ns.max(r.reading_max_ns);
            }
        }
        self.readings.push(rec);
        if let Some(d) = gaps {
            let interval = d.quantile_ms(0.5);
            let usual = !loading && self.usual(&d, interval);
            if d.updates > 0 && !loading {
                self.rates.push(d.updates);
                if let Some(ms) = interval {
                    self.intervals.push(ms);
                }
            }
            if usual {
                self.upto = self.readings.len().checked_sub(END_TRIM + 1);
                self.pending.push_back(d);
                if self.pending.len() > END_TRIM {
                    let done = self.pending.pop_front();
                    self.count(done);
                }
            }
        }
        self.figures(ports)
    }

    fn count(&mut self, d: Option<Gaps>) {
        let Some(d) = d else { return };
        match self.counted.as_mut() {
            None => self.counted = Some(d),
            Some(c) => {
                c.pkts += d.pkts;
                c.updates += d.updates;
                for (x, y) in c.hist.iter_mut().zip(d.hist.iter()) {
                    *x += y;
                }
            }
        }
    }

    /// Stalls and the longest gap over play so far, loading left out; the
    /// half and 99% figures from usual-rate readings. Before there's
    /// enough of either, the whole match.
    fn figures(&self, ports: &[(u16, bpf_intf::port_rx)]) -> Option<Gaps> {
        let mut g = Gaps::match_flows(ports)?;
        let (Some(upto), Some(c)) = (self.upto, self.counted.as_ref().filter(|c| c.count() > 0))
        else {
            return Some(g);
        };
        let play = self.readings[..=upto].iter().filter(|r| !r.loading);
        g.stalls = play.clone().map(|r| r.stalls).sum();
        g.max_gap_ns = play.map(|r| r.max_ns).max().unwrap_or(0);
        g.pkts = c.pkts;
        g.updates = c.updates;
        g.hist = c.hist;
        Some(g)
    }
}

/// Each port's arrivals in `now` since `base`. The longest gap is `now`'s
/// own (the meter's was zeroed when `base` was read); a port the map
/// dropped and made again since counts from zero.
fn since(now: &[(u16, bpf_intf::port_rx)], base: &[(u16, bpf_intf::port_rx)]) -> PortReadings {
    now.iter()
        .map(|(port, r)| {
            let mut d = *r;
            if let Some((_, b)) = base.iter().find(|(p, b)| p == port && b.pkts <= r.pkts) {
                d.pkts = r.pkts - b.pkts;
                d.updates = r.updates.saturating_sub(b.updates);
                d.stalls = r.stalls.saturating_sub(b.stalls);
                for (x, y) in d.hist.iter_mut().zip(b.hist.iter()) {
                    *x = x.saturating_sub(*y);
                }
            }
            (*port, d)
        })
        .collect()
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
        self.busy_on = false;
        self.servers = Servers::default();
        self.play.start();
        self.watch(ifaces);
    }

    /// Time to start counting play? The caller then hands the current
    /// reading to [`Tracker::settle`].
    pub fn settle_due(&self) -> bool {
        self.base.is_some() && self.play.settle_due()
    }

    pub fn settle(&mut self, ports: &[(u16, bpf_intf::port_rx)]) {
        self.play.settle(ports);
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

    /// Recompute from the meter's per-port statistics (`reading`: which of
    /// the meter's readings they are, see `maps::next_reading`), the game's
    /// own TCP received so far, and the counters.
    pub fn update(
        &mut self,
        ports: &[(u16, bpf_intf::port_rx)],
        reading: u32,
        game_tcp_rx: Option<u64>,
    ) {
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
        if !self.busy_on {
            self.busy_on = busy_polling_on();
        }
        let busy_polled = sys.busy_polled.filter(|n| self.busy_on || *n > 0);
        let main = self.play.update(ports, reading, game_tcp_rx);
        let napi_id = Gaps::match_flows(ports).map_or(0, |g| g.napi_id);
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
            busy_polled,
            server_changes: self.servers.changes(),
            ..Default::default()
        });
    }

    /// One reading of packets per peer (`game_peers`), `dt` seconds after
    /// the last: follows the game's server.
    pub fn servers(&mut self, dt: f64, peers: &[(Peer, u64)]) -> Vec<ServerEvent> {
        let events = self.servers.update(dt, peers);
        if let Some(h) = self.latest.as_mut() {
            h.server_changes = self.servers.changes();
        }
        events
    }

    /// "A:27031" and its packets a second, the game's current server.
    pub fn server(&self) -> Option<(String, f64)> {
        self.servers
            .main()
            .map(|(p, pps)| (self.servers.label(&p), pps))
    }

    /// Peers that sent the game anything in the last reading.
    pub fn active_peers(&self) -> usize {
        self.servers.active()
    }

    /// Packets a second from peers other than the server, in the last
    /// reading ([`peers::Servers::others_pps`]).
    pub fn others_pps(&self) -> f64 {
        self.servers.others_pps()
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
        self.busy_on = false;
        self.play = Play::default();
        let changes = self.servers.changes();
        self.servers = Servers::default();
        self.latest.take().map(|mut h| {
            h.server_changes = changes;
            h
        })
    }
}

/// Is busy polling on right now, by either sysctl?
fn busy_polling_on() -> bool {
    ["busy_poll", "busy_read"].iter().any(|k| {
        crate::util::read_trim(format!("/proc/sys/net/core/{k}"))
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|v| v > 0)
    })
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

    /// A game port's cumulative meter readings, a second at a time, and
    /// the game's own TCP received.
    struct Port {
        r: bpf_intf::port_rx,
        reading: u32,
        tcp: u64,
    }

    impl Port {
        fn new() -> Self {
            Port {
                r: bpf_intf::port_rx::default(),
                reading: 0,
                tcp: 0,
            }
        }

        /// The next reading: ports as the meter has them, its number.
        fn next(&mut self) -> (PortReadings, u32) {
            let out = (vec![(27015, self.r)], self.reading);
            self.reading += 1;
            out
        }

        fn gap(&mut self, ns: u64) {
            self.r.max_gap_ns = self.r.max_gap_ns.max(ns);
            if self.r.reading != self.reading {
                self.r.reading = self.reading;
                self.r.reading_max_ns = 0;
            }
            self.r.reading_max_ns = self.r.reading_max_ns.max(ns);
        }

        /// A second of `n` updates `ms` apart, each split into `split`
        /// packets.
        fn second(&mut self, p: &mut Play, n: u32, ms: usize, split: u64) -> Option<Gaps> {
            self.r.pkts += u64::from(n) * split;
            self.r.updates += u64::from(n);
            self.r.hist[ms] += n;
            self.gap(ms as u64 * 1_000_000);
            let (ports, reading) = self.next();
            p.update(&ports, reading, Some(self.tcp))
        }

        /// A hiccup: the flow paused for `ms`, then came back.
        fn stall(&mut self, p: &mut Play, ms: u64) -> Option<Gaps> {
            self.r.stalls += 1;
            self.r.hist[BUCKETS - 1] += 1;
            self.gap(ms * 1_000_000);
            self.second(p, 50, 15, 1)
        }

        /// A second with nothing from the game's server.
        fn silent(&mut self, p: &mut Play) -> Option<Gaps> {
            let (ports, reading) = self.next();
            p.update(&ports, reading, Some(self.tcp))
        }

        fn settle(&mut self, p: &mut Play) {
            let (ports, reading) = self.next();
            p.settle(&ports);
            p.update(&ports, reading, Some(self.tcp));
        }
    }

    #[test]
    fn play_is_the_usual_rate_between_loading_and_the_end_screen() {
        let mut p = Play::default();
        p.start();
        let mut port = Port::new();
        // loading: bursts and a 1 s pause
        port.second(&mut p, 200, 2, 1);
        let g = port.stall(&mut p, 1000).unwrap();
        assert_eq!(g.stalls, 1, "the whole match until play starts");
        // a minute in, play starts
        port.settle(&mut p);
        // play: 64 updates a second, each split into 2 packets in fights
        for i in 0..120 {
            port.second(&mut p, 64, 15, if i % 3 == 0 { 2 } else { 1 });
        }
        // dead for 10 s: 32 a second
        for _ in 0..10 {
            port.second(&mut p, 32, 31, 1);
        }
        // a hiccup mid-play, then play again
        port.stall(&mut p, 300);
        for _ in 0..60 {
            port.second(&mut p, 64, 15, 1);
        }
        // the end screen at 32 a second for 12 s, the menu, then relay
        // pings on the same port
        for _ in 0..12 {
            port.second(&mut p, 32, 31, 1);
        }
        for _ in 0..14 {
            port.silent(&mut p);
        }
        let g = port.second(&mut p, 3, 2, 1).unwrap();
        // the half and 99% figures are the 64-a-second ones: no 32 ms
        // stretches, no split packets halving the gaps
        assert_eq!(g.quantile_ms(0.5), Some(16), "{g:?}");
        assert_eq!(g.quantile_ms(0.99), Some(16), "{g:?}");
        // the hiccup counts, loading doesn't; the longest gap is the hiccup
        assert_eq!(g.stalls, 1, "{g:?}");
        assert_eq!(g.max_gap_ns, 300_000_000, "{g:?}");
    }

    #[test]
    fn loading_a_map_mid_session_isnt_play() {
        // Trackmania: racing at about 90 updates a second, then a new map:
        // tens of megabytes over the game's own TCP, the race traffic
        // stopping for a few seconds and coming back with a stall
        let mut p = Play::default();
        p.start();
        let mut port = Port::new();
        port.second(&mut p, 90, 11, 1);
        port.settle(&mut p);
        for _ in 0..120 {
            port.tcp += 160_000;
            port.second(&mut p, 90, 11, 1);
        }
        port.tcp += 40_000_000;
        port.silent(&mut p);
        port.tcp += 20_000_000;
        port.silent(&mut p);
        port.stall(&mut p, 1800);
        // the load goes on in bursts: seconds slow, under a megabyte, and
        // another stall (2026-11-04)
        for _ in 0..4 {
            port.tcp += 800_000;
            port.second(&mut p, 20, 31, 1);
        }
        port.tcp += 680_000;
        port.stall(&mut p, 900);
        port.tcp += 30_000_000;
        port.silent(&mut p);
        for _ in 0..120 {
            port.tcp += 160_000;
            port.second(&mut p, 90, 11, 1);
        }
        // and a hiccup while racing, which counts
        port.stall(&mut p, 250);
        for _ in 0..30 {
            port.second(&mut p, 90, 11, 1);
        }
        let g = port.silent(&mut p).unwrap();
        assert_eq!(g.stalls, 1, "{g:?}");
        assert_eq!(g.max_gap_ns, 250_000_000, "{g:?}");
        assert_eq!(g.quantile_ms(0.99), Some(12), "{g:?}");
    }

    #[test]
    fn a_match_without_usual_rate_readings_yet_is_counted_whole() {
        let mut p = Play::default();
        p.start();
        let mut port = Port::new();
        port.settle(&mut p);
        let g = port.second(&mut p, 64, 15, 1).unwrap();
        assert_eq!(g.updates, 64);
    }

    #[test]
    fn a_port_made_again_counts_from_zero() {
        let base = vec![(1, port_rx(1000, &[(15, 999)]))];
        let now = vec![(1, port_rx(10, &[(15, 9)])), (2, port_rx(5, &[(15, 4)]))];
        let d = since(&now, &base);
        assert_eq!(d[0].1.pkts, 10);
        assert_eq!(d[1].1.pkts, 5);
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
    fn the_match_is_every_busy_port_not_the_pings() {
        let ports = [
            (40001, port_rx(30, &[(63, 29)])), // relay pings
            (27015, port_rx(5000, &[(15, 4999)])),
            // the game moved to a new socket for a while
            (51234, port_rx(2001, &[(15, 1990), (31, 10)])),
        ];
        let g = Gaps::match_flows(&ports).unwrap();
        assert_eq!(g.port, 27015, "named after the busiest");
        assert_eq!(g.pkts, 7001, "the pings are left out");
        assert_eq!(g.hist[15], 4999 + 1990);
        assert_eq!(g.hist[63], 0);
        assert!(Gaps::match_flows(&[]).is_none());
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
    fn server_changes_show_when_there_were_any() {
        let one = Health {
            server_changes: 1,
            ..Default::default()
        };
        assert!(one.summary().ends_with("; the game's server changed once"));
        let five = Health {
            server_changes: 5,
            ..Default::default()
        };
        assert!(
            five.summary()
                .ends_with("; the game's server changed 5 times")
        );
        assert!(!Health::default().summary().contains("server"));
    }

    #[test]
    fn busy_polled_packets_show_when_counted() {
        let h = Health {
            squeezed: 2,
            busy_polled: Some(0),
            ..Default::default()
        };
        assert!(
            h.summary().ends_with(
                "no drops; receive processing ran out of budget 2x; busy-polled packets: 0"
            ),
            "{}",
            h.summary()
        );
        let off = Health::default();
        assert!(!off.summary().contains("busy"));
    }

    #[test]
    fn the_games_own_tcp_shows_when_it_matters() {
        let h = Health {
            game_tcp_bytes: 120_000_000,
            ..Default::default()
        };
        assert!(
            h.summary()
                .ends_with("no drops; the game's own TCP: 120 MB"),
            "{}",
            h.summary()
        );
        let small = Health {
            game_tcp_bytes: 40_000,
            ..Default::default()
        };
        assert!(!small.summary().contains("TCP"));
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
