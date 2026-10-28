// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! The daemon: [`Tuner`] loads the BPF programs ([`Tuner::init`]), then
//! [`Tuner::run`] wakes once per tick to feed the detector and act on what
//! it reports. Same shape as a sched_ext Rust scheduler's `Scheduler`.
//!
//! Per tick:
//!   1. drain exit events from the ring buffer (a game exit ends the match
//!      at once rather than after the linger time);
//!   2. read per-process UDP counters and run the detector;
//!   3. act on its actions: apply a tier, re-tier, restore everything;
//!   4. publish stats for `--monitor` and Waybar, and follow the game if
//!      its traffic moves to another interface.

use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};
use std::fs;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{Link, OpenObject, RingBufferBuilder};
use log::{debug, info};

use crate::bpf::tc::{Role, TcSet};
use crate::bpf::{self, maps};
use crate::bpf_intf;
use crate::bpf_skel::{BpfSkel, BpfSkelBuilder};
use crate::bus::{self, Bus};
use crate::config::{Config, Tier, parse_dscp};
use crate::detect::bulk::{BulkDetector, BulkEvent};
use crate::detect::classify::{self, ProcfsLookup};
use crate::detect::egress::Egress;
use crate::detect::{Action, Detector, Sample, SessionInfo};
use crate::experiment;
use crate::health;
use crate::net::{self, Iface};
use crate::stats::{
    self, AppliedMetric, BulkMetric, Counters, DscpMetrics, Metrics, RecentMatch, SessionMetrics,
    TopProc,
};
use crate::tune::{Knobs, coexist};

/// The parts of the command line the daemon needs.
pub struct RunOpts {
    /// Log what would change, change nothing.
    pub dry_run: bool,
    /// Pass libbpf's debug output through (-vv).
    pub libbpf_debug: bool,
    /// Log a stats line this often.
    pub stats_every: Option<Duration>,
}

/// Load the BPF programs and run until `shutdown` is set. Everything
/// changed is restored when the Tuner is dropped, on the way out.
pub fn run(run: &RunOpts, cfg: Config, shutdown: Arc<AtomicBool>) -> Result<()> {
    let mut open_object = MaybeUninit::uninit();
    let mut tuner = Tuner::init(run, cfg, &mut open_object)?;
    tuner.run(shutdown)
}

/// Held for as long as this process may change settings. It's an flock,
/// so the kernel drops it if the process dies.
pub struct Lock {
    _file: fs::File,
}

/// Take the run-directory lock, so two instances never fight over the
/// same knobs (or one restores what the other is holding).
pub fn lock(run_dir: &Path) -> Result<Lock> {
    fs::create_dir_all(run_dir).with_context(|| format!("creating {}", run_dir.display()))?;
    let path = run_dir.join("bpfrag.lock");
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let pid = stats::read(run_dir)
            .map(|s| s.pid.to_string())
            .unwrap_or_else(|_| "?".into());
        bail!("another bpfrag is running (pid {pid})");
    }
    Ok(Lock { _file: file })
}

/// Sorted interface names, for comparing and logging paths.
fn iface_names(ifaces: &[Iface]) -> Vec<String> {
    let mut v: Vec<String> = ifaces.iter().map(|i| i.name.clone()).collect();
    v.sort();
    v
}

/// How long per-interface knobs wait for the marker to see which link the
/// game uses before they go on every candidate.
const EGRESS_GRACE: Duration = Duration::from_secs(5);

/// Interface names the current tier was applied to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Paths {
    /// Where the DSCP marker is attached.
    marker: Vec<String>,
    /// Where per-interface knobs (coalescing, Wi-Fi power save) went.
    knobs: Vec<String>,
}

impl Paths {
    fn new(marker: &[Iface], knobs: &[Iface]) -> Self {
        Self {
            marker: iface_names(marker),
            knobs: iface_names(knobs),
        }
    }
}

/// The daemon. Same shape as a sched_ext Rust scheduler: init() opens,
/// configures and loads the skeleton; run() is the userspace loop.
pub struct Tuner<'a> {
    cfg: Config,
    dry_run: bool,
    stats_every: Option<Duration>,
    run_dir: PathBuf,
    skel: BpfSkel<'a>,
    /// The counting and exit hooks. Dropping a link detaches it.
    _links: Vec<Link>,
    /// DSCP marker and arrival meter attachments (only during a match).
    marker: TcSet,
    meter: TcSet,
    /// The current match's connection health.
    health: health::Tracker,
    detector: Detector,
    /// Processes moving bulk data during the match.
    bulk: BulkDetector,
    procs: ProcfsLookup,
    knobs: Knobs,
    /// When the current match started (None between matches), and the
    /// same in Unix seconds for the D-Bus `MatchSince` property.
    session_start: Option<Instant>,
    started_unix: u64,
    /// The read-only D-Bus interface, unless `[general] dbus = false`.
    bus: Option<Bus>,
    /// (pid, start time) of processes already reported as ignored.
    logged_ignores: HashSet<(u32, u64)>,
    /// The last "leaving these sysctls to bpftune" note, so it is logged
    /// only when it changes.
    bpftune_note: Option<String>,
    /// Other tuners on the box, rescanned every 30s rather than every tick.
    neighbours: Vec<String>,
    neighbours_at: Option<Instant>,
    /// Where the current tier was applied, and when that was last checked.
    applied_paths: Paths,
    last_path_check: Instant,
    /// Which links the game's packets actually leave on.
    egress: Egress,
    /// Finished matches, newest first.
    recent: VecDeque<RecentMatch>,
    /// The `[experiment]` setting, if any (never in a dry run).
    experiment: Option<experiment::Setting>,
    /// This match's draw.
    arm: Option<experiment::Arm>,
}

impl<'a> Tuner<'a> {
    /// Open the BPF object, set its tunables, load it and attach the
    /// counting and exit hooks. The tc marker attaches later, per match.
    pub fn init(
        run: &RunOpts,
        cfg: Config,
        open_object: &'a mut MaybeUninit<OpenObject>,
    ) -> Result<Self> {
        bpf::check_kernel()?;
        bpf::bump_memlock();

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(run.libbpf_debug);
        let mut open = skel_builder
            .open(open_object)
            .context("opening BPF object")?;

        // rodata tunables, frozen at load
        let rodata = open
            .maps
            .rodata_data
            .as_deref_mut()
            .context("BPF rodata missing")?;
        rodata.dscp = parse_dscp(&cfg.dscp.class)?;
        rodata.dscp_override = cfg.dscp.override_app;
        rodata.set_priority = cfg.dscp.set_priority;
        rodata.bulk_dscp = parse_dscp(&cfg.bulk.class)?;

        let skel = open.load().context("loading BPF programs")?;

        let mut links = Vec::new();
        {
            let p = &skel.progs;
            for (what, prog) in [
                ("sock_send_length", &p.bpfrag_send_tp),
                ("sock_recv_length", &p.bpfrag_recv_tp),
                ("sched_process_exit", &p.bpfrag_exit),
            ] {
                links.push(prog.attach().with_context(|| format!("attaching {what}"))?);
            }
        }

        let run_dir = PathBuf::from(&cfg.general.run_dir);
        // A dry run changes nothing, so it has nothing to switch off.
        let experiment = cfg.experiment_setting()?.filter(|_| !run.dry_run);
        let bus = cfg.general.dbus.then(|| Bus::new(run.dry_run));
        Ok(Self {
            experiment,
            arm: None,
            bus,
            started_unix: 0,
            dry_run: run.dry_run,
            stats_every: run.stats_every,
            knobs: Knobs::new(&run_dir, run.dry_run),
            run_dir,
            detector: Detector::new(cfg.detect.clone()),
            bulk: BulkDetector::new(&cfg.bulk),
            procs: ProcfsLookup::new(&cfg.classify),
            cfg,
            skel,
            _links: links,
            marker: TcSet::new(Role::Marker),
            meter: TcSet::new(Role::Meter),
            health: health::Tracker::default(),
            session_start: None,
            logged_ignores: HashSet::new(),
            bpftune_note: None,
            neighbours: Vec::new(),
            neighbours_at: None,
            applied_paths: Paths::default(),
            last_path_check: Instant::now(),
            egress: Egress::default(),
            recent: VecDeque::new(),
        })
    }

    /// Where the game's packets can leave: the configured interfaces, or
    /// those with a default route (plus a connected socket's device).
    fn candidates(&self, s: &SessionInfo) -> Vec<Iface> {
        if !self.cfg.dscp.interfaces.is_empty() {
            return self
                .cfg
                .dscp
                .interfaces
                .iter()
                .filter_map(|n| net::iface_by_name(n))
                .collect();
        }
        let mut v = net::default_route_ifaces();
        if s.ifindex != 0 && !v.iter().any(|i| i.ifindex == s.ifindex) {
            v.extend(net::iface_by_index(s.ifindex));
        }
        v
    }

    /// Links the game's packets have been seen leaving on.
    fn seen_egress(&self) -> Vec<Iface> {
        self.egress
            .ifaces()
            .into_iter()
            .filter_map(net::iface_by_index)
            .collect()
    }

    /// (marker interfaces, knob interfaces). The DSCP marker sits on every
    /// candidate so it can see where the game's packets go; per-interface
    /// knobs (coalescing, Wi-Fi power save) only go where they actually
    /// leave. For the first few seconds, while the marker finds that out,
    /// they wait. Packets seen only in an L3 tunnel (WireGuard, OpenVPN tun,
    /// PPPoE), or not seen at all, leave through some real link the marker
    /// can't tell apart, so the knobs then go on every candidate.
    fn targets(&self, s: &SessionInfo) -> (Vec<Iface>, Vec<Iface>) {
        let marker = self.candidates(s);
        let seen = self.seen_egress();
        let learning = seen.is_empty()
            && self.cfg.profile(s.tier).dscp
            && !self.dry_run
            && self
                .session_start
                .is_none_or(|t| t.elapsed() < EGRESS_GRACE);
        let knobs = if seen.iter().any(|i| !i.is_tunnel()) {
            seen
        } else if learning {
            Vec::new()
        } else {
            marker.clone()
        };
        (marker, knobs)
    }

    /// Apply the profile for `s.tier`: the knobs, the exit watch and the
    /// DSCP marker. Also used to re-apply after a tier or path change;
    /// `Knobs::apply` reverts whatever the new profile no longer wants.
    fn apply_tier(&mut self, s: &SessionInfo) {
        let mut profile = self.cfg.profile(s.tier).clone();
        if let Some(a) = &self.arm {
            a.apply(&mut profile);
        }
        let (marker, ifaces) = self.targets(s);
        self.applied_paths = Paths::new(&marker, &ifaces);
        self.last_path_check = Instant::now();

        let (skip, note) = coexist::skip_set(&self.cfg);
        if note.is_some() && note != self.bpftune_note {
            info!("{}", note.as_deref().unwrap_or_default());
        }
        self.bpftune_note = note;

        let mut changes = self.knobs.apply(&profile, &ifaces, &skip);
        maps::watch(&self.skel, s.tgid, true);
        // The meter only observes, so it runs in every tier and in dry-run.
        self.meter.attach(&self.skel, &marker);
        if profile.dscp {
            let names: Vec<&str> = marker.iter().map(|i| i.name.as_str()).collect();
            if self.dry_run {
                changes.push(format!(
                    "would DSCP-mark {} on {}",
                    self.cfg.dscp.class,
                    names.join(", ")
                ));
            } else {
                self.marker.attach(&self.skel, &marker);
                if !self.marker.ifaces().is_empty() {
                    changes.push(format!(
                        "dscp={} on {}",
                        self.cfg.dscp.class,
                        self.marker.ifaces().join(",")
                    ));
                }
            }
        } else {
            self.marker.detach_all(&self.skel);
        }
        if changes.is_empty() {
            info!("{} profile: nothing to change (already tuned)", s.tier);
        } else {
            info!("{} profile: {}", s.tier, changes.join(", "));
        }
    }

    /// Stop marking, measuring and watching the game, and put every
    /// setting back.
    fn end_session(&mut self, tgid: Option<u32>) {
        if let Some(t) = tgid {
            maps::track_ports(&self.skel, t, false);
            maps::watch(&self.skel, t, false);
        }
        self.marker.detach_all(&self.skel);
        self.meter.detach_all(&self.skel);
        maps::clear_port_rx(&self.skel);
        self.health.finish();
        self.egress.reset();
        self.bulk.reset();
        maps::clear_bulk(&mut self.skel);
        maps::count_tcp(&mut self.skel, false);
        let (done, kept) = self.knobs.restore_all();
        if !done.is_empty() {
            debug!("restored: {}", done.join(", "));
        }
        for k in kept {
            info!("{k}");
        }
        self.session_start = None;
        self.arm = None;
    }

    /// Act on one thing the detector reported.
    fn handle(&mut self, a: Action) {
        match a {
            Action::Start(s) => {
                info!(
                    "Match detected: {} (pid {}) at ~{:.0} pkt/s (tx {:.0}, rx {:.0}) -> {} [{}]",
                    s.name, s.tgid, s.pps, s.tx_pps, s.rx_pps, s.tier, s.reason
                );
                self.session_start = Some(Instant::now());
                self.arm = self.experiment.as_ref().map(|e| {
                    experiment::draw(&self.cfg.experiment.setting, e, self.cfg.experiment.keep)
                });
                if let Some(a) = &self.arm {
                    info!(
                        "Experiment: {} for this match (chosen at random)",
                        a.label()
                    );
                }
                maps::count_tcp(&mut self.skel, true);
                self.egress.reset();
                // Learn the game's ports (for the marker and the meter) and
                // take the health baselines before anything changes.
                maps::clear_port_rx(&self.skel);
                maps::track_ports(&self.skel, s.tgid, true);
                self.health.start(s.tgid, &self.candidates(&s));
                self.started_unix = stats::now_unix();
                self.apply_tier(&s);
                // Properties first, so a listener that reads them when the
                // signal arrives sees this match.
                self.publish();
                if let Some(b) = &self.bus {
                    b.match_started(
                        s.tgid,
                        &s.name,
                        &tier_name(s.tier),
                        &s.reason,
                        &self.arm_label(),
                    );
                }
            }
            Action::Retier { from, to } => {
                if let Some(s) = self.detector.session().cloned() {
                    info!(
                        "{}: traffic now ~{:.0} pkt/s (tx {:.0}, rx {:.0}); {from} -> {to}",
                        s.name, s.pps, s.tx_pps, s.rx_pps
                    );
                    self.apply_tier(&s);
                    self.publish();
                    if let Some(b) = &self.bus {
                        b.tier_changed(s.tgid, &s.name, &tier_name(from), &tier_name(to));
                    }
                }
            }
            Action::End { session, reason } => {
                let secs = self.session_start.map_or(0, |t| t.elapsed().as_secs());
                self.health.update(&maps::read_port_rx(&self.skel));
                let mut health = self.health.finish();
                if let Some(h) = health.as_mut() {
                    h.bulk = self.bulk.moved();
                    h.bulk_class = self.bulk_marks().then(|| self.cfg.bulk.class.clone());
                    h.experiment = self.arm.as_ref().map(experiment::Arm::label);
                }
                self.recent.push_front(RecentMatch {
                    name: session.name.clone(),
                    peak_tier: session.peak_tier.to_string(),
                    peak_pps: session.peak_pps,
                    duration_secs: secs,
                    ended: stats::now_unix(),
                    reason: reason.clone(),
                    health: health.clone(),
                });
                self.recent.truncate(5);
                let arm = self.arm_label();
                self.end_session(Some(session.tgid));
                info!(
                    "Match ended after {} ({reason}); settings restored",
                    stats::fmt_dur(secs)
                );
                self.publish();
                if let Some(b) = &self.bus {
                    b.match_ended(
                        session.tgid,
                        &session.name,
                        &reason,
                        secs,
                        &tier_name(session.peak_tier),
                        &arm,
                        health.as_ref(),
                    );
                }
                if let Some(h) = health {
                    info!("{}: {}", session.name, h.summary());
                }
            }
            Action::Ignored {
                tgid,
                name,
                reason,
                pps,
                excluded,
            } => {
                // Deliberate exclusions (deny list, BPFRAG_GAME=0) are
                // expected and only logged at debug. A process with no game
                // signals at all is logged once at info: it may be a native
                // game that needs --allow.
                let start = classify::start_time(Path::new("/proc"), tgid).unwrap_or(0);
                let first = self.logged_ignores.insert((tgid, start));
                let level = if first && !excluded {
                    log::Level::Info
                } else {
                    log::Level::Debug
                };
                log::log!(
                    level,
                    "Ignoring game-like UDP from {name} (pid {tgid}, ~{pps:.0} pkt/s): {reason}"
                );
            }
        }
    }

    /// Per-tick upkeep while a match runs: refresh its health, and every
    /// 2 s follow the game if its traffic moves to another interface
    /// (docking, Wi-Fi to Ethernet, a VPN coming up).
    fn track_session(&mut self) {
        let Some(s) = self.detector.session().cloned() else {
            return;
        };
        self.health.update(&maps::read_port_rx(&self.skel));
        if self.last_path_check.elapsed() < Duration::from_secs(2) {
            return;
        }
        self.last_path_check = Instant::now();
        self.egress
            .update(&maps::game_packets(&self.skel), self.last_path_check);
        let (marker, knobs) = self.targets(&s);
        self.health
            .watch(if knobs.is_empty() { &marker } else { &knobs });
        let now = Paths::new(&marker, &knobs);
        if now == self.applied_paths {
            return;
        }
        let seen = iface_names(&self.seen_egress());
        if now.marker != self.applied_paths.marker {
            info!(
                "{}: network path changed ({} -> {}); re-applying {}",
                s.name,
                self.applied_paths.marker.join(","),
                now.marker.join(","),
                s.tier
            );
        } else if seen.is_empty() {
            info!(
                "{}: no game traffic seen on {} yet; per-interface settings go on all of them",
                s.name,
                now.knobs.join(",")
            );
        } else if seen == now.knobs {
            info!(
                "{}: game traffic leaves via {}; per-interface settings follow it",
                s.name,
                seen.join(",")
            );
        } else {
            info!(
                "{}: game traffic leaves via tunnel {}; per-interface settings go on {}",
                s.name,
                seen.join(","),
                now.knobs.join(",")
            );
        }
        self.apply_tier(&s);
    }

    /// This match's experiment arm, or "" (for the D-Bus signals).
    fn arm_label(&self) -> String {
        self.arm
            .as_ref()
            .map(experiment::Arm::label)
            .unwrap_or_default()
    }

    /// What the D-Bus properties should say now.
    fn bus_state(&self) -> bus::State {
        let Some(s) = self.detector.session() else {
            return bus::State::default();
        };
        bus::State {
            game_pid: s.tgid,
            game: s.name.clone(),
            reason: s.reason.clone(),
            tier: tier_name(s.tier),
            since: self.started_unix,
            experiment: self.arm_label(),
            applied: self
                .knobs
                .view()
                .into_iter()
                .map(|a| (a.knob, a.value, a.baseline))
                .collect(),
        }
    }

    /// Bring the D-Bus properties up to date (only changes are sent).
    fn publish(&mut self) {
        if self.bus.is_none() {
            return;
        }
        let state = self.bus_state();
        if let Some(b) = self.bus.as_mut() {
            b.set(state);
        }
    }

    /// What happens to bulk packets, for the log and --monitor.
    fn bulk_marking(&self) -> String {
        if !self.cfg.bulk.enabled {
            "not marked: bulk.enabled is off".into()
        } else if self.arm.as_ref().is_some_and(experiment::Arm::stops_bulk) {
            "not marked: the experiment switched it off for this match".into()
        } else if self.dry_run {
            format!("dry run: would mark {}", self.cfg.bulk.class)
        } else {
            format!("marked {}", self.cfg.bulk.class)
        }
    }

    /// Are bulk packets marked this match? Marking needs the DSCP marker,
    /// which a dry run never attaches.
    fn bulk_marks(&self) -> bool {
        self.cfg.bulk.enabled
            && !self.dry_run
            && !self.arm.as_ref().is_some_and(experiment::Arm::stops_bulk)
    }

    /// Follow which other processes move bulk data while a match is on.
    fn track_bulk(&mut self, dt: f64, samples: &[Sample]) {
        let Some(game) = self.detector.session().map(|s| s.tgid) else {
            return;
        };
        let procs = &self.procs;
        let mut names = |tgid: u32| procs.names(tgid);
        let events = self.bulk.tick(dt, samples, &[game], &mut names);
        let mark = self.bulk_marks();
        for e in &events {
            match e {
                BulkEvent::Started(p) => {
                    info!(
                        "Bulk transfer during the match: {} at {:.0} Mbit/s ({})",
                        p.name,
                        p.mbps,
                        self.bulk_marking()
                    );
                    if mark {
                        maps::bulk_tgid(&self.skel, p.tgid, true);
                    }
                }
                BulkEvent::Stopped { tgid, name } => {
                    info!("{name} is no longer moving bulk data");
                    if mark {
                        maps::bulk_tgid(&self.skel, *tgid, false);
                    }
                }
            }
        }
        if mark && !events.is_empty() {
            let any = !self.bulk.bulk().is_empty();
            maps::bulk_active(&mut self.skel, any);
        }
    }

    fn get_metrics(&mut self) -> Metrics {
        let session = self.detector.session().map(|s| SessionMetrics {
            tgid: s.tgid,
            name: s.name.clone(),
            reason: s.reason.clone(),
            tier: s.tier.to_string(),
            pps: s.pps,
            since_secs: self
                .session_start
                .map(|t| t.elapsed().as_secs())
                .unwrap_or(0),
            egress: iface_names(&self.seen_egress()),
            health: self.health.latest().cloned(),
            bulk: self
                .bulk
                .bulk()
                .into_iter()
                .map(|b| BulkMetric {
                    name: b.name,
                    mbps: b.mbps,
                })
                .collect(),
            bulk_marking: self.bulk_marking(),
            experiment: self.arm.as_ref().map(experiment::Arm::label),
        });
        let applied = self
            .knobs
            .view()
            .into_iter()
            .map(|a| AppliedMetric {
                knob: a.knob,
                value: a.value,
                baseline: a.baseline,
            })
            .collect();
        let ifs = self.marker.ifaces();
        let dscp = (!ifs.is_empty()).then(|| DscpMetrics {
            class: self.cfg.dscp.class.clone(),
            interfaces: ifs,
            ports: maps::marked_ports(&self.skel),
        });
        let g = maps::read_global_stats(&self.skel);
        let (udp_procs, udp_pps) = self.detector.totals();
        let counters = Counters {
            udp_procs,
            udp_pps,
            tc_seen: g[bpf_intf::STAT_TC_SEEN as usize],
            dscp_marked: g[bpf_intf::STAT_DSCP_MARKED as usize],
            dscp_kept: g[bpf_intf::STAT_DSCP_KEPT as usize],
            exits: g[bpf_intf::STAT_EXITS as usize],
            events_dropped: g[bpf_intf::STAT_EVENTS_DROPPED as usize],
            bulk_marked: g[bpf_intf::STAT_BULK_MARKED as usize],
        };
        if self
            .neighbours_at
            .is_none_or(|t| t.elapsed() > Duration::from_secs(30))
        {
            self.neighbours = coexist::neighbours();
            self.neighbours_at = Some(Instant::now());
        }
        let mut neighbours: Vec<String> = self.bpftune_note.iter().cloned().collect();
        neighbours.extend(self.neighbours.iter().cloned());
        let views = self.detector.view(6);
        let top = views
            .into_iter()
            .map(|p| {
                let (v, name) = self.procs.lookup(p.tgid);
                TopProc {
                    tgid: p.tgid,
                    name,
                    pps: p.pps,
                    tx_pps: p.tx_pps,
                    rx_pps: p.rx_pps,
                    avg_size: p.avg_size,
                    jitter: if p.jitter.is_finite() { p.jitter } else { -1.0 },
                    verdict: v.describe(),
                }
            })
            .collect();
        Metrics {
            version: env!("CARGO_PKG_VERSION").into(),
            pid: std::process::id(),
            updated: stats::now_unix(),
            dry_run: self.dry_run,
            session,
            applied,
            dscp,
            counters,
            neighbours,
            top,
            recent: self.recent.iter().cloned().collect(),
        }
    }

    /// The main loop, until `shutdown` is set (see the module docs).
    pub fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<()> {
        // The ring buffer callback can't borrow `self`, so it collects
        // exited tgids here and the loop handles them.
        let exits: Rc<RefCell<Vec<u32>>> = Rc::new(RefCell::new(Vec::new()));
        let events = maps::events_handle(&self.skel)?;
        let mut rbb = RingBufferBuilder::new();
        {
            let exits = exits.clone();
            rbb.add(&events, move |data: &[u8]| {
                if let Some(e) = maps::decode_event(data).filter(|e| e.kind == bpf_intf::EVENT_EXIT)
                {
                    exits.borrow_mut().push(e.tgid);
                }
                0
            })?;
        }
        let rb = rbb.build()?;

        let tick = Duration::from_millis(self.cfg.general.tick_ms);
        let t0 = Instant::now();
        let mut last = t0;
        let mut next = t0 + tick;
        let mut next_stats = self.stats_every.map(|d| t0 + d);

        info!(
            "bpfrag {} started{}; waiting for game traffic",
            env!("CARGO_PKG_VERSION"),
            if self.dry_run {
                " in dry-run mode (logging only, nothing is changed)"
            } else {
                ""
            }
        );

        if self.experiment.is_some() {
            info!(
                "Experiment: {} is switched off in {:.0}% of matches, chosen at random",
                self.cfg.experiment.setting.trim(),
                (1.0 - self.cfg.experiment.keep) * 100.0
            );
        } else if self.dry_run && !self.cfg.experiment.setting.trim().is_empty() {
            info!("Experiment: not run in a dry run (nothing is changed to switch off)");
        }

        while !shutdown.load(Ordering::Relaxed) {
            // Sleep in the ring buffer until the next tick, waking at least
            // every 250 ms so a game exit is acted on promptly.
            let wait = next
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(250));
            if let Err(e) = rb.poll(wait) {
                debug!("ringbuf poll: {e}");
            }
            // Answer property reads (so they wait at most one wake-up).
            if let Some(b) = self.bus.as_mut() {
                b.pump();
            }
            let exited: Vec<u32> = exits.borrow_mut().drain(..).collect();
            for tgid in exited {
                if let Some(a) = self.detector.on_exit(tgid) {
                    self.handle(a);
                }
            }

            let now = Instant::now();
            if now < next {
                continue;
            }
            // Rates are per real elapsed second, not per nominal tick.
            let dt = (now - last).as_secs_f64();
            last = now;
            next = now + tick;

            let samples = maps::read_proc_stats(&self.skel);
            let actions = self.detector.tick(
                now.duration_since(t0).as_secs_f64(),
                dt,
                &samples,
                &mut self.procs,
            );
            for a in actions {
                self.handle(a);
            }
            self.track_bulk(dt, &samples);

            self.track_session();
            // Settings can move mid-match (a new network path).
            self.publish();
            let m = self.get_metrics();
            if let Err(e) = stats::write(&self.run_dir, &m) {
                debug!("stats write: {e:#}");
            }

            if next_stats.is_some_and(|ns| now >= ns) {
                info!("{}", m.line());
                next_stats = self.stats_every.map(|d| now + d);
            }
        }
        info!("shutting down");
        Ok(())
    }
}

impl Drop for Tuner<'_> {
    fn drop(&mut self) {
        let arm = self.arm_label();
        let secs = self.session_start.map_or(0, |t| t.elapsed().as_secs());
        let session = self.detector.take_session();
        self.end_session(session.as_ref().map(|s| s.tgid));
        stats::remove(&self.run_dir);
        // Tell listeners the match is over for them too: its settings
        // have just been restored.
        if let Some(b) = self.bus.as_mut() {
            b.set(bus::State::default());
            if let Some(s) = &session {
                let peak = tier_name(s.peak_tier);
                b.match_ended(s.tgid, &s.name, "bpfrag stopped", secs, &peak, &arm, None);
            }
            b.flush();
        }
    }
}

/// Tier names on the bus are lower case, like Waybar's `class`.
fn tier_name(t: Tier) -> String {
    t.name().to_lowercase()
}
