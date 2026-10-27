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

use crate::bpf::{self, HookKind, maps, tc::TcMarker};
use crate::bpf_intf;
use crate::bpf_skel::{BpfSkel, BpfSkelBuilder};
use crate::config::{Config, parse_dscp};
use crate::detect::classify::{self, ProcfsLookup};
use crate::detect::egress::Egress;
use crate::detect::{Action, Detector, SessionInfo};
use crate::net::{self, Iface};
use crate::stats::{
    self, AppliedMetric, Counters, DscpMetrics, Metrics, RecentMatch, SessionMetrics, TopProc,
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
    hook: HookKind,
    /// DSCP marker attachments (only during a match).
    tc: TcMarker,
    detector: Detector,
    procs: ProcfsLookup,
    knobs: Knobs,
    /// When the current match started (None between matches).
    session_start: Option<Instant>,
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
}

impl<'a> Tuner<'a> {
    /// Open the BPF object, set its tunables, load it and attach the
    /// counting and exit hooks. The tc marker attaches later, per match.
    pub fn init(
        run: &RunOpts,
        cfg: Config,
        open_object: &'a mut MaybeUninit<OpenObject>,
    ) -> Result<Self> {
        let hook = bpf::pick_hook(cfg.general.hook)?;
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

        // Load only the counting programs this kernel can attach: the
        // generic socket tracepoints, or fexit on the UDP functions.
        let tp = hook == HookKind::Tracepoint;
        let v6 = !tp && bpf::has_udpv6_btf();
        open.progs.bpfrag_send_tp.set_autoload(tp);
        open.progs.bpfrag_recv_tp.set_autoload(tp);
        open.progs.bpfrag_udp_sendmsg.set_autoload(!tp);
        open.progs.bpfrag_udp_recvmsg.set_autoload(!tp);
        open.progs.bpfrag_udpv6_sendmsg.set_autoload(v6);
        open.progs.bpfrag_udpv6_recvmsg.set_autoload(v6);

        let skel = open.load().context("loading BPF programs")?;

        let mut links = Vec::new();
        {
            let p = &skel.progs;
            let mut progs: Vec<(&str, &libbpf_rs::ProgramMut)> = if tp {
                vec![
                    ("sock_send_length", &p.bpfrag_send_tp),
                    ("sock_recv_length", &p.bpfrag_recv_tp),
                ]
            } else {
                vec![
                    ("udp_sendmsg", &p.bpfrag_udp_sendmsg),
                    ("udp_recvmsg", &p.bpfrag_udp_recvmsg),
                ]
            };
            if v6 {
                progs.push(("udpv6_sendmsg", &p.bpfrag_udpv6_sendmsg));
                progs.push(("udpv6_recvmsg", &p.bpfrag_udpv6_recvmsg));
            }
            progs.push(("sched_process_exit", &p.bpfrag_exit));
            for (what, prog) in progs {
                links.push(prog.attach().with_context(|| format!("attaching {what}"))?);
            }
        }
        info!("counting UDP per process via {}", hook.describe());

        let run_dir = PathBuf::from(&cfg.general.run_dir);
        Ok(Self {
            dry_run: run.dry_run,
            stats_every: run.stats_every,
            knobs: Knobs::new(&run_dir, run.dry_run),
            run_dir,
            detector: Detector::new(cfg.detect.clone()),
            procs: ProcfsLookup::new(&cfg.classify),
            cfg,
            skel,
            _links: links,
            hook,
            tc: TcMarker::default(),
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
        let profile = self.cfg.profile(s.tier).clone();
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
        if profile.dscp {
            let names: Vec<&str> = marker.iter().map(|i| i.name.as_str()).collect();
            if self.dry_run {
                changes.push(format!(
                    "would DSCP-mark {} on {}",
                    self.cfg.dscp.class,
                    names.join(", ")
                ));
            } else {
                maps::set_marking(&self.skel, s.tgid, true);
                for l in self.tc.attach(&self.skel, &marker) {
                    self.knobs.track_tc_legacy(l);
                }
                if !self.tc.ifaces().is_empty() {
                    changes.push(format!(
                        "dscp={} on {}",
                        self.cfg.dscp.class,
                        self.tc.ifaces().join(",")
                    ));
                }
            }
        } else {
            maps::set_marking(&self.skel, s.tgid, false);
            for l in self.tc.detach_all(&self.skel) {
                self.knobs.untrack_tc_legacy(l);
            }
        }
        if changes.is_empty() {
            info!("{} profile: nothing to change (already tuned)", s.tier);
        } else {
            info!("{} profile: {}", s.tier, changes.join(", "));
        }
    }

    /// Stop marking and watching the game and put every setting back.
    fn end_session(&mut self, tgid: Option<u32>) {
        if let Some(t) = tgid {
            maps::set_marking(&self.skel, t, false);
            maps::watch(&self.skel, t, false);
        }
        for l in self.tc.detach_all(&self.skel) {
            self.knobs.untrack_tc_legacy(l);
        }
        self.egress.reset();
        let (done, kept) = self.knobs.restore_all();
        if !done.is_empty() {
            debug!("restored: {}", done.join(", "));
        }
        for k in kept {
            info!("{k}");
        }
        self.session_start = None;
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
                self.egress.reset();
                self.apply_tier(&s);
            }
            Action::Retier { from, to } => {
                if let Some(s) = self.detector.session().cloned() {
                    info!(
                        "{}: traffic now ~{:.0} pkt/s (tx {:.0}, rx {:.0}); {from} -> {to}",
                        s.name, s.pps, s.tx_pps, s.rx_pps
                    );
                    self.apply_tier(&s);
                }
            }
            Action::End { session, reason } => {
                let secs = self.session_start.map_or(0, |t| t.elapsed().as_secs());
                self.recent.push_front(RecentMatch {
                    name: session.name,
                    peak_tier: session.peak_tier.to_string(),
                    peak_pps: session.peak_pps,
                    duration_secs: secs,
                    ended: stats::now_unix(),
                    reason: reason.clone(),
                });
                self.recent.truncate(5);
                self.end_session(Some(session.tgid));
                info!(
                    "Match ended after {} ({reason}); settings restored",
                    stats::fmt_dur(secs)
                );
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

    /// Per-tick upkeep while a match runs: follow the game if its traffic
    /// moves to another interface (docking, Wi-Fi to Ethernet, a VPN coming
    /// up).
    fn track_session(&mut self) {
        let Some(s) = self.detector.session().cloned() else {
            return;
        };
        if self.last_path_check.elapsed() < Duration::from_secs(2) {
            return;
        }
        self.last_path_check = Instant::now();
        self.egress
            .update(&maps::game_packets(&self.skel), self.last_path_check);
        let (marker, knobs) = self.targets(&s);
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

    /// The snapshot written to stats.json every tick, for `--monitor`,
    /// `--waybar` and the `--stats` log line.
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
        let ifs = self.tc.ifaces();
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
            hook: self.hook.describe().into(),
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

        while !shutdown.load(Ordering::Relaxed) {
            // Sleep in the ring buffer until the next tick, waking at least
            // every 250 ms so a game exit is acted on promptly.
            let wait = next
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(250));
            if let Err(e) = rb.poll(wait) {
                debug!("ringbuf poll: {e}");
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

            let m = self.get_metrics();
            if let Err(e) = stats::write(&self.run_dir, &m) {
                debug!("stats write: {e:#}");
            }
            self.track_session();

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
        let tgid = self.detector.take_session().map(|s| s.tgid);
        self.end_session(tgid);
        stats::remove(&self.run_dir);
    }
}
