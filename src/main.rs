// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan
//
// bpfrag: eBPF-driven, self-reverting network tuning for competitive gaming.

mod bpf;
mod bpf_intf;
mod bpf_skel;
mod check;
mod classify;
mod coexist;
mod config;
mod detect;
mod knobs;
mod logger;
mod net;
mod selftest;
mod stats;
mod util;
mod wifi;

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Parser;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{Link, OpenObject, RingBufferBuilder};
use log::{debug, info, warn};

use bpf::HookKind;
use bpf_skel::{BpfSkel, BpfSkelBuilder};
use classify::{Classifier, Verdict};
use config::{Config, TIER_NAMES, parse_dscp};
use detect::{Action, Detector, Oracle, SessionInfo};
use knobs::Knobs;
use net::Iface;
use stats::{AppliedMetric, Counters, DscpMetrics, Metrics, SessionMetrics, TopProc};

/// bpfrag: eBPF-driven, self-reverting network tuning for competitive gaming.
///
/// BPF programs count UDP traffic per process. When a game's netcode shows
/// up (a steady, two-way, small-packet tick stream from a process that is
/// a game) bpfrag applies a networking profile picked from the tick
/// rate: CASUAL, COMPETITIVE or INTENSE. That covers socket busy-polling,
/// NIC interrupt coalescing, buffer headroom, DSCP marking of the game's
/// packets (helps Wi-Fi WMM and QoS routers) and, optionally, tighter dirty
/// writeback so background downloads don't flush in bursts mid-match.
///
/// When the match ends or the game exits, every change is put back. bpfrag
/// never touches CPU scheduling, so it runs fine next to sched_ext
/// schedulers, and it yields bpftune's sysctls while bpftune is running.
#[derive(Debug, Parser)]
#[command(name = "bpfrag", version, verbatim_doc_comment)]
struct Opts {
    /// TOML file with tiers, classifier lists and detector settings.
    /// Defaults to /etc/bpfrag/bpfrag.toml if it exists.
    #[clap(short = 'c', long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Detect and log what would change, but change nothing.
    #[clap(short = 'n', long)]
    dry_run: bool,

    /// Use this tier for every match instead of following the tick rate.
    #[clap(short = 't', long, value_parser = ["casual", "competitive", "intense"])]
    tier: Option<String>,

    /// DSCP class for game packets (CS4, EF, AF41, 0-63), or "off".
    #[clap(short = 'd', long, value_name = "CLASS")]
    dscp: Option<String>,

    /// Interface to tune and mark on (repeatable). Default: the interfaces
    /// carrying the default routes.
    #[clap(short = 'i', long = "iface", value_name = "IFACE")]
    ifaces: Vec<String>,

    /// Process name glob that is always a game (repeatable).
    #[clap(short = 'a', long, value_name = "GLOB")]
    allow: Vec<String>,

    /// Process name glob that is never a game (repeatable).
    #[clap(long, value_name = "GLOB")]
    deny: Vec<String>,

    /// Smoothed packets/s a process needs before it can count as a match.
    #[clap(long, value_name = "PPS")]
    min_pps: Option<u32>,

    /// Quiet seconds before a match is considered over.
    #[clap(long, value_name = "SECS")]
    linger: Option<u64>,

    /// Sharing sysctls with bpftune: auto (yield while it runs), yield, ignore.
    #[clap(long, value_parser = ["auto", "yield", "ignore"])]
    bpftune: Option<String>,

    /// Print a stats line to the log every SECS while running.
    #[clap(long, value_name = "SECS")]
    stats: Option<f64>,

    /// Don't run: print one line of JSON for a Waybar custom module.
    #[clap(long)]
    waybar: bool,

    /// Don't run: show the running instance's stats every SECS (0 = once).
    #[clap(long, value_name = "SECS")]
    monitor: Option<f64>,

    /// Don't run: undo anything a crashed or killed instance left changed.
    #[clap(long)]
    restore: bool,

    /// Don't run: report what this machine supports and who else is tuning it.
    #[clap(long)]
    check: bool,

    /// Don't run: classify PID the way the daemon would.
    #[clap(long, value_name = "PID")]
    classify: Option<u32>,

    /// Don't run: push test packets through the DSCP marker on this kernel
    /// (BPF_PROG_TEST_RUN; attaches nothing, changes nothing).
    #[clap(long)]
    selftest: bool,

    /// Don't run: print the effective configuration as TOML.
    #[clap(long)]
    dump_config: bool,

    /// Verbose output (-v debug, -vv trace including libbpf).
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
}

impl Opts {
    /// Command line beats the config file.
    fn apply(&self, cfg: &mut Config) -> Result<()> {
        if let Some(t) = &self.tier {
            cfg.detect.pin_tier = Some(t.clone());
        }
        if let Some(d) = &self.dscp {
            if d.eq_ignore_ascii_case("off") {
                for t in cfg.tiers.iter_mut() {
                    t.dscp = false;
                }
            } else {
                cfg.dscp.class = d.clone();
            }
        }
        if !self.ifaces.is_empty() {
            cfg.dscp.interfaces = self.ifaces.clone();
        }
        cfg.classify.allow.extend(self.allow.iter().cloned());
        cfg.classify.deny.extend(self.deny.iter().cloned());
        if let Some(p) = self.min_pps {
            cfg.detect.min_pps = p;
        }
        if let Some(l) = self.linger {
            cfg.detect.linger_secs = l;
        }
        if let Some(b) = &self.bpftune {
            cfg.general.bpftune = b.clone();
        }
        cfg.validate()
    }
}

fn iface_names(ifaces: &[Iface]) -> Vec<String> {
    let mut v: Vec<String> = ifaces.iter().map(|i| i.name.clone()).collect();
    v.sort();
    v
}

/// Exclusive lock so two instances never fight over the same knobs.
struct Lock {
    _file: fs::File,
}

fn lock(run_dir: &Path) -> Result<Lock> {
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

/// Classifier with a short-lived cache keyed on (pid, start time).
struct ProcOracle {
    classifier: Classifier,
    cache: HashMap<u32, (u64, Verdict, String, Instant)>,
}

impl ProcOracle {
    fn lookup(&mut self, tgid: u32) -> (Verdict, String) {
        let start = classify::start_time(Path::new("/proc"), tgid).unwrap_or(0);
        if let Some((st, v, n, at)) = self.cache.get(&tgid)
            && *st == start
            && at.elapsed() < Duration::from_secs(30)
        {
            return (v.clone(), n.clone());
        }
        let (v, info) = self.classifier.classify(tgid);
        let name = info
            .map(|i| i.display_name())
            .unwrap_or_else(|| format!("pid {tgid}"));
        self.cache
            .insert(tgid, (start, v.clone(), name.clone(), Instant::now()));
        if self.cache.len() > 512 {
            self.cache
                .retain(|_, e| e.3.elapsed() < Duration::from_secs(30));
        }
        (v, name)
    }
}

impl Oracle for ProcOracle {
    fn verdict(&mut self, tgid: u32) -> (Verdict, String) {
        self.lookup(tgid)
    }
    fn alive(&mut self, tgid: u32) -> bool {
        Path::new(&format!("/proc/{tgid}")).exists()
    }
}

/// The daemon. Same shape as a sched_ext Rust scheduler: init() opens,
/// configures and loads the skeleton; run() is the userspace loop.
struct Tuner<'a> {
    cfg: Config,
    dry_run: bool,
    stats_every: Option<Duration>,
    run_dir: PathBuf,
    skel: BpfSkel<'a>,
    _links: Vec<Link>,
    hook: HookKind,
    tc: bpf::TcMarker,
    detector: Detector,
    oracle: ProcOracle,
    knobs: Knobs,
    session_start: Option<Instant>,
    /// The detector forgets the session before handing us End.
    last_tgid: Option<u32>,
    logged_ignores: HashSet<(u32, u64)>,
    bpftune_note: Option<String>,
    /// Other tuners on the box; rescanned every 30s, not every tick.
    neighbours: (Vec<String>, Option<Instant>),
    /// Interfaces the current tier was applied to, and when we last looked.
    /// (marker, knob) interface names the current tier was applied to.
    applied_paths: (Vec<String>, Vec<String>),
    last_iface_check: Instant,
    /// Peak tier / pps of the running match, and finished matches.
    peak: (usize, f64),
    last_session_name: Option<String>,
    recent: std::collections::VecDeque<stats::RecentMatch>,
}

impl<'a> Tuner<'a> {
    fn init(
        opts: &Opts,
        cfg: Config,
        open_object: &'a mut MaybeUninit<OpenObject>,
    ) -> Result<Self> {
        let hook = bpf::pick_hook(&cfg.general.hook)?;
        bpf::bump_memlock();

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose >= 2);
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
            dry_run: opts.dry_run,
            stats_every: opts.stats.filter(|s| *s > 0.0).map(Duration::from_secs_f64),
            knobs: Knobs::new(&run_dir, opts.dry_run),
            run_dir,
            detector: Detector::new(cfg.detect.clone()),
            oracle: ProcOracle {
                classifier: Classifier::new(&cfg.classify),
                cache: HashMap::new(),
            },
            cfg,
            skel,
            _links: links,
            hook,
            tc: bpf::TcMarker::default(),
            session_start: None,
            last_tgid: None,
            logged_ignores: HashSet::new(),
            bpftune_note: None,
            neighbours: (Vec::new(), None),
            applied_paths: (Vec::new(), Vec::new()),
            last_iface_check: Instant::now(),
            peak: (0, 0.0),
            last_session_name: None,
            recent: std::collections::VecDeque::new(),
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
        if s.ifindex != 0
            && !v.iter().any(|i| i.ifindex == s.ifindex)
            && let Some(i) = net::iface_by_index(s.ifindex)
        {
            v.push(i);
        }
        v
    }

    /// (marker interfaces, knob interfaces). The DSCP marker sits on every
    /// candidate so it can see where the game's packets go; per-interface
    /// knobs (coalescing, Wi-Fi power save) only go where they actually
    /// leave, once the marker has seen that.
    fn targets(&self, s: &SessionInfo) -> (Vec<Iface>, Vec<Iface>) {
        let marker = self.candidates(s);
        let seen: Vec<Iface> = bpf::game_egress(&self.skel, s.tgid, Duration::from_secs(10))
            .into_iter()
            .filter_map(net::iface_by_index)
            .collect();
        let knobs = if seen.is_empty() {
            marker.clone()
        } else {
            seen
        };
        (marker, knobs)
    }

    fn apply_tier(&mut self, s: &SessionInfo) {
        let tier = self.cfg.tiers[s.tier.min(2)].clone();
        let (marker, ifaces) = self.targets(s);
        self.applied_paths = (iface_names(&marker), iface_names(&ifaces));
        self.last_iface_check = Instant::now();

        let (skip, note) = coexist::skip_set(&self.cfg);
        if note.is_some() && note != self.bpftune_note {
            info!("{}", note.as_deref().unwrap_or_default());
        }
        self.bpftune_note = note;

        let mut changes = self.knobs.apply(&tier, &ifaces, &skip);
        bpf::watch(&self.skel, s.tgid, true);
        if tier.dscp {
            let names: Vec<&str> = marker.iter().map(|i| i.name.as_str()).collect();
            if self.dry_run {
                changes.push(format!(
                    "would DSCP-mark {} on {}",
                    self.cfg.dscp.class,
                    names.join(", ")
                ));
            } else {
                bpf::set_marking(&self.skel, s.tgid, true);
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
            bpf::set_marking(&self.skel, s.tgid, false);
            for l in self.tc.detach_all(&self.skel) {
                self.knobs.untrack_tc_legacy(l);
            }
        }
        if changes.is_empty() {
            info!("{} profile: nothing to change (already tuned)", tier.name);
        } else {
            info!("{} profile: {}", tier.name, changes.join(", "));
        }
    }

    fn end_session(&mut self, tgid: Option<u32>) {
        if let Some(t) = tgid {
            bpf::set_marking(&self.skel, t, false);
            bpf::watch(&self.skel, t, false);
        }
        for l in self.tc.detach_all(&self.skel) {
            self.knobs.untrack_tc_legacy(l);
        }
        let (done, kept) = self.knobs.restore_all();
        if !done.is_empty() {
            debug!("restored: {}", done.join(", "));
        }
        for k in kept {
            info!("{k}");
        }
        self.session_start = None;
    }

    fn handle(&mut self, a: Action) {
        match a {
            Action::Start(s) => {
                info!(
                    "Match detected: {} (pid {}) at ~{:.0} pkt/s (tx {:.0}, rx {:.0}) -> {} [{}]",
                    s.name,
                    s.tgid,
                    s.pps,
                    s.tx_pps,
                    s.rx_pps,
                    TIER_NAMES[s.tier.min(2)],
                    s.reason
                );
                self.session_start = Some(Instant::now());
                self.peak = (s.tier, s.pps);
                self.last_session_name = Some(s.name.clone());
                self.apply_tier(&s);
            }
            Action::Retier { from, to, pps } => {
                if let Some(s) = self.detector.session().cloned() {
                    info!(
                        "{}: traffic now ~{pps:.0} pkt/s (tx {:.0}, rx {:.0}); {} -> {}",
                        s.name,
                        s.tx_pps,
                        s.rx_pps,
                        TIER_NAMES[from.min(2)],
                        TIER_NAMES[to.min(2)]
                    );
                    self.apply_tier(&s);
                }
            }
            Action::End { reason } => {
                if let Some(name) = self.last_session_name.take() {
                    self.recent.push_front(stats::RecentMatch {
                        name,
                        peak_tier: TIER_NAMES[self.peak.0.min(2)].into(),
                        peak_pps: self.peak.1,
                        duration_secs: self
                            .session_start
                            .map(|t| t.elapsed().as_secs())
                            .unwrap_or(0),
                        ended: stats::now_unix(),
                        reason: reason.clone(),
                    });
                    self.recent.truncate(5);
                }
                let tgid = self.last_tgid.take();
                let took = self
                    .session_start
                    .map(|t| t.elapsed().as_secs())
                    .unwrap_or(0);
                self.end_session(tgid);
                info!(
                    "Match ended after {} ({reason}); settings restored",
                    stats::fmt_dur(took)
                );
            }
            Action::Ignored {
                tgid,
                name,
                reason,
                pps,
            } => {
                // Deliberate exclusions (deny list, BPFRAG_GAME=0) are expected
                // and only logged at debug. A process with no game signals at
                // all is logged once at info: it may be a native game that
                // needs --allow.
                let excluded = reason.starts_with("deny list") || reason.contains("BPFRAG_GAME=0");
                let start = classify::start_time(Path::new("/proc"), tgid).unwrap_or(0);
                let first = self.logged_ignores.insert((tgid, start));
                if first && !excluded {
                    info!(
                        "Ignoring game-like UDP from {name} (pid {tgid}, ~{pps:.0} pkt/s): {reason}"
                    );
                } else {
                    debug!(
                        "Ignoring game-like UDP from {name} (pid {tgid}, ~{pps:.0} pkt/s): {reason}"
                    );
                }
            }
        }
    }

    /// Per-tick upkeep while a match runs: remember its peak, and follow
    /// the game if its traffic moves to another interface (docking, Wi-Fi
    /// to Ethernet, a VPN coming up).
    fn track_session(&mut self) {
        let Some(s) = self.detector.session().cloned() else {
            return;
        };
        if s.tier > self.peak.0 {
            self.peak.0 = s.tier;
        }
        if s.pps > self.peak.1 {
            self.peak.1 = s.pps;
        }
        if self.last_iface_check.elapsed() < Duration::from_secs(2) {
            return;
        }
        self.last_iface_check = Instant::now();
        let (marker, knobs) = self.targets(&s);
        let now = (iface_names(&marker), iface_names(&knobs));
        if now == self.applied_paths {
            return;
        }
        if now.0 != self.applied_paths.0 {
            info!(
                "{}: network path changed ({} -> {}); re-applying {}",
                s.name,
                self.applied_paths.0.join(","),
                now.0.join(","),
                TIER_NAMES[s.tier.min(2)]
            );
        } else {
            info!(
                "{}: game traffic leaves via {}; per-interface settings follow it",
                s.name,
                now.1.join(",")
            );
        }
        self.apply_tier(&s);
    }

    fn get_metrics(&mut self) -> Metrics {
        let session = self.detector.session().map(|s| SessionMetrics {
            tgid: s.tgid,
            name: s.name.clone(),
            reason: s.reason.clone(),
            tier: TIER_NAMES[s.tier.min(2)].into(),
            pps: s.pps,
            since_secs: self
                .session_start
                .map(|t| t.elapsed().as_secs())
                .unwrap_or(0),
            egress: bpf::game_egress(&self.skel, s.tgid, Duration::from_secs(10))
                .into_iter()
                .filter_map(net::iface_by_index)
                .map(|i| i.name)
                .collect(),
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
            ports: bpf::marked_ports(&self.skel),
        });
        let g = bpf::read_global_stats(&self.skel);
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
            .neighbours
            .1
            .is_none_or(|t| t.elapsed() > Duration::from_secs(30))
        {
            self.neighbours = (coexist::neighbours(), Some(Instant::now()));
        }
        let mut neighbours: Vec<String> = self.bpftune_note.iter().cloned().collect();
        neighbours.extend(self.neighbours.0.iter().cloned());
        let views = self.detector.view(6);
        let top = views
            .into_iter()
            .map(|p| {
                let (v, name) = self.oracle.lookup(p.tgid);
                TopProc {
                    tgid: p.tgid,
                    name,
                    pps: p.pps,
                    tx_pps: p.tx_pps,
                    rx_pps: p.rx_pps,
                    avg_size: p.avg_size,
                    jitter: if p.jitter.is_finite() { p.jitter } else { -1.0 },
                    verdict: match v {
                        Verdict::Game(r) => format!("game: {r}"),
                        Verdict::NotGame(r) => format!("not a game: {r}"),
                    },
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

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<()> {
        let exits: Rc<RefCell<Vec<u32>>> = Rc::new(RefCell::new(Vec::new()));
        let events = bpf::events_handle(&self.skel)?;
        let mut rbb = RingBufferBuilder::new();
        {
            let exits = exits.clone();
            rbb.add(&events, move |data: &[u8]| {
                if let Some(e) = bpf::decode_event(data)
                    && e.kind == bpf_intf::EVENT_EXIT
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
            let wait = next
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(250));
            if let Err(e) = rb.poll(wait) {
                debug!("ringbuf poll: {e}");
            }
            let exited: Vec<u32> = exits.borrow_mut().drain(..).collect();
            for tgid in exited {
                if let Some(a) = self.detector.on_exit(tgid) {
                    self.last_tgid = Some(tgid);
                    self.handle(a);
                }
            }

            let now = Instant::now();
            if now < next {
                continue;
            }
            let dt = (now - last).as_secs_f64();
            last = now;
            next = now + tick;

            let samples = bpf::read_proc_stats(&self.skel);
            let before = self.detector.session().map(|s| s.tgid);
            let actions = self.detector.tick(
                now.duration_since(t0).as_secs_f64(),
                dt,
                &samples,
                &mut self.oracle,
            );
            for a in actions {
                if matches!(a, Action::End { .. }) {
                    self.last_tgid = before;
                }
                self.handle(a);
            }

            let m = self.get_metrics();
            if let Err(e) = stats::write(&self.run_dir, &m) {
                debug!("stats write: {e:#}");
            }
            self.track_session();

            if let Some(ns) = next_stats
                && now >= ns
            {
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
        let tgid = self.detector.session().map(|s| s.tgid);
        self.detector.reset();
        self.end_session(tgid);
        stats::remove(&self.run_dir);
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();
    logger::init(opts.verbose);

    let mut cfg = Config::load(opts.config.as_deref())?;
    opts.apply(&mut cfg)?;
    let run_dir = PathBuf::from(&cfg.general.run_dir);

    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown = shutdown.clone();
        ctrlc::set_handler(move || shutdown.store(true, Ordering::Relaxed))
            .context("setting signal handler")?;
    }

    if opts.waybar {
        println!("{}", stats::waybar(&run_dir));
        return Ok(());
    }
    if let Some(intv) = opts.monitor {
        return stats::monitor(&run_dir, intv, shutdown);
    }
    if opts.dump_config {
        print!("{}", cfg.to_toml()?);
        return Ok(());
    }
    if opts.check {
        if !check::run(&cfg) {
            std::process::exit(1);
        }
        return Ok(());
    }
    if let Some(pid) = opts.classify {
        let (v, info) = Classifier::new(&cfg.classify).classify(pid);
        let name = info.as_ref().map(|i| i.display_name()).unwrap_or_default();
        match v {
            Verdict::Game(r) => println!("{pid} {name}: GAME ({r})"),
            Verdict::NotGame(r) => println!("{pid} {name}: not a game ({r})"),
        }
        return Ok(());
    }

    if !util::is_root() {
        bail!("bpfrag needs root (CAP_BPF, CAP_PERFMON and CAP_NET_ADMIN)");
    }
    if opts.selftest {
        if !selftest::run(&cfg)? {
            std::process::exit(1);
        }
        return Ok(());
    }
    let _lock = lock(&run_dir)?;

    if opts.restore {
        let n = Knobs::recover(&run_dir)?;
        stats::remove(&run_dir);
        info!(
            "{}",
            if n == 0 {
                "nothing to restore".to_string()
            } else {
                format!("restored {n} setting(s)")
            }
        );
        return Ok(());
    }

    if !opts.dry_run {
        match Knobs::recover(&run_dir) {
            Ok(0) => {}
            Ok(n) => warn!("a previous run did not shut down cleanly; restored {n} setting(s)"),
            Err(e) => warn!("could not replay old journal: {e:#}"),
        }
    }

    let mut open_object = MaybeUninit::uninit();
    let mut tuner = Tuner::init(&opts, cfg, &mut open_object)?;
    tuner.run(shutdown)
}
