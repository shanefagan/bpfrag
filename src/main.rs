// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! bpfrag: eBPF-driven, self-reverting network tuning for competitive gaming.
//!
//! This file is the command line: the options, the one-shot commands
//! (`--check`, `--monitor`, `--restore`, ...), and starting the daemon in
//! [`daemon`]. See README.md for the layout of the rest.

mod bpf;
mod bpf_intf;
mod bpf_skel;
mod cli;
mod config;
mod daemon;
mod detect;
mod health;
mod logger;
mod net;
mod stats;
mod tune;
mod util;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use log::{info, warn};

use config::{BpftuneMode, Config, Tier};
use detect::classify::{Classifier, Verdict};
use tune::Knobs;

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
/// Each match also gets a health report (packet gaps, drop counters) in
/// --monitor and the log; --dry-run measures without changing anything.
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
    #[clap(short = 't', long, value_enum)]
    tier: Option<Tier>,

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

    /// How to share sysctls with bpftune.
    #[clap(long, value_enum)]
    bpftune: Option<BpftuneMode>,

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

    /// Don't run: push test packets through the tc programs on this kernel
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
        if self.tier.is_some() {
            cfg.detect.pin_tier = self.tier;
        }
        if let Some(d) = &self.dscp {
            if d.eq_ignore_ascii_case("off") {
                for p in cfg.profiles.iter_mut() {
                    p.dscp = false;
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
        if let Some(b) = self.bpftune {
            cfg.general.bpftune = b;
        }
        cfg.validate()
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();
    logger::init(opts.verbose);

    let mut cfg = Config::load(opts.config.as_deref())?;
    opts.apply(&mut cfg)?;
    let run_dir = PathBuf::from(&cfg.general.run_dir);

    // SIGINT/SIGTERM/SIGHUP ask the daemon (or --monitor) to stop cleanly,
    // so settings are restored on the way out.
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown = shutdown.clone();
        ctrlc::set_handler(move || shutdown.store(true, Ordering::Relaxed))
            .context("setting signal handler")?;
    }

    // Commands that only read: no root needed.
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
        if !cli::check::run(&cfg) {
            std::process::exit(1);
        }
        return Ok(());
    }
    if let Some(pid) = opts.classify {
        let (v, info) = Classifier::new(&cfg.classify).classify(pid);
        let name = info.as_ref().map(|i| i.display_name()).unwrap_or_default();
        match v {
            Verdict::Game(r) => println!("{pid} {name}: GAME ({r})"),
            v => println!("{pid} {name}: not a game ({})", v.reason()),
        }
        return Ok(());
    }

    // Everything below loads BPF or changes settings.
    if !util::is_root() {
        bail!("bpfrag needs root (CAP_BPF, CAP_PERFMON and CAP_NET_ADMIN)");
    }
    if opts.selftest {
        if !cli::selftest::run(&cfg)? {
            std::process::exit(1);
        }
        return Ok(());
    }
    let _lock = daemon::lock(&run_dir)?;

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

    // A journal left by a crashed run: put those settings back first.
    if !opts.dry_run {
        match Knobs::recover(&run_dir) {
            Ok(0) => {}
            Ok(n) => warn!("a previous run did not shut down cleanly; restored {n} setting(s)"),
            Err(e) => warn!("could not replay old journal: {e:#}"),
        }
    }

    let run = daemon::RunOpts {
        dry_run: opts.dry_run,
        libbpf_debug: opts.verbose >= 2,
        stats_every: opts.stats.filter(|s| *s > 0.0).map(Duration::from_secs_f64),
    };
    daemon::run(&run, cfg, shutdown)
}
#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn man_page_lists_every_flag() {
        let man =
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/dist/bpfrag.8")).replace("\\-", "-");
        for arg in Opts::command().get_arguments() {
            if let Some(long) = arg.get_long() {
                assert!(
                    man.contains(&format!("--{long}")),
                    "dist/bpfrag.8 lacks --{long}"
                );
            }
        }
    }

    #[test]
    fn packaging_versions_match_cargo() {
        let ver = env!("CARGO_PKG_VERSION");
        let spec = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/packaging/rpm/bpfrag.spec"
        ));
        assert!(
            spec.lines()
                .any(|l| l.starts_with("Version:") && l.split_whitespace().nth(1) == Some(ver)),
            "packaging/rpm/bpfrag.spec Version is not {ver}"
        );
        let changelog = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/packaging/debian/changelog"
        ));
        assert!(
            changelog.starts_with(&format!("bpfrag ({ver}-")),
            "packaging/debian/changelog's newest entry is not {ver}"
        );
        let man = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/dist/bpfrag.8"));
        assert!(
            man.contains(&format!("\"bpfrag {ver}\"")),
            "dist/bpfrag.8 is not {ver}"
        );
    }
}
