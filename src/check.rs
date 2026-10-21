// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan
//
// `bpfrag --check`: what will (and won't) work on this machine, and who
// else is tuning it.

use std::path::Path;

use crate::coexist;
use crate::config::Config;
use crate::net;
use crate::util::{is_root, read_trim, sysctl_path};

fn line(ok: Option<bool>, what: &str, detail: impl AsRef<str>) {
    let mark = match ok {
        Some(true) => " ok ",
        Some(false) => "FAIL",
        None => " -- ",
    };
    println!("[{mark}] {what:<20} {}", detail.as_ref());
}

fn kernel_version() -> (String, (u32, u32)) {
    let rel = read_trim("/proc/sys/kernel/osrelease").unwrap_or_default();
    let mut it = rel
        .split(|c: char| !c.is_ascii_digit())
        .filter_map(|x| x.parse::<u32>().ok());
    let v = (it.next().unwrap_or(0), it.next().unwrap_or(0));
    (rel, v)
}

pub fn run(cfg: &Config) -> bool {
    let mut fatal = false;
    let (rel, ver) = kernel_version();
    line(None, "kernel", &rel);

    let root = is_root();
    line(
        Some(root),
        "running as root",
        if root {
            "yes"
        } else {
            "no (needed to load BPF and change settings)"
        },
    );
    fatal |= !root;

    let btf = Path::new("/sys/kernel/btf/vmlinux").exists();
    line(
        Some(btf),
        "kernel BTF",
        if btf {
            "/sys/kernel/btf/vmlinux"
        } else {
            "missing (CONFIG_DEBUG_INFO_BTF)"
        },
    );
    fatal |= !btf;
    if btf {
        match crate::bpf::pick_hook(&cfg.general.hook) {
            Ok(h) => line(Some(true), "UDP counting hook", h.describe()),
            Err(e) => {
                line(Some(false), "UDP counting hook", format!("{e:#}"));
                fatal = true;
            }
        }
    }
    line(
        Some(true),
        "DSCP marker",
        if ver >= (6, 6) {
            "tcx link (auto-detached if bpfrag dies)"
        } else {
            "legacy tc filter (journalled for cleanup)"
        },
    );

    let ifaces = net::default_route_ifaces();
    if ifaces.is_empty() {
        line(
            None,
            "default route",
            "none found (set dscp.interfaces or --iface)",
        );
    }
    for i in &ifaces {
        let wireless = crate::wifi::is_wireless(&i.name);
        let kind = match (i.l2_len, wireless) {
            (14, true) => "wifi",
            (14, false) => "ethernet",
            _ => "L3 tunnel",
        };
        let co = if wireless {
            // Wi-Fi drivers rarely do coalescing; power save is the knob there.
            match crate::wifi::get_power_save(i.ifindex) {
                Ok(true) => "power save on, turned off during COMPETITIVE/INTENSE".to_string(),
                Ok(false) => "power save already off".to_string(),
                Err(e) => format!("power save unreadable via nl80211 ({e})"),
            }
        } else if i.physical {
            match net::get_coalesce(&i.name) {
                Ok(c) => format!("coalescing {}", c.describe()),
                Err(e) => format!("coalescing unsupported ({e})"),
            }
        } else {
            "virtual, no coalescing".into()
        };
        line(
            Some(true),
            "egress interface",
            format!("{} ({kind}, {}, {co})", i.name, net::driver(&i.name)),
        );
    }

    let mut missing: Vec<&str> = cfg
        .tiers
        .iter()
        .flat_map(|t| t.sysctl.keys())
        .filter(|k| !sysctl_path(k).is_some_and(|p| p.exists()))
        .map(String::as_str)
        .collect();
    missing.sort();
    missing.dedup();
    if missing.is_empty() {
        line(Some(true), "sysctls", "all present");
    } else {
        line(
            None,
            "sysctls",
            format!("not on this kernel (skipped): {}", missing.join(", ")),
        );
    }

    let bytes = read_trim("/proc/sys/vm/dirty_bytes").unwrap_or_default();
    let ratio = read_trim("/proc/sys/vm/dirty_ratio").unwrap_or_default();
    line(
        None,
        "writeback",
        if bytes != "0" && !bytes.is_empty() {
            format!("vm.dirty_bytes = {bytes}")
        } else {
            format!("vm.dirty_ratio = {ratio}% (tightened to bytes during COMPETITIVE/INTENSE)")
        },
    );

    println!();
    let (skip, note) = coexist::skip_set(cfg);
    match coexist::bpftune_pid() {
        Some(p) => line(
            Some(true),
            "bpftune",
            format!("running (pid {p}); {} sysctl(s) yielded to it", skip.len()),
        ),
        None => line(None, "bpftune", "not running"),
    }
    if let Some(n) = note {
        println!("       {n}");
    }
    match coexist::sched_ext() {
        Some((state, ops)) => line(
            None,
            "sched_ext",
            format!(
                "{state}{}: no overlap",
                ops.map(|o| format!(" ({o})")).unwrap_or_default()
            ),
        ),
        None => line(None, "sched_ext", "not available on this kernel"),
    }
    for n in coexist::neighbours()
        .into_iter()
        .filter(|n| !n.starts_with("sched_ext"))
    {
        line(None, "neighbour", n);
    }

    println!();
    if fatal {
        println!("bpfrag cannot run here yet; fix the FAIL lines above.");
    } else {
        println!("Ready. Try `sudo bpfrag --dry-run -v` and start a match.");
    }
    !fatal
}
