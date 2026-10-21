// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan
//
// Who else is tuning this machine?
//
//   bpftune     owns buffer/backlog sysctls and switches its own tuners off
//               when anyone else writes them -> we yield those while it runs.
//   sched_ext   owns CPU scheduling; bpfrag never touches scheduling, so
//               there is nothing to share. Reported in --check for information.
//   gamemode    CPU governor, GPU, process niceness: complementary.
//   tuned       its network-latency profile sets busy_read/busy_poll; our
//               "don't clobber" restore rule keeps us out of its way.

use std::collections::HashSet;
use std::fs;

use crate::config::{BPFTUNE_SYSCTLS, Config};
use crate::util::read_trim;

/// First pid whose comm is exactly `name`.
pub fn find_process(name: &str) -> Option<u32> {
    let rd = fs::read_dir("/proc").ok()?;
    for e in rd.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        if read_trim(format!("/proc/{pid}/comm")).ok().as_deref() == Some(name) {
            return Some(pid);
        }
    }
    None
}

pub fn bpftune_pid() -> Option<u32> {
    find_process("bpftune")
}

/// (state, scheduler name) from /sys/kernel/sched_ext.
pub fn sched_ext() -> Option<(String, Option<String>)> {
    let state = read_trim("/sys/kernel/sched_ext/state").ok()?;
    let ops = read_trim("/sys/kernel/sched_ext/root/ops")
        .ok()
        .filter(|s| !s.is_empty());
    Some((state, ops))
}

pub fn tuned_profile() -> Option<String> {
    find_process("tuned")?;
    Some(read_trim("/etc/tuned/active_profile").unwrap_or_else(|_| "?".into()))
}

/// Sysctls we must leave alone right now, plus a note explaining why.
pub fn skip_set(cfg: &Config) -> (HashSet<String>, Option<String>) {
    let mode = cfg.general.bpftune.as_str();
    let pid = bpftune_pid();
    let yield_now = match mode {
        "yield" => true,
        "ignore" => false,
        _ => pid.is_some(),
    };
    if !yield_now {
        let note = pid.map(|p| {
            format!("bpftune (pid {p}) is running and bpftune = \"ignore\": it will disable its own tuners when we write their sysctls")
        });
        return (HashSet::new(), note);
    }
    let ours: HashSet<&str> = cfg
        .tiers
        .iter()
        .flat_map(|t| t.sysctl.keys().map(String::as_str))
        .collect();
    let skip: HashSet<String> = BPFTUNE_SYSCTLS
        .iter()
        .filter(|k| ours.contains(*k))
        .map(|s| s.to_string())
        .collect();
    let who = match pid {
        Some(p) => format!("bpftune (pid {p}) is running"),
        None => "bpftune = \"yield\"".into(),
    };
    let note = (!skip.is_empty()).then(|| {
        let mut v: Vec<&str> = skip.iter().map(String::as_str).collect();
        v.sort();
        format!("{who}: leaving {} to it", v.join(", "))
    });
    (skip, note)
}

/// Human notes for --check and the stats output.
pub fn neighbours() -> Vec<String> {
    let mut v = Vec::new();
    if let Some((state, ops)) = sched_ext()
        && state == "enabled"
    {
        v.push(format!(
            "sched_ext scheduler {} is active: no overlap, bpfrag never touches CPU scheduling",
            ops.unwrap_or_else(|| "?".into())
        ));
    }
    if find_process("gamemoded").is_some() {
        v.push(
            "gamemode is running: complementary (it does CPU/GPU, bpfrag does networking)".into(),
        );
    }
    if let Some(p) = tuned_profile() {
        v.push(format!(
            "tuned is running (profile {p}): if it sets busy_read/busy_poll too, bpfrag leaves its values alone on restore"
        ));
    }
    v
}
