// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! `bpfrag --check`: what will (and won't) work on this machine, and who
//! else is tuning it.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use crate::config::Config;
use crate::net;
use crate::tune::{coexist, target_for};
use crate::util::{is_root, norm_ws, read_trim, sysctl_path};

/// One report line: `ok` is pass / fail / just information (None).
fn line(ok: Option<bool>, what: &str, detail: impl AsRef<str>) {
    let mark = match ok {
        Some(true) => " ok ",
        Some(false) => "FAIL",
        None => " -- ",
    };
    println!("[{mark}] {what:<20} {}", detail.as_ref());
}

pub fn run(cfg: &Config) -> bool {
    let mut fatal = false;
    let rel = read_trim("/proc/sys/kernel/osrelease").unwrap_or_default();
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
        match crate::bpf::check_kernel() {
            Ok(()) => line(Some(true), "kernel hooks", "socket tracepoints and tcx"),
            Err(e) => {
                line(Some(false), "kernel hooks", format!("{e:#}"));
                fatal = true;
            }
        }
    }

    let ifaces = net::default_route_ifaces();
    if ifaces.is_empty() {
        line(
            None,
            "default route",
            "none found (set dscp.interfaces or --iface)",
        );
    }
    for i in &ifaces {
        let wireless = net::is_wireless(&i.name);
        let kind = match (i.l2_len, wireless) {
            (14, true) => "wifi",
            (14, false) => "ethernet",
            _ => "L3 tunnel",
        };
        let co = if wireless {
            // Wi-Fi drivers rarely do coalescing; power save is the knob there.
            match net::nl80211::get_power_save(i.ifindex) {
                Ok(true) => match cfg.tiers_where(|p| p.wifi_powersave_off) {
                    Some(t) => format!("power save on, turned off during {t}"),
                    None => "power save on, left alone (no tier turns it off)".into(),
                },
                Ok(false) => "power save already off".into(),
                Err(e) => format!("power save unreadable via nl80211 ({e})"),
            }
        } else if i.physical {
            match net::ethtool::get_coalesce(&i.name) {
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
        .profiles
        .iter()
        .flat_map(|p| p.sysctl.keys())
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
    let now = if bytes != "0" && !bytes.is_empty() {
        format!("vm.dirty_bytes = {bytes}")
    } else {
        format!("vm.dirty_ratio = {ratio}%")
    };
    let during = match cfg.tiers_where(|p| p.writeback.is_some()) {
        Some(t) => format!("tightened during {t} if higher"),
        None => "left alone".into(),
    };
    line(None, "writeback", format!("{now} ({during})"));

    println!();
    let (skip, note) = coexist::skip_set(cfg);
    settings(cfg, &skip);
    context();

    println!();
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

/// Every sysctl bpfrag sets: its value now, and what each tier would make
/// it. Distros ship different defaults, so this is where they show.
fn settings(cfg: &Config, skip: &HashSet<String>) {
    let mut keys: Vec<&String> = cfg.profiles.iter().flat_map(|p| p.sysctl.keys()).collect();
    keys.sort();
    keys.dedup();
    println!("Settings now, and what each tier would set (\"=\" means it already holds that):");
    for k in keys {
        let Some(cur) = sysctl_path(k).and_then(|p| read_trim(p).ok()) else {
            println!("  {k:<32} not on this kernel");
            continue;
        };
        let cur = norm_ws(&cur);
        let tiers: Vec<String> = cfg
            .profiles
            .iter()
            .filter_map(|p| {
                let v = p.sysctl.get(k)?;
                let t = target_for(v, &cur).unwrap_or_else(|| format!("bad value {v:?}"));
                let t = if t == cur { "=".into() } else { t };
                Some(format!("{} {t}", p.tier))
            })
            .collect();
        let note = if skip.contains(k.as_str()) {
            " (left to bpftune)"
        } else {
            ""
        };
        println!("  {k:<32} {cur:<12} {}{note}", tiers.join(", "));
    }
}

/// Things bpfrag doesn't change that decide how much its settings matter.
fn context() {
    println!();
    let sysctl = |k: &str| {
        sysctl_path(k)
            .and_then(|p| read_trim(p).ok())
            .unwrap_or_else(|| "?".into())
    };
    line(
        None,
        "default qdisc",
        format!(
            "{} (new interfaces' queues)",
            sysctl("net.core.default_qdisc")
        ),
    );
    line(
        None,
        "TCP congestion",
        format!(
            "{} (how much queue downloads build)",
            sysctl("net.ipv4.tcp_congestion_control")
        ),
    );
    let rel = read_trim("/proc/sys/kernel/osrelease").unwrap_or_default();
    match kernel_config(&rel) {
        Some(c) => {
            let hz = config_value(&c, "CONFIG_HZ").unwrap_or("?");
            let preempt = [
                ("PREEMPT_RT", "rt"),
                ("PREEMPT_LAZY", "lazy"),
                ("PREEMPT", "full"),
                ("PREEMPT_VOLUNTARY", "voluntary"),
                ("PREEMPT_NONE", "none"),
            ]
            .into_iter()
            .find(|(k, _)| config_value(&c, &format!("CONFIG_{k}")) == Some("y"))
            .map_or("?", |(_, m)| m);
            // With PREEMPT_DYNAMIC the build choice is only the default:
            // debugfs shows the live mode as "(full)", and preempt= on the
            // command line overrides it at boot.
            let live = read_trim("/sys/kernel/debug/sched/preempt")
                .ok()
                .and_then(|s| {
                    s.split_whitespace()
                        .find_map(|w| w.strip_prefix('(')?.strip_suffix(')').map(String::from))
                });
            let cmdline = read_trim("/proc/cmdline").unwrap_or_default();
            let boot = cmdline
                .split_whitespace()
                .find_map(|w| w.strip_prefix("preempt="));
            let dynamic = config_value(&c, "CONFIG_PREEMPT_DYNAMIC") == Some("y");
            let mode = match (live, boot) {
                (Some(m), _) => format!("preemption {m}"),
                (None, Some(m)) => format!("preemption {m} (from the command line)"),
                (None, None) if dynamic => format!("preemption {preempt} by default"),
                (None, None) => format!("preemption {preempt}"),
            };
            line(None, "kernel build", format!("HZ={hz}, {mode}"));
        }
        None => line(
            None,
            "kernel build",
            "config not found (/boot or /proc/config.gz)",
        ),
    }
    let nm =
        Path::new("/etc/NetworkManager").exists() || Path::new("/usr/lib/NetworkManager").exists();
    if nm && nm_wifi_powersave(Path::new("/")).is_none() {
        line(
            None,
            "NM wifi.powersave",
            "not set (the driver's default, usually on)",
        );
    }
    if let Some((v, file)) = nm_wifi_powersave(Path::new("/")) {
        let what = match v.as_str() {
            "0" => "default (the driver's choice)",
            "1" => "ignore (NetworkManager leaves it alone)",
            "2" => "disable",
            "3" => "enable",
            _ => "unknown value",
        };
        line(
            None,
            "NM wifi.powersave",
            format!("{v} = {what}, from {file}"),
        );
    }
}

/// This kernel's build config: /boot/config-<release> (Debian, Ubuntu,
/// Fedora) or /proc/config.gz (Arch, CachyOS).
fn kernel_config(release: &str) -> Option<String> {
    if let Ok(t) = std::fs::read_to_string(format!("/boot/config-{release}")) {
        return Some(t);
    }
    let out = std::process::Command::new("gzip")
        .args(["-dc", "/proc/config.gz"])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn config_value<'a>(config: &'a str, key: &str) -> Option<&'a str> {
    config.lines().find_map(|l| {
        l.strip_prefix(key)
            .and_then(|r| r.strip_prefix('='))
            .map(|v| v.trim_matches('"'))
    })
}

/// NetworkManager's default `wifi.powersave` and the file that sets it,
/// following its merge order: NetworkManager.conf, then conf.d files by
/// name, where /etc beats /run beats /usr/lib for the same name. None if
/// NetworkManager isn't installed or nothing sets it.
fn nm_wifi_powersave(root: &Path) -> Option<(String, String)> {
    let etc = root.join("etc/NetworkManager");
    if !etc.exists() && !root.join("usr/lib/NetworkManager").exists() {
        return None;
    }
    let mut files: Vec<std::path::PathBuf> = vec![etc.join("NetworkManager.conf")];
    let mut by_name: BTreeMap<String, std::path::PathBuf> = BTreeMap::new();
    for dir in [
        "usr/lib/NetworkManager/conf.d",
        "run/NetworkManager/conf.d",
        "etc/NetworkManager/conf.d",
    ] {
        let Ok(rd) = std::fs::read_dir(root.join(dir)) else {
            continue;
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.ends_with(".conf") {
                by_name.insert(name, e.path());
            }
        }
    }
    files.extend(by_name.into_values());
    let mut found = None;
    for f in files {
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        if let Some(v) = wifi_powersave_in(&text) {
            let shown = f
                .strip_prefix(root)
                .map(|p| format!("/{}", p.display()))
                .unwrap_or_else(|_| f.display().to_string());
            found = Some((v, shown));
        }
    }
    found
}

/// The last `wifi.powersave` in a `[connection...]` section of one file.
fn wifi_powersave_in(text: &str) -> Option<String> {
    let mut in_conn = false;
    let mut found = None;
    for l in text.lines().map(str::trim) {
        if l.starts_with('[') {
            in_conn = l.starts_with("[connection");
        } else if in_conn {
            if let Some((k, v)) = l.split_once('=') {
                if k.trim() == "wifi.powersave" {
                    found = Some(v.trim().to_string());
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_kernel_config_values() {
        let c = "# CONFIG_HZ_250 is not set\nCONFIG_HZ_1000=y\nCONFIG_HZ=1000\nCONFIG_DEFAULT_TCP_CONG=\"cubic\"\n";
        assert_eq!(config_value(c, "CONFIG_HZ"), Some("1000"));
        assert_eq!(config_value(c, "CONFIG_DEFAULT_TCP_CONG"), Some("cubic"));
        assert_eq!(config_value(c, "CONFIG_HZ_250"), None);
    }

    #[test]
    fn network_manager_merge_order() {
        let root = std::env::temp_dir().join(format!("bpfrag-nm-{}", std::process::id()));
        let w = |p: &str, t: &str| {
            let f = root.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, t).unwrap();
        };
        // Ubuntu's package file, then a user's override with the same name
        // in /etc, then a later file that only sets something else.
        w(
            "etc/NetworkManager/NetworkManager.conf",
            "[main]\nplugins=keyfile\n",
        );
        w(
            "usr/lib/NetworkManager/conf.d/default-wifi-powersave-on.conf",
            "[connection]\nwifi.powersave = 3\n",
        );
        assert_eq!(
            nm_wifi_powersave(&root),
            Some((
                "3".into(),
                "/usr/lib/NetworkManager/conf.d/default-wifi-powersave-on.conf".into()
            ))
        );
        w(
            "etc/NetworkManager/conf.d/default-wifi-powersave-on.conf",
            "[connection]\nwifi.powersave = 2\n",
        );
        w(
            "etc/NetworkManager/conf.d/zz-dns.conf",
            "[main]\ndns=none\n[device]\nwifi.powersave=3\n",
        );
        assert_eq!(
            nm_wifi_powersave(&root),
            Some((
                "2".into(),
                "/etc/NetworkManager/conf.d/default-wifi-powersave-on.conf".into()
            ))
        );
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(nm_wifi_powersave(&root), None);
    }
}
