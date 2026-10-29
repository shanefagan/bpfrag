// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! A/B experiments: switch one setting off in a random share of matches,
//! so its effect can be measured without the comparison being skewed by
//! the time of day, the server or the map. Each match logs which arm it
//! got, and its health line ends with it, for `docs/scripts/matches.py`.
//!
//! The setting names match the sections of `docs/knobs.md`.
//!
//! `setting = "random"` tests one setting at a time without picking it by
//! hand: each period (a day from 05:00, or a boot) one is drawn from a pool,
//! then every match flips a coin for it as usual. The pick is saved in the
//! state directory, so restarting the daemon keeps it until the period ends.

use std::fs;
use std::path::Path;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::config::{Period, Pool, Profile};

/// What an experiment switches off in its "off" arm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Setting {
    /// Everything: the match is only measured, like a dry run.
    All,
    Dscp,
    WifiPowerSave,
    Coalescing,
    Writeback,
    Bulk,
    /// One or more sysctls, by name.
    Sysctls(Vec<&'static str>),
    /// A sysctl named in the config (`sysctl:net.core.busy_poll`).
    Sysctl(String),
}

/// `[experiment] setting` value that picks one from `pool` each period.
pub const RANDOM: &str = "random";

/// The pool for a wired connection: everything but Wi-Fi power save.
pub const WIRED_POOL: &[&str] = &[
    "dscp",
    "coalescing",
    "busy_polling",
    "socket_buffers",
    "backlog",
    "budget",
    "writeback",
    "bulk",
];

/// The pool for Wi-Fi: everything but NIC coalescing, which Wi-Fi drivers
/// generally don't support.
pub const WIFI_POOL: &[&str] = &[
    "dscp",
    "wifi_power_save",
    "busy_polling",
    "socket_buffers",
    "backlog",
    "budget",
    "writeback",
    "bulk",
];

/// The names `[experiment] setting` accepts, for messages and docs.
pub const NAMES: &[&str] = &[
    "all",
    "dscp",
    "wifi_power_save",
    "coalescing",
    "busy_polling",
    "socket_buffers",
    "backlog",
    "budget",
    "writeback",
    "bulk",
    "sysctl:<name>",
];

impl Setting {
    /// Parse a config value; `""` means no experiment.
    pub fn parse(name: &str) -> Result<Option<Setting>> {
        let s = match name.trim() {
            "" => return Ok(None),
            "all" => Setting::All,
            "dscp" => Setting::Dscp,
            "wifi_power_save" => Setting::WifiPowerSave,
            "coalescing" => Setting::Coalescing,
            "busy_polling" => Setting::Sysctls(vec!["net.core.busy_poll", "net.core.busy_read"]),
            "socket_buffers" => Setting::Sysctls(vec![
                "net.core.rmem_default",
                "net.core.rmem_max",
                "net.core.wmem_default",
                "net.core.wmem_max",
            ]),
            "backlog" => Setting::Sysctls(vec!["net.core.netdev_max_backlog"]),
            "budget" => Setting::Sysctls(vec![
                "net.core.netdev_budget",
                "net.core.netdev_budget_usecs",
            ]),
            "writeback" => Setting::Writeback,
            "bulk" => Setting::Bulk,
            other => match other.strip_prefix("sysctl:") {
                Some(k) if !k.is_empty() => Setting::Sysctl(k.to_string()),
                _ => bail!("unknown setting {other:?}; one of {}", NAMES.join(", ")),
            },
        };
        Ok(Some(s))
    }

    /// Switch this setting off in `p`.
    pub fn strip(&self, p: &mut Profile) {
        match self {
            Setting::All => {
                p.sysctl.clear();
                p.dscp = false;
                p.wifi_powersave_off = false;
                p.coalesce_usecs = None;
                p.writeback = None;
            }
            Setting::Dscp => p.dscp = false,
            Setting::WifiPowerSave => p.wifi_powersave_off = false,
            Setting::Coalescing => p.coalesce_usecs = None,
            Setting::Writeback => p.writeback = None,
            Setting::Bulk => {}
            Setting::Sysctls(keys) => {
                for k in keys {
                    p.sysctl.remove(*k);
                }
            }
            Setting::Sysctl(k) => {
                p.sysctl.remove(k);
            }
        }
    }

    /// Does the "off" arm also stop bulk demotion?
    pub fn stops_bulk(&self) -> bool {
        matches!(self, Setting::All | Setting::Bulk)
    }

    /// Does any tier set this at all? An experiment on something no tier
    /// changes would compare two identical arms.
    pub fn used_by(&self, profiles: &[Profile], bulk_enabled: bool) -> bool {
        profiles.iter().any(|p| match self {
            Setting::All => true,
            Setting::Dscp => p.dscp,
            Setting::WifiPowerSave => p.wifi_powersave_off,
            Setting::Coalescing => p.coalesce_usecs.is_some(),
            Setting::Writeback => p.writeback.is_some(),
            Setting::Bulk => bulk_enabled,
            Setting::Sysctls(keys) => keys.iter().any(|k| p.sysctl.contains_key(*k)),
            Setting::Sysctl(k) => p.sysctl.contains_key(k),
        })
    }
}

/// One match's draw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arm {
    /// The setting's config name, e.g. "busy_polling".
    pub name: String,
    pub setting: Setting,
    /// true: the match keeps the setting; false: it's switched off.
    pub on: bool,
}

impl Arm {
    /// "busy_polling on" / "busy_polling off", as logged and in the
    /// health line.
    pub fn label(&self) -> String {
        format!("{} {}", self.name, if self.on { "on" } else { "off" })
    }

    /// The profile this match uses.
    pub fn apply(&self, p: &mut Profile) {
        if !self.on {
            self.setting.strip(p);
        }
    }

    pub fn stops_bulk(&self) -> bool {
        !self.on && self.setting.stops_bulk()
    }
}

/// What kind of link the game will most likely use, for `pool = "auto"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Link {
    Wired,
    Wifi,
}

/// The setting names a pool stands for.
pub fn pool_names(pool: &Pool, link: Link) -> Vec<String> {
    let named = |n: &[&str]| n.iter().map(|s| s.to_string()).collect();
    match pool {
        Pool::List(l) => l.iter().map(|s| s.trim().to_string()).collect(),
        Pool::Named(n) if n == "wired" => named(WIRED_POOL),
        Pool::Named(n) if n == "wifi" => named(WIFI_POOL),
        Pool::Named(_) => match link {
            Link::Wired => named(WIRED_POOL),
            Link::Wifi => named(WIFI_POOL),
        },
    }
}

/// Which of `names` are worth an experiment here: some tier changes the
/// setting (bulk only counts when it's enabled), it isn't DSCP while bulk
/// demotion is on (the marker does both), and `would_change` says this
/// machine isn't already at its value (CachyOS already ships bpfrag's
/// writeback limits, say). Returns (kept, left out as already in place).
pub fn candidates(
    names: &[String],
    profiles: &[Profile],
    bulk_enabled: bool,
    mut would_change: impl FnMut(&Setting) -> bool,
) -> (Vec<(String, Setting)>, Vec<String>) {
    let mut keep = Vec::new();
    let mut in_place = Vec::new();
    for n in names {
        let Ok(Some(s)) = Setting::parse(n) else {
            continue;
        };
        if s == Setting::All || !s.used_by(profiles, bulk_enabled) {
            continue;
        }
        if s == Setting::Dscp && bulk_enabled {
            continue;
        }
        if would_change(&s) {
            keep.push((n.clone(), s));
        } else {
            in_place.push(n.clone());
        }
    }
    (keep, in_place)
}

/// The pick for one period, as saved in the state directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pick {
    /// The period it's for: a date ("2026-10-29") or a boot id.
    pub period: String,
    pub setting: String,
}

const PICK_FILE: &str = "experiment.json";

pub fn load_pick(state_dir: &Path) -> Option<Pick> {
    let t = fs::read_to_string(state_dir.join(PICK_FILE)).ok()?;
    serde_json::from_str(&t).ok()
}

pub fn save_pick(state_dir: &Path, pick: &Pick) -> std::io::Result<()> {
    fs::create_dir_all(state_dir)?;
    let tmp = state_dir.join(format!("{PICK_FILE}.tmp"));
    fs::write(&tmp, serde_json::to_string(pick).unwrap_or_default())?;
    fs::rename(tmp, state_dir.join(PICK_FILE))
}

/// The setting for `period`: the saved pick if it's for this period and
/// still a candidate, otherwise a new one drawn with `index(len)`. The
/// bool says whether it was drawn just now. None if there's no candidate.
pub fn pick_for(
    period: &str,
    saved: Option<&Pick>,
    candidates: &[String],
    index: impl FnOnce(usize) -> usize,
) -> Option<(String, bool)> {
    if candidates.is_empty() {
        return None;
    }
    if let Some(p) = saved.filter(|p| p.period == period && candidates.contains(&p.setting)) {
        return Some((p.setting.clone(), false));
    }
    let i = index(candidates.len()).min(candidates.len() - 1);
    Some((candidates[i].clone(), true))
}

/// A random index below `n`.
pub fn random_index(n: usize) -> usize {
    (random_unit() * n as f64) as usize
}

/// The current period's key: for `Day`, the local date of now minus five
/// hours, so a session that runs past midnight still counts as the evening
/// it started in; for `Boot`, the kernel's boot id.
pub fn period_key(period: Period) -> String {
    match period {
        Period::Day => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64);
            local_date(now - 5 * 3600)
        }
        Period::Boot => fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|s| s.trim().to_string())
            .unwrap_or_default(),
    }
}

/// "YYYY-MM-DD" in local time for a Unix time.
fn local_date(t: i64) -> String {
    let t = t as libc::time_t;
    // SAFETY: localtime_r only writes the tm we hand it.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return String::new();
    }
    format!(
        "{:04}-{:02}-{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday
    )
}

/// Draw an arm: the setting stays on with probability `keep`.
pub fn draw(name: &str, setting: &Setting, keep: f64) -> Arm {
    Arm {
        name: name.trim().to_string(),
        setting: setting.clone(),
        on: random_unit() < keep,
    }
}

/// A uniform number in [0, 1) from the kernel's random source.
fn random_unit() -> f64 {
    let mut b = [0u8; 8];
    // SAFETY: writes at most b.len() bytes into b.
    let n = unsafe { libc::getrandom(b.as_mut_ptr().cast(), b.len(), 0) };
    if n != b.len() as isize {
        // never expected; fall back to the clock's low bits
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        return f64::from(t % 1000) / 1000.0;
    }
    (u64::from_le_bytes(b) >> 11) as f64 / (1u64 << 53) as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::builtin_profiles;

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn pools_follow_the_link() {
        let auto = Pool::Named("auto".into());
        assert!(!pool_names(&auto, Link::Wired).contains(&"wifi_power_save".into()));
        assert!(pool_names(&auto, Link::Wired).contains(&"coalescing".into()));
        assert!(pool_names(&auto, Link::Wifi).contains(&"wifi_power_save".into()));
        assert!(!pool_names(&auto, Link::Wifi).contains(&"coalescing".into()));
        // a named pool ignores the link; a list is taken as given
        assert!(
            !pool_names(&Pool::Named("wired".into()), Link::Wifi)
                .contains(&"wifi_power_save".into())
        );
        assert_eq!(
            pool_names(&Pool::List(names(&["backlog"])), Link::Wifi),
            ["backlog"]
        );
        for n in WIRED_POOL.iter().chain(WIFI_POOL) {
            assert!(Setting::parse(n).unwrap().is_some(), "{n}");
        }
    }

    #[test]
    fn candidates_leave_out_what_cant_differ() {
        let profiles = builtin_profiles();
        let pool = pool_names(&Pool::Named("wired".into()), Link::Wired);
        // writeback already in place here, everything else would change
        let (keep, in_place) = candidates(&pool, &profiles, false, |s| *s != Setting::Writeback);
        let kept: Vec<&str> = keep.iter().map(|(n, _)| n.as_str()).collect();
        assert!(kept.contains(&"busy_polling") && kept.contains(&"dscp"));
        assert!(!kept.contains(&"bulk"), "bulk is off");
        assert_eq!(in_place, ["writeback"]);
        // with bulk on, bulk joins and dscp leaves (the marker does both)
        let (keep, _) = candidates(&pool, &profiles, true, |_| true);
        let kept: Vec<&str> = keep.iter().map(|(n, _)| n.as_str()).collect();
        assert!(kept.contains(&"bulk") && !kept.contains(&"dscp"));
    }

    #[test]
    fn a_pick_lasts_its_period() {
        let c = names(&["backlog", "budget", "busy_polling"]);
        let (first, new) = pick_for("2026-10-29", None, &c, |_| 1).unwrap();
        assert_eq!((first.as_str(), new), ("budget", true));
        let saved = Pick {
            period: "2026-10-29".into(),
            setting: first,
        };
        // same day: kept, whatever the dice say
        assert_eq!(
            pick_for("2026-10-29", Some(&saved), &c, |_| 2),
            Some(("budget".into(), false))
        );
        // next day: drawn again
        assert_eq!(
            pick_for("2026-10-30", Some(&saved), &c, |_| 2),
            Some(("busy_polling".into(), true))
        );
        // the saved one no longer a candidate: drawn again
        let fewer = names(&["backlog"]);
        assert_eq!(
            pick_for("2026-10-29", Some(&saved), &fewer, |_| 0),
            Some(("backlog".into(), true))
        );
        assert_eq!(pick_for("2026-10-29", None, &[], |_| 0), None);
    }

    #[test]
    fn picks_are_saved_and_read_back() {
        let dir = std::env::temp_dir().join(format!("bpfrag-pick-{}", std::process::id()));
        let p = Pick {
            period: "2026-10-29".into(),
            setting: "backlog".into(),
        };
        save_pick(&dir, &p).unwrap();
        assert_eq!(load_pick(&dir), Some(p));
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(load_pick(&dir), None);
    }

    #[test]
    fn days_start_at_five_in_the_morning() {
        // local_date itself follows TZ; the key shifts by five hours
        let k = period_key(Period::Day);
        assert_eq!(k.len(), 10, "{k}");
        assert_eq!(local_date(0).len(), 10);
        let (a, b) = (random_index(3), random_index(1));
        assert!(a < 3 && b == 0);
    }

    #[test]
    fn names_parse_and_strip() {
        assert_eq!(Setting::parse("").unwrap(), None);
        assert!(Setting::parse("turbo").is_err());
        assert!(Setting::parse("sysctl:").is_err());
        for n in NAMES.iter().filter(|n| !n.contains('<')) {
            assert!(Setting::parse(n).unwrap().is_some(), "{n}");
        }
        let mut p = builtin_profiles()[2].clone();
        assert!(p.sysctl.contains_key("net.core.busy_poll"));
        Setting::parse("busy_polling")
            .unwrap()
            .unwrap()
            .strip(&mut p);
        assert!(!p.sysctl.contains_key("net.core.busy_poll"));
        assert!(!p.sysctl.contains_key("net.core.busy_read"));
        assert!(
            p.sysctl.contains_key("net.core.rmem_max"),
            "only that setting"
        );
        assert!(p.dscp);

        let mut all = builtin_profiles()[2].clone();
        Setting::All.strip(&mut all);
        assert!(all.sysctl.is_empty() && !all.dscp && !all.wifi_powersave_off);
        assert!(all.coalesce_usecs.is_none() && all.writeback.is_none());
    }

    #[test]
    fn the_on_arm_changes_nothing() {
        let base = builtin_profiles()[1].clone();
        let arm = Arm {
            name: "dscp".into(),
            setting: Setting::Dscp,
            on: true,
        };
        let mut p = base.clone();
        arm.apply(&mut p);
        assert_eq!(p.dscp, base.dscp);
        assert_eq!(arm.label(), "dscp on");
        let off = Arm { on: false, ..arm };
        off.apply(&mut p);
        assert!(!p.dscp);
        assert_eq!(off.label(), "dscp off");
    }

    #[test]
    fn unused_settings_are_caught() {
        let profiles = builtin_profiles();
        assert!(Setting::Dscp.used_by(&profiles, false));
        assert!(!Setting::Bulk.used_by(&profiles, false));
        assert!(Setting::Bulk.used_by(&profiles, true));
        assert!(!Setting::Sysctl("net.ipv4.tcp_ecn".into()).used_by(&profiles, false));
    }

    #[test]
    fn draws_are_roughly_fair() {
        let s = Setting::Dscp;
        let on = (0..4000).filter(|_| draw("dscp", &s, 0.5).on).count();
        assert!((1700..2300).contains(&on), "{on} of 4000");
        assert!((0..100).all(|_| draw("dscp", &s, 1.0).on));
        assert!((0..100).all(|_| !draw("dscp", &s, 0.0).on));
    }
}
