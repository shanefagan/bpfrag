// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! A/B experiments: switch one setting off in a random share of matches,
//! so its effect can be measured without the comparison being skewed by
//! the time of day, the server or the map. Each match logs which arm it
//! got, and its health line ends with it, for `docs/scripts/matches.py`.
//!
//! The setting names match the sections of `docs/knobs.md`.

use anyhow::{Result, bail};

use crate::config::Profile;

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
