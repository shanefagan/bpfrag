// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan
//
// Configuration: compiled-in defaults, optionally overridden by a TOML file
// (default /etc/bpfrag/bpfrag.toml), then by command line flags. Every key
// is optional; anything you leave out keeps its default.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub const DEFAULT_CONFIG: &str = "/etc/bpfrag/bpfrag.toml";

pub const TIER_NAMES: [&str; 3] = ["CASUAL", "COMPETITIVE", "INTENSE"];

pub fn tier_index(name: &str) -> Option<usize> {
    TIER_NAMES.iter().position(|t| t.eq_ignore_ascii_case(name))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct General {
    /// Where the stats file and the restore journal live (tmpfs, so a
    /// reboot clears it together with the sysctls it describes).
    pub run_dir: String,
    /// "auto", "tracepoint" or "fexit"
    pub hook: String,
    /// Sampling window in milliseconds.
    pub tick_ms: u64,
    /// Sharing sysctls with bpftune:
    ///   "auto"   - yield bpftune's sysctls while bpftune is running (default)
    ///   "yield"  - never touch bpftune's sysctls
    ///   "ignore" - write them anyway (bpftune will disable its own tuners)
    pub bpftune: String,
}

impl Default for General {
    fn default() -> Self {
        Self {
            run_dir: "/run/bpfrag".into(),
            hook: "auto".into(),
            tick_ms: 1000,
            bpftune: "auto".into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Detect {
    /// Smoothed packets/s (tx+rx) before a process looks like live netcode.
    pub min_pps: u32,
    /// Each direction must carry at least this much: games both send input
    /// and receive snapshots, one-way streams (mDNS, DNS bursts) don't.
    pub min_dir_pps: u32,
    /// Tier thresholds (smoothed pps) and the hysteresis margin around them.
    pub competitive_pps: u32,
    pub intense_pps: u32,
    pub margin: u32,
    /// A window at or below this is "quiet".
    pub idle_pps: u32,
    /// Consecutive steady windows needed to start a session.
    pub steady_windows: u32,
    /// Windows used for smoothing / jitter.
    pub history: usize,
    /// Mean absolute deviation / mean. Tick-driven netcode is very regular.
    pub max_jitter: f64,
    /// Average UDP payload must be below this (bulk QUIC/torrents sit ~1200+).
    pub max_avg_packet: u32,
    /// Quiet seconds before the session ends and everything is reverted.
    pub linger_secs: u64,
    /// Minimum seconds between tier changes.
    pub dwell_secs: u64,
    /// Use this tier for every match instead of following the tick rate.
    pub pin_tier: Option<String>,
}

impl Default for Detect {
    fn default() -> Self {
        Self {
            min_pps: 25,
            min_dir_pps: 5,
            competitive_pps: 70,
            intense_pps: 140,
            margin: 15,
            idle_pps: 10,
            steady_windows: 3,
            history: 8,
            max_jitter: 0.5,
            max_avg_packet: 1100,
            linger_secs: 15,
            dwell_secs: 5,
            pin_tier: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Classify {
    /// Process (comm or exe name) globs that are always games.
    pub allow: Vec<String>,
    /// Globs that are never games (browsers, voice chat, torrents...).
    pub deny: Vec<String>,
    /// Ancestor process globs that mark their descendants as games.
    pub launchers: Vec<String>,
    /// Substrings of exe path / cmdline that mean "this lives in a game library".
    pub game_paths: Vec<String>,
    /// If false, the built-in lists are replaced instead of extended.
    pub use_builtin_lists: bool,
}

impl Default for Classify {
    fn default() -> Self {
        Self {
            allow: vec![],
            deny: vec![],
            launchers: vec![],
            game_paths: vec![],
            use_builtin_lists: true,
        }
    }
}

pub const BUILTIN_DENY: &[&str] = &[
    // browsers (QUIC is UDP and bursty enough to fool a global counter)
    "firefox*",
    "librewolf*",
    "waterfox*",
    "floorp*",
    "zen",
    "zen-bin",
    "chrome*",
    "chromium*",
    "google-chrome*",
    "brave*",
    "vivaldi*",
    "opera*",
    "msedge*",
    "microsoft-edge*",
    "thorium*",
    "epiphany*",
    "falkon",
    "qutebrowser*",
    "Isolated Web Co",
    "Web Content",
    "Socket Process",
    "RDD Process",
    // voice / chat (a 50 pkt/s Opus stream looks a lot like a 50 Hz game)
    "discord*",
    "vesktop*",
    "webcord*",
    "legcord*",
    "armcord*",
    "equibop*",
    "teamspeak*",
    "ts3client*",
    "mumble*",
    "element*",
    "signal*",
    "telegram*",
    "slack*",
    "zoom*",
    "teams*",
    "skype*",
    "whatsapp*",
    "obs",
    // p2p / sync
    "qbittorrent*",
    "transmission*",
    "deluge*",
    "rtorrent",
    "aria2c",
    "ktorrent",
    "fragments",
    "tixati",
    "syncthing",
    "rslsync",
    "resilio*",
    // system & network plumbing
    "systemd-resolve*",
    "systemd-timesyn*",
    "avahi-daemon",
    "NetworkManager",
    "dnsmasq",
    "chronyd",
    "ntpd",
    "tailscaled",
    "zerotier-one",
    "nebula",
    "netbird*",
    "kdeconnectd",
    "gsconnect*",
    "pipewire*",
    "wireplumber",
    "pulseaudio",
    "spotify*",
    "kodi*",
    "vlc",
    "mpv",
    "sunshine",
    "parsec*",
    // the Steam client itself (its children are still eligible via launchers)
    "steam",
    "steamwebhelper",
    "steamservice*",
];

pub const BUILTIN_LAUNCHERS: &[&str] = &[
    "steam",
    "reaper",
    "pressure-vessel*",
    "steam-runtime*",
    "srt-bwrap",
    "gamescope*",
    "gamemoderun",
    "game-perf*",
    "lutris",
    "heroic",
    "legendary",
    "gogdl",
    "nile",
    "bottles*",
    "umu-run",
    "umu",
    "minigalaxy",
    "itch",
    "faugus*",
    "proton",
    "wine*",
];

pub const BUILTIN_GAME_PATHS: &[&str] = &[
    "steamapps/common/",
    "steamapps/compatdata/",
    "/Games/",
    "/.local/share/lutris/",
    "/heroic/",
];

/// Sysctls bpftune tunes itself. bpftune's sysctl watcher disables the
/// owning tuner as soon as any other process writes one of these, so while
/// bpftune runs we leave them to it (it sizes them from real drop data).
pub const BPFTUNE_SYSCTLS: &[&str] = &[
    // net_buffer tuner
    "net.core.netdev_max_backlog",
    "net.core.flow_limit_cpu_bitmap",
    "net.core.netdev_budget",
    "net.core.netdev_budget_usecs",
    // udp_buffer tuner
    "net.ipv4.udp_mem",
    "net.core.rmem_max",
    "net.core.rmem_default",
    // tcp_buffer tuner
    "net.ipv4.tcp_rmem",
    "net.ipv4.tcp_wmem",
    "net.ipv4.tcp_mem",
    "net.ipv4.tcp_moderate_rcvbuf",
    "net.ipv4.tcp_no_metrics_save",
    "net.ipv4.tcp_no_ssthresh_metrics_save",
    "net.core.high_order_alloc_disable",
    "net.ipv4.tcp_syncookies",
    "net.ipv4.tcp_max_syn_backlog",
    "net.ipv4.tcp_max_orphans",
    // ip_frag / route tuners
    "net.ipv4.ipfrag_high_thresh",
    "net.ipv6.ip6frag_high_thresh",
    "net.ipv6.route.max_size",
];

impl Classify {
    fn merged(list: &[String], builtin: &[&str], use_builtin: bool) -> Vec<String> {
        let mut out: Vec<String> = if use_builtin {
            builtin.iter().map(|s| s.to_string()).collect()
        } else {
            vec![]
        };
        out.extend(list.iter().cloned());
        out
    }
    pub fn deny_list(&self) -> Vec<String> {
        Self::merged(&self.deny, BUILTIN_DENY, self.use_builtin_lists)
    }
    pub fn launcher_list(&self) -> Vec<String> {
        Self::merged(&self.launchers, BUILTIN_LAUNCHERS, self.use_builtin_lists)
    }
    pub fn game_path_list(&self) -> Vec<String> {
        Self::merged(&self.game_paths, BUILTIN_GAME_PATHS, self.use_builtin_lists)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Dscp {
    /// DSCP for game packets: a class name (CS4, EF, AF41...) or 0-63.
    /// CS4 is RFC 4594 "real-time interactive", the class meant for gaming,
    /// and maps to the WMM video queue on Wi-Fi (RFC 8325).
    pub class: String,
    /// Rewrite packets the game already marked itself.
    #[serde(rename = "override")]
    pub override_app: bool,
    /// Also set skb->priority so pfifo_fast/prio qdiscs use the interactive band.
    pub set_priority: bool,
    /// Interfaces to tune and mark on. Empty = the ones with a default route.
    pub interfaces: Vec<String>,
}

impl Default for Dscp {
    fn default() -> Self {
        Self {
            class: "CS4".into(),
            override_app: false,
            set_priority: true,
            interfaces: vec![],
        }
    }
}

pub fn parse_dscp(s: &str) -> Result<u8> {
    let up = s.trim().to_ascii_uppercase();
    let v = match up.as_str() {
        "BE" | "CS0" | "DF" => 0,
        "CS1" => 8,
        "CS2" => 16,
        "CS3" => 24,
        "CS4" => 32,
        "CS5" => 40,
        "CS6" => 48,
        "CS7" => 56,
        "EF" => 46,
        "VA" | "VOICE-ADMIT" => 44,
        x if x.len() == 4 && x.starts_with("AF") => {
            let c = x.as_bytes()[2].wrapping_sub(b'0');
            let d = x.as_bytes()[3].wrapping_sub(b'0');
            if !(1..=4).contains(&c) || !(1..=3).contains(&d) {
                bail!("bad DSCP class {s}");
            }
            c * 8 + d * 2
        }
        x => x
            .parse::<u8>()
            .with_context(|| format!("bad DSCP value {s}"))?,
    };
    if v > 63 {
        bail!("DSCP {v} out of range (0-63)");
    }
    Ok(v)
}

/// Dirty page writeback limits held during a match. Only ever *tightens*:
/// if the current limit is already lower, nothing changes.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Writeback {
    /// vm.dirty_bytes, in MiB
    pub dirty_mb: u64,
    /// vm.dirty_background_bytes, in MiB
    pub background_mb: u64,
}

/// One tuning tier. Option fields: None = leave that knob alone.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Tier {
    pub name: String,
    /// sysctl -> value. A ">=" prefix means "raise only": never lower a value
    /// the user already set higher (applied per field for multi-value keys).
    pub sysctl: BTreeMap<String, String>,
    /// NIC interrupt coalescing (rx/tx usecs) on the game's interface(s).
    pub coalesce_usecs: Option<u32>,
    /// DSCP-mark the game's UDP packets.
    pub dscp: bool,
    /// Keep background writeback (downloads, shader caches) from building
    /// up huge dirty backlogs that flush in bursts mid-match.
    pub writeback: Option<Writeback>,
}

fn s(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Built-in tiers. The network values are the CASUAL / COMPETITIVE / INTENSE
/// profiles from the original bpftune gaming tuner patches; capacity knobs
/// are raise-only so we never shrink something the user sized up.
pub fn builtin_tiers() -> [Tier; 3] {
    let wb = Some(Writeback {
        dirty_mb: 256,
        background_mb: 64,
    });
    let casual = Tier {
        name: TIER_NAMES[0].into(),
        sysctl: s(&[
            ("net.core.rmem_default", ">=262144"),
            ("net.core.rmem_max", ">=8388608"),
            ("net.core.wmem_default", ">=262144"),
            ("net.core.wmem_max", ">=8388608"),
            ("net.core.netdev_max_backlog", ">=5000"),
            ("net.core.netdev_budget", ">=400"),
            ("net.core.netdev_budget_usecs", ">=8000"),
            ("net.ipv4.udp_mem", ">=65536 436900 8388608"),
            ("net.core.busy_read", "25"),
            ("net.core.busy_poll", "25"),
            ("net.ipv4.udp_early_demux", "1"),
        ]),
        coalesce_usecs: None,
        dscp: true,
        writeback: None,
    };
    let competitive = Tier {
        name: TIER_NAMES[1].into(),
        sysctl: s(&[
            ("net.core.rmem_default", ">=262144"),
            ("net.core.rmem_max", ">=16777216"),
            ("net.core.wmem_default", ">=262144"),
            ("net.core.wmem_max", ">=16777216"),
            ("net.core.netdev_max_backlog", ">=5000"),
            ("net.core.netdev_budget", ">=600"),
            ("net.core.netdev_budget_usecs", ">=8000"),
            ("net.ipv4.udp_mem", ">=102400 873800 16777216"),
            ("net.core.busy_read", "50"),
            ("net.core.busy_poll", "50"),
            ("net.ipv4.udp_early_demux", "1"),
        ]),
        coalesce_usecs: Some(10),
        dscp: true,
        writeback: wb,
    };
    let intense = Tier {
        name: TIER_NAMES[2].into(),
        sysctl: s(&[
            ("net.core.rmem_default", ">=262144"),
            ("net.core.rmem_max", ">=33554432"),
            ("net.core.wmem_default", ">=262144"),
            ("net.core.wmem_max", ">=33554432"),
            ("net.core.netdev_max_backlog", ">=5000"),
            ("net.core.netdev_budget", ">=800"),
            ("net.core.netdev_budget_usecs", ">=8000"),
            ("net.ipv4.udp_mem", ">=204800 1747600 33554432"),
            ("net.core.busy_read", "75"),
            ("net.core.busy_poll", "75"),
            ("net.ipv4.udp_early_demux", "1"),
        ]),
        coalesce_usecs: Some(0),
        dscp: true,
        writeback: wb,
    };
    [casual, competitive, intense]
}

/// `knob = false` turns a knob off, `knob = <value>` sets it.
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum Setting<T> {
    Flag(bool),
    Value(T),
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TierOverride {
    /// "" or false removes a built-in sysctl from the tier.
    pub sysctl: BTreeMap<String, Setting<toml::Value>>,
    pub coalesce_usecs: Option<Setting<u32>>,
    pub dscp: Option<bool>,
    pub writeback: Option<Setting<Writeback>>,
}

fn merge_opt<T: Clone>(dst: &mut Option<T>, ov: &Option<Setting<T>>, what: &str) -> Result<()> {
    match ov {
        None => {}
        Some(Setting::Flag(false)) => *dst = None,
        Some(Setting::Flag(true)) => {
            if dst.is_none() {
                bail!("{what} = true needs a value, not just 'true'");
            }
        }
        Some(Setting::Value(v)) => *dst = Some(v.clone()),
    }
    Ok(())
}

impl TierOverride {
    fn apply(&self, tier: &mut Tier) -> Result<()> {
        for (k, v) in &self.sysctl {
            let value = match v {
                Setting::Flag(false) => None,
                Setting::Flag(true) => bail!("sysctl {k} = true needs a value"),
                Setting::Value(toml::Value::String(s)) if s.is_empty() => None,
                Setting::Value(toml::Value::String(s)) => Some(s.clone()),
                Setting::Value(toml::Value::Integer(i)) => Some(i.to_string()),
                Setting::Value(other) => bail!("sysctl {k}: unsupported value {other}"),
            };
            match value {
                Some(v) => {
                    tier.sysctl.insert(k.clone(), v);
                }
                None => {
                    tier.sysctl.remove(k);
                }
            }
        }
        merge_opt(
            &mut tier.coalesce_usecs,
            &self.coalesce_usecs,
            "coalesce_usecs",
        )?;
        if let Some(d) = self.dscp {
            tier.dscp = d;
        }
        merge_opt(&mut tier.writeback, &self.writeback, "writeback")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TiersFile {
    /// Applied to all three tiers before the per-tier tables.
    all: TierOverride,
    casual: TierOverride,
    competitive: TierOverride,
    intense: TierOverride,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ConfigFile {
    general: General,
    detect: Detect,
    classify: Classify,
    dscp: Dscp,
    tier: TiersFile,
}

#[derive(Clone, Debug, Serialize)]
pub struct Config {
    pub general: General,
    pub detect: Detect,
    pub classify: Classify,
    pub dscp: Dscp,
    pub tiers: [Tier; 3],
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: General::default(),
            detect: Detect::default(),
            classify: Classify::default(),
            dscp: Dscp::default(),
            tiers: builtin_tiers(),
        }
    }
}

impl Config {
    pub fn from_toml(text: &str) -> Result<Self> {
        let file: ConfigFile = toml::from_str(text)?;
        let mut tiers = builtin_tiers();
        for t in tiers.iter_mut() {
            file.tier.all.apply(t)?;
        }
        file.tier.casual.apply(&mut tiers[0])?;
        file.tier.competitive.apply(&mut tiers[1])?;
        file.tier.intense.apply(&mut tiers[2])?;
        let cfg = Config {
            general: file.general,
            detect: file.detect,
            classify: file.classify,
            dscp: file.dscp,
            tiers,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load `path`. A missing file at the default location is fine.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let (p, explicit) = match path {
            Some(p) => (p.to_path_buf(), true),
            None => (Path::new(DEFAULT_CONFIG).to_path_buf(), false),
        };
        match std::fs::read_to_string(&p) {
            Ok(text) => Self::from_toml(&text).with_context(|| format!("parsing {}", p.display())),
            Err(e) if !explicit && e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
        }
    }

    pub fn validate(&self) -> Result<()> {
        let d = &self.detect;
        if d.history < 2 {
            bail!("detect.history must be >= 2");
        }
        if d.steady_windows == 0 {
            bail!("detect.steady_windows must be >= 1");
        }
        if d.intense_pps <= d.competitive_pps {
            bail!("detect.intense_pps must be above detect.competitive_pps");
        }
        if let Some(t) = &d.pin_tier
            && tier_index(t).is_none()
        {
            bail!("detect.pin_tier must be casual, competitive or intense");
        }
        if self.general.tick_ms < 100 {
            bail!("general.tick_ms must be >= 100");
        }
        if !matches!(self.general.hook.as_str(), "auto" | "tracepoint" | "fexit") {
            bail!("general.hook must be auto, tracepoint or fexit");
        }
        if !matches!(self.general.bpftune.as_str(), "auto" | "yield" | "ignore") {
            bail!("general.bpftune must be auto, yield or ignore");
        }
        parse_dscp(&self.dscp.class)?;
        for t in &self.tiers {
            for k in t.sysctl.keys() {
                if crate::util::sysctl_path(k).is_none() {
                    bail!("tier {}: invalid sysctl name {k:?}", t.name);
                }
            }
            if let Some(w) = t.writeback
                && (w.dirty_mb == 0 || w.background_mb == 0 || w.background_mb >= w.dirty_mb)
            {
                bail!(
                    "tier {}: writeback needs 0 < background_mb < dirty_mb",
                    t.name
                );
            }
        }
        Ok(())
    }
}

impl Config {
    /// The effective configuration in the same shape the TOML file uses,
    /// with knobs that are off written as `false`.
    pub fn to_toml(&self) -> Result<String> {
        #[derive(Serialize)]
        struct TierOut {
            dscp: bool,
            coalesce_usecs: toml::Value,
            writeback: toml::Value,
            sysctl: BTreeMap<String, String>,
        }
        #[derive(Serialize)]
        struct Out<'a> {
            general: &'a General,
            detect: &'a Detect,
            classify: &'a Classify,
            dscp: &'a Dscp,
            tier: BTreeMap<String, TierOut>,
        }
        let tier = self
            .tiers
            .iter()
            .map(|t| {
                let out = TierOut {
                    dscp: t.dscp,
                    coalesce_usecs: t
                        .coalesce_usecs
                        .map(|u| toml::Value::Integer(u.into()))
                        .unwrap_or(toml::Value::Boolean(false)),
                    writeback: match t.writeback {
                        Some(w) => toml::Value::try_from(w).unwrap_or(toml::Value::Boolean(false)),
                        None => toml::Value::Boolean(false),
                    },
                    sysctl: t.sysctl.clone(),
                };
                (t.name.to_lowercase(), out)
            })
            .collect();
        Ok(toml::to_string_pretty(&Out {
            general: &self.general,
            detect: &self.detect,
            classify: &self.classify,
            dscp: &self.dscp,
            tier,
        })?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn dscp_names() {
        assert_eq!(parse_dscp("cs4").unwrap(), 32);
        assert_eq!(parse_dscp("EF").unwrap(), 46);
        assert_eq!(parse_dscp("AF41").unwrap(), 34);
        assert_eq!(parse_dscp("10").unwrap(), 10);
        assert!(parse_dscp("AF51").is_err());
        assert!(parse_dscp("64").is_err());
    }

    #[test]
    fn overrides_merge() {
        let cfg = Config::from_toml(
            r#"
            [detect]
            min_pps = 30
            pin_tier = "competitive"

            [classify]
            allow = ["mynativegame"]

            [tier.all]
            sysctl = { "net.core.busy_read" = false }

            [tier.intense]
            coalesce_usecs = 5
            writeback = false
            sysctl = { "net.core.busy_poll" = 0, "net.ipv4.tcp_fastopen" = "3" }
            "#,
        )
        .unwrap();
        assert_eq!(cfg.detect.min_pps, 30);
        assert_eq!(cfg.detect.intense_pps, 140);
        let i = &cfg.tiers[2];
        assert_eq!(i.coalesce_usecs, Some(5));
        assert_eq!(i.writeback, None);
        assert_eq!(i.sysctl["net.core.busy_poll"], "0");
        assert_eq!(i.sysctl["net.ipv4.tcp_fastopen"], "3");
        assert!(!i.sysctl.contains_key("net.core.busy_read"));
        assert!(!cfg.tiers[0].sysctl.contains_key("net.core.busy_read"));
        let mut c = builtin_tiers()[1].clone();
        c.sysctl.remove("net.core.busy_read");
        assert_eq!(cfg.tiers[1], c);
        assert!(cfg.classify.deny_list().iter().any(|d| d == "discord*"));
    }

    #[test]
    fn dump_round_trips() {
        let mut cfg = Config::default();
        cfg.tiers[1].coalesce_usecs = None;
        cfg.tiers[2].writeback = None;
        cfg.detect.min_pps = 33;
        let back = Config::from_toml(&cfg.to_toml().unwrap()).unwrap();
        assert_eq!(back.tiers, cfg.tiers);
        assert_eq!(back.detect.min_pps, 33);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(Config::from_toml("[detect]\nmin_ppz = 3\n").is_err());
        assert!(Config::from_toml("[detect]\npin_tier = \"godlike\"\n").is_err());
        assert!(
            Config::from_toml("[tier.casual]\nwriteback = { dirty_mb = 10, background_mb = 20 }\n")
                .is_err()
        );
        assert!(Config::from_toml("[general]\nbpftune = \"maybe\"\n").is_err());
    }

    #[test]
    fn builtin_tiers_are_network_and_writeback_only() {
        for t in builtin_tiers() {
            assert!(t.sysctl.keys().all(|k| k.starts_with("net.")), "{}", t.name);
        }
    }
}
