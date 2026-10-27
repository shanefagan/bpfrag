// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Built-in data: the classifier's lists, the sysctls bpftune owns, and
//! the three tier profiles. All of it can be extended or overridden from
//! the config file.

use std::collections::BTreeMap;

use super::{Profile, Tier, Writeback};

/// Exact process names (comm, or exe name) where possible: a broad glob
/// like "signal*" would also catch the game SIGNALIS, "brave*" catches
/// Bravely Default. Globs are only used for names that come in variants.
pub const BUILTIN_DENY: &[&str] = &[
    // browsers (QUIC is UDP and bursty enough to fool a global counter)
    "firefox",
    "firefox-bin",
    "firefox-esr",
    "GeckoMain",
    "librewolf",
    "waterfox",
    "floorp",
    "zen",
    "zen-bin",
    "chrome",
    "chromium",
    "chromium-browse",
    "google-chrome*",
    "brave",
    "brave-browser*",
    "vivaldi",
    "vivaldi-bin",
    "opera",
    "msedge",
    "microsoft-edge*",
    "thorium",
    "thorium-browser",
    "epiphany",
    "WebKitNetworkPr",
    "falkon",
    "qutebrowser",
    "Isolated Web Co",
    "Web Content",
    "Socket Process",
    "RDD Process",
    "Utility Process",
    "Privileged Cont",
    // voice / chat (a 50 pkt/s Opus stream looks a lot like a 50 Hz game)
    "discord",
    "discordcanary",
    "discordptb",
    "vesktop",
    "webcord",
    "legcord",
    "armcord",
    "equibop",
    "teamspeak*",
    "ts3client*",
    "mumble",
    "element-desktop",
    "signal-desktop",
    "telegram",
    "telegram-deskto*",
    "slack",
    "zoom",
    "teams-for-linux",
    "skypeforlinux",
    "whatsapp*",
    "obs",
    // RGB / peripheral software (SignalRGB under Wine streams steady UDP)
    "signalrgb*",
    "openrgb",
    // store launchers under Wine (not games themselves)
    "battle.net*",
    "eadesktop*",
    "epicgameslaunch*",
    "galaxyclient*",
    "ubisoftconnect*",
    "upc",
    "upc.exe",
    "riotclientserv*",
    // p2p / sync
    "qbittorrent*",
    "transmission-*",
    "deluge*",
    "rtorrent",
    "aria2c",
    "ktorrent",
    "fragments",
    "tixati",
    "syncthing",
    "rslsync",
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
    "gsconnectd",
    "pipewire",
    "pipewire-pulse",
    "wireplumber",
    "pulseaudio",
    "spotify",
    "kodi",
    "kodi.bin",
    "vlc",
    "mpv",
    "sunshine",
    "parsecd",
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

/// A sysctl table from (name, value) pairs.
fn sysctls(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Built-in profiles. The network values are the CASUAL / COMPETITIVE /
/// INTENSE profiles from the original bpftune gaming tuner patches; capacity
/// knobs are raise-only so we never shrink something the user sized up.
/// net.ipv4.udp_mem is left out: it is in pages, the kernel already sizes
/// it from RAM (gigabytes, versus the kilobytes a game buffers), and the
/// original values raised its hard limit past physical memory.
pub fn builtin_profiles() -> [Profile; 3] {
    let wb = Some(Writeback {
        dirty_mb: 256,
        background_mb: 64,
    });
    let casual = Profile {
        tier: Tier::Casual,
        sysctl: sysctls(&[
            ("net.core.rmem_default", ">=262144"),
            ("net.core.rmem_max", ">=8388608"),
            ("net.core.wmem_default", ">=262144"),
            ("net.core.wmem_max", ">=8388608"),
            ("net.core.netdev_max_backlog", ">=5000"),
            ("net.core.netdev_budget", ">=400"),
            ("net.core.netdev_budget_usecs", ">=8000"),
            ("net.core.busy_read", "25"),
            ("net.core.busy_poll", "25"),
            ("net.ipv4.udp_early_demux", "1"),
        ]),
        coalesce_usecs: None,
        dscp: true,
        writeback: None,
        wifi_powersave_off: false,
    };
    let competitive = Profile {
        tier: Tier::Competitive,
        sysctl: sysctls(&[
            ("net.core.rmem_default", ">=262144"),
            ("net.core.rmem_max", ">=16777216"),
            ("net.core.wmem_default", ">=262144"),
            ("net.core.wmem_max", ">=16777216"),
            ("net.core.netdev_max_backlog", ">=5000"),
            ("net.core.netdev_budget", ">=600"),
            ("net.core.netdev_budget_usecs", ">=8000"),
            ("net.core.busy_read", "50"),
            ("net.core.busy_poll", "50"),
            ("net.ipv4.udp_early_demux", "1"),
        ]),
        coalesce_usecs: Some(10),
        dscp: true,
        writeback: wb,
        wifi_powersave_off: true,
    };
    let intense = Profile {
        tier: Tier::Intense,
        sysctl: sysctls(&[
            ("net.core.rmem_default", ">=262144"),
            ("net.core.rmem_max", ">=33554432"),
            ("net.core.wmem_default", ">=262144"),
            ("net.core.wmem_max", ">=33554432"),
            ("net.core.netdev_max_backlog", ">=5000"),
            ("net.core.netdev_budget", ">=800"),
            ("net.core.netdev_budget_usecs", ">=8000"),
            ("net.core.busy_read", "75"),
            ("net.core.busy_poll", "75"),
            ("net.ipv4.udp_early_demux", "1"),
        ]),
        coalesce_usecs: Some(0),
        dscp: true,
        writeback: wb,
        wifi_powersave_off: true,
    };
    [casual, competitive, intense]
}
