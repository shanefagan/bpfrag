// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! The operating system's networking interfaces, without any policy:
//!
//! - this file: which interfaces exist, which carry default routes, and
//!   what kind each one is;
//! - [`ethtool`]: NIC interrupt coalescing through the ethtool ioctl;
//! - [`nl80211`]: Wi-Fi power save over generic netlink;
//! - [`netdev`]: which receive queue (NAPI instance) a packet came in on;
//! - [`sockets`]: receive-buffer drops on one process's UDP sockets;
//! - [`genl`]: the generic netlink both of those use.
//!
//! What to change and when lives in `tune`.

pub mod ethtool;
pub mod genl;
pub mod netdev;
pub mod nl80211;
pub mod sockets;

use std::ffi::CStr;
use std::fs;
use std::path::Path;

use crate::util::read_trim;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Iface {
    pub name: String,
    pub ifindex: u32,
    /// Bytes of link-layer header in front of the IP header at tc egress.
    pub l2_len: u32,
    /// Backed by real hardware (has a /sys/class/net/X/device link).
    pub physical: bool,
}

impl Iface {
    /// An L3 tunnel (wg, tun, ppp): packets leave again through another
    /// interface underneath.
    pub fn is_tunnel(&self) -> bool {
        self.l2_len == 0
    }
}

pub fn iface_by_name(name: &str) -> Option<Iface> {
    let base = format!("/sys/class/net/{name}");
    let ifindex: u32 = read_trim(format!("{base}/ifindex")).ok()?.parse().ok()?;
    let ty: u32 = read_trim(format!("{base}/type")).ok()?.parse().ok()?;
    let l2_len = match ty {
        1 => 14,          // ARPHRD_ETHER (also Wi-Fi)
        65534 | 512 => 0, // ARPHRD_NONE (wg, tun), ARPHRD_PPP
        _ => return None, // something exotic: leave it alone
    };
    Some(Iface {
        name: name.to_string(),
        ifindex,
        l2_len,
        physical: fs::metadata(format!("{base}/device")).is_ok(),
    })
}

pub fn iface_by_index(ifindex: u32) -> Option<Iface> {
    iface_by_name(&ifname(ifindex)?)
}

/// The interface's name, whatever its kind.
pub fn ifname(ifindex: u32) -> Option<String> {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    let p = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr()) };
    if p.is_null() {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(buf.as_ptr()) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// Interfaces carrying an IPv4 or IPv6 default route in the main routing
/// table (what `ip route` shows; policy-routing tables are not read).
pub fn default_route_ifaces() -> Vec<Iface> {
    let mut names: Vec<String> = Vec::new();
    if let Ok(t) = fs::read_to_string("/proc/net/route") {
        for line in t.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            // Iface Destination Gateway Flags RefCnt Use Metric Mask ...
            // A default route has destination 0.0.0.0 and mask 0.0.0.0.
            if f.len() > 7 && f[1] == "00000000" && f[7] == "00000000" {
                names.push(f[0].to_string());
            }
        }
    }
    if let Ok(t) = fs::read_to_string("/proc/net/ipv6_route") {
        for line in t.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            // dest plen src splen nexthop metric refcnt use flags dev
            // A default route is ::/0; skip the loopback catch-alls.
            if f.len() >= 10 && f[0].chars().all(|c| c == '0') && f[1] == "00" && f[9] != "lo" {
                names.push(f[9].to_string());
            }
        }
    }
    names.sort();
    names.dedup();
    names.iter().filter_map(|n| iface_by_name(n)).collect()
}

/// Kernel driver behind an interface ("igc", "r8169", ...), for messages.
pub fn driver(ifname: &str) -> String {
    fs::read_link(format!("/sys/class/net/{ifname}/device/driver"))
        .ok()
        .and_then(|p| p.file_name().map(|f| f.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "unknown driver".into())
}

/// Is this a Wi-Fi interface? (cfg80211 devices have one of these.)
pub fn is_wireless(ifname: &str) -> bool {
    Path::new(&format!("/sys/class/net/{ifname}/wireless")).exists()
        || Path::new(&format!("/sys/class/net/{ifname}/phy80211")).exists()
}
