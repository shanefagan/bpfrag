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
    /// Loopback: what arrives here never left the machine.
    pub local: bool,
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
        local: false,
    })
}

/// The loopback interface, for the arrival meter: a game that talks to a
/// server of its own (in its menus, say) does it here. Loopback frames
/// carry an Ethernet header at tc, like any ARPHRD_LOOPBACK device.
pub fn loopback() -> Option<Iface> {
    let ifindex: u32 = read_trim("/sys/class/net/lo/ifindex").ok()?.parse().ok()?;
    Some(Iface {
        name: "lo".into(),
        ifindex,
        l2_len: 14,
        physical: false,
        local: true,
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

/// Interfaces that are up with an IPv4 address or an IPv6 one beyond
/// link-local, loopback aside: every link a packet for one of this
/// machine's addresses can come in on. Linux takes such a packet on any
/// interface, not only the one holding the address, and two links on one
/// network (wired and Wi-Fi) each answer ARP for the other's address.
pub fn addressed_ifaces() -> Vec<Iface> {
    let mut names: Vec<String> = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list we own until freeifaddrs.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Vec::new();
    }
    let mut p = head;
    while !p.is_null() {
        // SAFETY: p is a node of the list getifaddrs returned, not yet freed.
        let ifa = unsafe { &*p };
        p = ifa.ifa_next;
        let up = ifa.ifa_flags & libc::IFF_UP as libc::c_uint != 0;
        let lo = ifa.ifa_flags & libc::IFF_LOOPBACK as libc::c_uint != 0;
        if !up || lo || ifa.ifa_addr.is_null() || ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: ifa_addr is non-null and points at a sockaddr of the
        // family it names; an AF_INET6 one is a sockaddr_in6.
        let addressed = match i32::from(unsafe { (*ifa.ifa_addr).sa_family }) {
            libc::AF_INET => true,
            libc::AF_INET6 => {
                let a = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                !is_link_local_v6(&a.sin6_addr.s6_addr)
            }
            _ => false, // AF_PACKET: the link itself, not an address
        };
        if addressed {
            // SAFETY: ifa_name is a non-null C string in the list.
            let name = unsafe { CStr::from_ptr(ifa.ifa_name) };
            names.push(name.to_string_lossy().into_owned());
        }
    }
    // SAFETY: head came from getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(head) };
    names.sort();
    names.dedup();
    names.iter().filter_map(|n| iface_by_name(n)).collect()
}

/// fe80::/10: every IPv6 interface has one, so it says nothing about
/// which networks the interface is on.
fn is_link_local_v6(a: &[u8; 16]) -> bool {
    a[0] == 0xfe && a[1] & 0xc0 == 0x80
}

/// Kernel driver behind an interface ("igc", "r8169", ...), for messages.
pub fn driver(ifname: &str) -> String {
    fs::read_link(format!("/sys/class/net/{ifname}/device/driver"))
        .ok()
        .and_then(|p| p.file_name().map(|f| f.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "unknown driver".into())
}

/// Is this a Wi-Fi interface? (cfg80211 devices have one of these.)
/// The interface of the preferred default route: the lowest-metric IPv4
/// one, else any default route's. What `pool = "auto"` goes by.
pub fn primary_default_route() -> Option<Iface> {
    let best = fs::read_to_string("/proc/net/route").ok().and_then(|t| {
        t.lines()
            .skip(1)
            .filter_map(|line| {
                let f: Vec<&str> = line.split_whitespace().collect();
                (f.len() > 7 && f[1] == "00000000" && f[7] == "00000000")
                    .then(|| (f[6].parse::<u64>().unwrap_or(u64::MAX), f[0].to_string()))
            })
            .min()
    });
    match best {
        Some((_, name)) => iface_by_name(&name),
        None => default_route_ifaces().into_iter().next(),
    }
}

pub fn is_wireless(ifname: &str) -> bool {
    Path::new(&format!("/sys/class/net/{ifname}/wireless")).exists()
        || Path::new(&format!("/sys/class/net/{ifname}/phy80211")).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_fe80_slash_10_is_link_local() {
        let mut a = [0u8; 16];
        a[0] = 0xfe;
        a[1] = 0x80;
        assert!(is_link_local_v6(&a));
        a[1] = 0xbf;
        assert!(is_link_local_v6(&a), "fe80::/10 runs to febf::");
        a[1] = 0xc0;
        assert!(!is_link_local_v6(&a), "fec0:: is outside it");
        a[0] = 0xfd;
        a[1] = 0x00;
        assert!(!is_link_local_v6(&a), "a ULA is an address on a network");
    }

    #[test]
    fn loopback_is_never_an_addressed_interface() {
        // whatever this machine has, lo is up with 127.0.0.1 and is left out
        assert!(addressed_ifaces().iter().all(|i| i.name != "lo"));
    }
}
