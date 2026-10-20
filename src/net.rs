// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan
//
// Interface discovery and NIC interrupt coalescing (legacy ethtool ioctl,
// ported from the original gaming tuner patch).

use std::ffi::CStr;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

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
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    let p = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr()) };
    if p.is_null() {
        return None;
    }
    let name = unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    iface_by_name(&name)
}

/// Interfaces carrying an IPv4 or IPv6 default route.
pub fn default_route_ifaces() -> Vec<Iface> {
    let mut names: Vec<String> = Vec::new();
    if let Ok(t) = fs::read_to_string("/proc/net/route") {
        for line in t.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            // Iface Destination Gateway Flags RefCnt Use Metric Mask ...
            if f.len() > 7 && f[1] == "00000000" && f[7] == "00000000" {
                names.push(f[0].to_string());
            }
        }
    }
    if let Ok(t) = fs::read_to_string("/proc/net/ipv6_route") {
        for line in t.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            // dest plen src splen nexthop metric refcnt use flags dev
            if f.len() >= 10 && f[0].chars().all(|c| c == '0') && f[1] == "00" && f[9] != "lo" {
                names.push(f[9].to_string());
            }
        }
    }
    names.sort();
    names.dedup();
    names.iter().filter_map(|n| iface_by_name(n)).collect()
}

// ---- ethtool coalescing -----------------------------------------------------

const SIOCETHTOOL: libc::c_ulong = 0x8946;
const ETHTOOL_GCOALESCE: u32 = 0x0e;
const ETHTOOL_SCOALESCE: u32 = 0x0f;

pub const COALESCE_WORDS: usize = 23;
const RX_USECS: usize = 1;
const TX_USECS: usize = 5;
const ADAPTIVE_RX: usize = 10;
const ADAPTIVE_TX: usize = 11;

/// struct ethtool_coalesce, as raw u32 words (cmd + 22 fields).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Coalesce(pub [u32; COALESCE_WORDS]);

#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IF_NAMESIZE],
    data: *mut libc::c_void,
    _pad: [u8; 16],
}

fn ethtool(ifname: &str, c: &mut Coalesce) -> io::Result<()> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut req = IfReq {
        name: [0; libc::IF_NAMESIZE],
        data: c.0.as_mut_ptr().cast(),
        _pad: [0; 16],
    };
    for (i, b) in ifname.bytes().take(libc::IF_NAMESIZE - 1).enumerate() {
        req.name[i] = b as libc::c_char;
    }
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), SIOCETHTOOL as _, &mut req) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn get_coalesce(ifname: &str) -> io::Result<Coalesce> {
    let mut c = Coalesce([0; COALESCE_WORDS]);
    c.0[0] = ETHTOOL_GCOALESCE;
    ethtool(ifname, &mut c)?;
    Ok(c)
}

pub fn set_coalesce(ifname: &str, c: &Coalesce) -> io::Result<()> {
    let mut c = *c;
    c.0[0] = ETHTOOL_SCOALESCE;
    ethtool(ifname, &mut c)
}

impl Coalesce {
    /// Equal apart from the ioctl command word.
    pub fn same_as(&self, other: &Coalesce) -> bool {
        self.0[1..] == other.0[1..]
    }

    /// Baseline with rx (and tx, if `with_tx`) usecs forced and adaptive off.
    pub fn with_usecs(&self, usecs: u32, with_tx: bool) -> Coalesce {
        let mut c = *self;
        c.0[RX_USECS] = usecs;
        c.0[ADAPTIVE_RX] = 0;
        if with_tx {
            c.0[TX_USECS] = usecs;
            c.0[ADAPTIVE_TX] = 0;
        }
        c
    }

    /// `self` (the device's current settings) with only the fields bpfrag
    /// changes copied back from `base`. Used when a driver refuses its own
    /// full struct on restore.
    pub fn restore_from(&self, base: &Coalesce, with_tx: bool) -> Coalesce {
        let mut c = *self;
        c.0[RX_USECS] = base.0[RX_USECS];
        c.0[ADAPTIVE_RX] = base.0[ADAPTIVE_RX];
        if with_tx {
            c.0[TX_USECS] = base.0[TX_USECS];
            c.0[ADAPTIVE_TX] = base.0[ADAPTIVE_TX];
        }
        c
    }

    pub fn describe(&self) -> String {
        format!(
            "rx-usecs {} tx-usecs {} adaptive-rx {}",
            self.0[RX_USECS],
            self.0[TX_USECS],
            if self.0[ADAPTIVE_RX] != 0 {
                "on"
            } else {
                "off"
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesce_field_merge() {
        let mut base = Coalesce([0; COALESCE_WORDS]);
        base.0[RX_USECS] = 3;
        base.0[TX_USECS] = 3;
        base.0[ADAPTIVE_RX] = 1;
        base.0[7] = 99; // some field we never touch
        let tuned = base.with_usecs(0, true);
        assert_eq!(
            (tuned.0[RX_USECS], tuned.0[TX_USECS], tuned.0[ADAPTIVE_RX]),
            (0, 0, 0)
        );
        assert_eq!(tuned.0[7], 99);

        let mut cur = tuned;
        cur.0[7] = 42; // driver changed an unrelated field meanwhile
        let back = cur.restore_from(&base, true);
        assert_eq!(
            (back.0[RX_USECS], back.0[TX_USECS], back.0[ADAPTIVE_RX]),
            (3, 3, 1)
        );
        assert_eq!(back.0[7], 42, "only our fields are put back");
        let rx_only = cur.restore_from(&base, false);
        assert_eq!((rx_only.0[RX_USECS], rx_only.0[TX_USECS]), (3, 0));
    }
}
