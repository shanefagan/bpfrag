// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Kernel counters that grow when the receive path can't keep up. Each
//! maps to something the tiers tune:
//!
//! - UDP receive-buffer drops (`RcvbufErrors`): a socket's buffer was full
//!   (`rmem_*`);
//! - backlog drops (softnet_stat column 2): the per-CPU input queue was
//!   full (`netdev_max_backlog`);
//! - budget squeezes (softnet_stat column 3): packet processing ran out of
//!   its budget and was deferred (`netdev_budget*`, busy polling);
//! - NIC overruns: the NIC's receive ring filled before the driver emptied
//!   it (interrupt coalescing).
//!
//! All are system-wide (NIC overruns per interface), so a busy download
//! during a match counts too.

use std::fs;

use crate::util::read_trim;

/// One reading of the system-wide counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SysCounters {
    pub udp_rcvbuf: u64,
    pub backlog_drops: u64,
    pub squeezed: u64,
}

impl SysCounters {
    pub fn read() -> Self {
        let rcvbuf4 = fs::read_to_string("/proc/net/snmp")
            .ok()
            .and_then(|t| udp_rcvbuf_v4(&t))
            .unwrap_or(0);
        // /proc/net/snmp6 is missing when IPv6 is disabled
        let rcvbuf6 = fs::read_to_string("/proc/net/snmp6")
            .ok()
            .and_then(|t| udp_rcvbuf_v6(&t))
            .unwrap_or(0);
        let (backlog_drops, squeezed) = fs::read_to_string("/proc/net/softnet_stat")
            .map(|t| softnet(&t))
            .unwrap_or_default();
        Self {
            udp_rcvbuf: rcvbuf4 + rcvbuf6,
            backlog_drops,
            squeezed,
        }
    }

    /// Growth since `base`. Counters only grow, but a CPU going offline
    /// takes its softnet line with it, so this saturates at zero.
    pub fn since(&self, base: &SysCounters) -> SysCounters {
        SysCounters {
            udp_rcvbuf: self.udp_rcvbuf.saturating_sub(base.udp_rcvbuf),
            backlog_drops: self.backlog_drops.saturating_sub(base.backlog_drops),
            squeezed: self.squeezed.saturating_sub(base.squeezed),
        }
    }
}

/// `RcvbufErrors` from the `Udp:` lines of /proc/net/snmp (a header line
/// of names followed by a line of values).
fn udp_rcvbuf_v4(text: &str) -> Option<u64> {
    let mut lines = text.lines().filter(|l| l.starts_with("Udp: "));
    let names = lines.next()?.split_whitespace();
    let values = lines.next()?.split_whitespace();
    names
        .zip(values)
        .find(|(n, _)| *n == "RcvbufErrors")?
        .1
        .parse()
        .ok()
}

/// `Udp6RcvbufErrors` from /proc/net/snmp6 (one "name value" per line).
fn udp_rcvbuf_v6(text: &str) -> Option<u64> {
    text.lines().find_map(|l| {
        let mut f = l.split_whitespace();
        (f.next()? == "Udp6RcvbufErrors").then(|| f.next()?.parse().ok())?
    })
}

/// (dropped, time_squeeze) summed over CPUs: columns 2 and 3 of
/// /proc/net/softnet_stat, in hex.
fn softnet(text: &str) -> (u64, u64) {
    let col = |l: &str, i: usize| {
        l.split_whitespace()
            .nth(i)
            .and_then(|v| u64::from_str_radix(v, 16).ok())
            .unwrap_or(0)
    };
    text.lines()
        .fold((0, 0), |(d, s), l| (d + col(l, 1), s + col(l, 2)))
}

/// Packets the NIC dropped because its receive ring was full. Drivers
/// report this under different names, so the three are summed. Not
/// `rx_dropped`, which also counts frames the stack had no use for.
pub fn nic_overruns(ifname: &str) -> Option<u64> {
    let stat = |n: &str| -> Option<u64> {
        read_trim(format!("/sys/class/net/{ifname}/statistics/{n}"))
            .ok()?
            .parse()
            .ok()
    };
    let parts = [
        stat("rx_missed_errors"),
        stat("rx_fifo_errors"),
        stat("rx_over_errors"),
    ];
    parts
        .iter()
        .any(Option::is_some)
        .then(|| parts.iter().flatten().sum())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_snmp() {
        let snmp = "Ip: Forwarding DefaultTTL\nIp: 1 64\n\
                    Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors\n\
                    Udp: 28694 1 7 28710 5 0\n\
                    UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors\n\
                    UdpLite: 0 0 0 0 99 0\n";
        assert_eq!(udp_rcvbuf_v4(snmp), Some(5));
        let snmp6 = "Udp6InDatagrams                 \t12\nUdp6RcvbufErrors                \t3\n";
        assert_eq!(udp_rcvbuf_v6(snmp6), Some(3));
        assert_eq!(udp_rcvbuf_v6("Ip6InReceives 1\n"), None);
    }

    #[test]
    fn sums_softnet_over_cpus() {
        let t = "0000bb69 00000002 0000000a 00000000\n000072ef 00000001 00000001 00000000\n";
        assert_eq!(softnet(t), (3, 11));
    }

    #[test]
    fn growth_saturates() {
        let a = SysCounters {
            udp_rcvbuf: 10,
            backlog_drops: 5,
            squeezed: 7,
        };
        let b = SysCounters {
            udp_rcvbuf: 12,
            backlog_drops: 4,
            squeezed: 9,
        };
        assert_eq!(
            b.since(&a),
            SysCounters {
                udp_rcvbuf: 2,
                backlog_drops: 0,
                squeezed: 2
            }
        );
    }
}
