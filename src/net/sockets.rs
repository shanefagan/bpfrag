// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Receive-buffer drops on one process's own UDP sockets. The kernel keeps
//! a drop count per socket (`sk_drops`), shown in the last column of
//! `/proc/<pid>/net/udp` and `udp6`; the process's socket inodes come from its
//! `/proc/<pid>/fd` links. Reading another user's fds needs CAP_SYS_PTRACE,
//! which the unit has.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// inode -> drops for each UDP socket `tgid` holds open. None if the
/// process is gone or its fds can't be read.
pub fn udp_drops(proc_root: &Path, tgid: u32) -> Option<HashMap<u64, u64>> {
    let pid = proc_root.join(tgid.to_string());
    let mut inodes = Vec::new();
    for e in fs::read_dir(pid.join("fd")).ok()?.flatten() {
        if let Some(i) = fs::read_link(e.path())
            .ok()
            .and_then(|l| socket_inode(&l.to_string_lossy()))
        {
            inodes.push(i);
        }
    }
    let mut out = HashMap::new();
    if inodes.is_empty() {
        return Some(out);
    }
    for table in ["udp", "udp6"] {
        // udp6 is missing when IPv6 is disabled
        if let Ok(t) = fs::read_to_string(pid.join("net").join(table)) {
            for (inode, drops) in parse_table(&t) {
                if inodes.contains(&inode) {
                    out.insert(inode, drops);
                }
            }
        }
    }
    Some(out)
}

/// `socket:[12345]` -> 12345.
fn socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// (inode, drops) for each row of /proc/net/udp or udp6.
fn parse_table(text: &str) -> Vec<(u64, u64)> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            Some((f.get(9)?.parse().ok()?, f.last()?.parse().ok()?))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_net_udp() {
        let t = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
                 \x20 512: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   977        0 23456 2 0000000000000000 0\n\
                 \x20 931: 00000000:6987 00000000:0000 07 00000000:00034000 00:00000000 00000000  1000        0 98765 2 0000000000000000 318\n";
        assert_eq!(parse_table(t), vec![(23456, 0), (98765, 318)]);
        assert_eq!(socket_inode("socket:[98765]"), Some(98765));
        assert_eq!(socket_inode("pipe:[98765]"), None);
        assert_eq!(socket_inode("/dev/null"), None);
    }

    #[test]
    fn reads_this_process() {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let d = udp_drops(Path::new("/proc"), std::process::id()).unwrap();
        // other tests may hold UDP sockets too
        assert!(!d.is_empty(), "{d:?}");
        drop(s);
    }
}
