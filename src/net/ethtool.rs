// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! NIC interrupt coalescing through the legacy ethtool ioctl (what
//! `ethtool -c` / `ethtool -C` do), ported from the original gaming-tuner
//! patch. The ioctl is used rather than ethtool netlink so this needs
//! nothing but a socket.
//!
//! `struct ethtool_coalesce` is handled as raw u32 words: a command word
//! followed by 22 fields, of which bpfrag only reads or changes four.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const SIOCETHTOOL: libc::c_ulong = 0x8946;
const ETHTOOL_GCOALESCE: u32 = 0x0e;
const ETHTOOL_SCOALESCE: u32 = 0x0f;

pub const COALESCE_WORDS: usize = 23;
// Word offsets in struct ethtool_coalesce (word 0 is the command).
const RX_USECS: usize = 1; // rx_coalesce_usecs
const TX_USECS: usize = 5; // tx_coalesce_usecs
const ADAPTIVE_RX: usize = 10; // use_adaptive_rx_coalesce
const ADAPTIVE_TX: usize = 11; // use_adaptive_tx_coalesce

/// `struct ethtool_coalesce`, as raw u32 words (cmd + 22 fields).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Coalesce(pub [u32; COALESCE_WORDS]);

/// `struct ifreq` with `ifr_data` pointing at the ethtool request.
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
    /// From journalled words; missing ones are zero.
    pub fn from_words(words: &[u32]) -> Coalesce {
        let mut c = Coalesce([0; COALESCE_WORDS]);
        for (d, s) in c.0.iter_mut().zip(words) {
            *d = *s;
        }
        c
    }

    pub fn rx_usecs(&self) -> u32 {
        self.0[RX_USECS]
    }

    pub fn adaptive_rx(&self) -> bool {
        self.0[ADAPTIVE_RX] != 0
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
