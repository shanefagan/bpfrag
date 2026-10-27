// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Wi-Fi power save over nl80211 (what `iw dev wlan0 get/set power_save`
//! does), with the plain generic netlink in [`super::genl`].

use std::io;

use super::genl::{Genl, NLM_F_ACK, find_attr};

const NL80211_CMD_SET_POWER_SAVE: u8 = 61;
const NL80211_CMD_GET_POWER_SAVE: u8 = 62;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_PS_STATE: u16 = 93;

/// Is power save on for this wireless interface?
pub fn get_power_save(ifindex: u32) -> io::Result<bool> {
    let mut g = Genl::open()?;
    let fam = g.family("nl80211")?;
    let idx = ifindex.to_ne_bytes();
    let replies = g.call(
        fam,
        0,
        NL80211_CMD_GET_POWER_SAVE,
        &[(NL80211_ATTR_IFINDEX, &idx)],
    )?;
    let v = find_attr(&replies, NL80211_ATTR_PS_STATE)
        .filter(|v| v.len() >= 4)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no PS_STATE in reply"))?;
    Ok(u32::from_ne_bytes(v[..4].try_into().unwrap()) != 0)
}

pub fn set_power_save(ifindex: u32, on: bool) -> io::Result<()> {
    let mut g = Genl::open()?;
    let fam = g.family("nl80211")?;
    let idx = ifindex.to_ne_bytes();
    let state = u32::from(on).to_ne_bytes();
    g.call(
        fam,
        NLM_F_ACK,
        NL80211_CMD_SET_POWER_SAVE,
        &[
            (NL80211_ATTR_IFINDEX, &idx),
            (NL80211_ATTR_PS_STATE, &state),
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::genl::{NLM_F_REQUEST, encode};

    #[test]
    fn encodes_set_power_save_like_iw() {
        let idx = 3u32.to_ne_bytes();
        let st = 0u32.to_ne_bytes();
        let m = encode(
            0x1c,
            NLM_F_ACK,
            7,
            NL80211_CMD_SET_POWER_SAVE,
            &[(3, &idx), (93, &st)],
        );
        // 16 nlmsghdr + 4 genl + 2 * (4 hdr + 4 payload)
        assert_eq!(m.len(), 36);
        assert_eq!(u32::from_ne_bytes(m[0..4].try_into().unwrap()), 36);
        assert_eq!(u16::from_ne_bytes(m[4..6].try_into().unwrap()), 0x1c);
        assert_eq!(
            u16::from_ne_bytes(m[6..8].try_into().unwrap()),
            NLM_F_REQUEST | NLM_F_ACK
        );
        assert_eq!(m[16], 61);
        assert_eq!(&m[20..24], &[8, 0, 3, 0]);
        assert_eq!(&m[28..32], &[8, 0, 93, 0]);
    }
}
