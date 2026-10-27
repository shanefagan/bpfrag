// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Which receive queue a NAPI instance belongs to, over the `netdev`
//! generic netlink family (what `ynl --family netdev` shows).
//!
//! The kernel stamps each received packet with the id of the NAPI instance
//! that processed it, and the arrival meter records it per game port. Here
//! that id becomes "eno1, rx queue 2, IRQ 140". The `napi-get` and
//! `queue-get` commands need kernel 6.8 or newer, and some drivers (Wi-Fi
//! ones especially) run NAPI on an internal device that netlink doesn't
//! list; then only the id is known.

use std::io;

use serde::{Deserialize, Serialize};

use super::genl::{Genl, NLM_F_DUMP, Reply, attr_u32};

const NETDEV_CMD_QUEUE_GET: u8 = 10;
const NETDEV_CMD_NAPI_GET: u8 = 11;

const NETDEV_A_NAPI_IFINDEX: u16 = 1;
const NETDEV_A_NAPI_ID: u16 = 2;
const NETDEV_A_NAPI_IRQ: u16 = 3;

const NETDEV_A_QUEUE_ID: u16 = 1;
const NETDEV_A_QUEUE_IFINDEX: u16 = 2;
const NETDEV_A_QUEUE_TYPE: u16 = 3;
const NETDEV_A_QUEUE_NAPI_ID: u16 = 4;
const NETDEV_QUEUE_TYPE_RX: u32 = 0;

/// Where a game's packets come in.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RxQueue {
    pub napi_id: u32,
    pub ifname: Option<String>,
    pub queue: Option<u32>,
    pub irq: Option<u32>,
}

impl RxQueue {
    /// "eno1 rx queue 2, IRQ 140", or "NAPI 8195" if that's all we know.
    pub fn describe(&self) -> String {
        let Some(ifname) = &self.ifname else {
            return format!("NAPI {}", self.napi_id);
        };
        let mut s = ifname.clone();
        if let Some(q) = self.queue {
            s += &format!(" rx queue {q}");
        }
        if let Some(irq) = self.irq {
            s += &format!(", IRQ {irq}");
        }
        s
    }
}

/// Look up NAPI instance `napi_id`. Never fails: whatever couldn't be
/// found is left out.
pub fn rx_queue(napi_id: u32) -> RxQueue {
    let mut q = RxQueue {
        napi_id,
        ..Default::default()
    };
    if let Err(e) = fill(&mut q) {
        log::debug!("NAPI {napi_id}: {e}");
    }
    q
}

fn fill(q: &mut RxQueue) -> io::Result<()> {
    let mut g = Genl::open()?;
    let fam = g.family("netdev")?;
    let napi = g.call(
        fam,
        0,
        NETDEV_CMD_NAPI_GET,
        &[(NETDEV_A_NAPI_ID, &q.napi_id.to_ne_bytes())],
    )?;
    let Some(Reply::Attrs(attrs)) = napi.iter().find(|r| matches!(r, Reply::Attrs(_))) else {
        return Ok(());
    };
    q.irq = attr_u32(attrs, NETDEV_A_NAPI_IRQ);
    let Some(ifindex) = attr_u32(attrs, NETDEV_A_NAPI_IFINDEX) else {
        return Ok(());
    };
    q.ifname = super::ifname(ifindex);

    let queues = g.call(
        fam,
        NLM_F_DUMP,
        NETDEV_CMD_QUEUE_GET,
        &[(NETDEV_A_QUEUE_IFINDEX, &ifindex.to_ne_bytes())],
    )?;
    q.queue = rx_queue_of(&queues, q.napi_id);
    Ok(())
}

/// The rx queue served by `napi_id`, from a `queue-get` dump.
fn rx_queue_of(replies: &[Reply], napi_id: u32) -> Option<u32> {
    replies.iter().find_map(|r| match r {
        Reply::Attrs(a)
            if attr_u32(a, NETDEV_A_QUEUE_TYPE) == Some(NETDEV_QUEUE_TYPE_RX)
                && attr_u32(a, NETDEV_A_QUEUE_NAPI_ID) == Some(napi_id) =>
        {
            attr_u32(a, NETDEV_A_QUEUE_ID)
        }
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queue(id: u32, ty: u32, napi: u32) -> Reply {
        Reply::Attrs(vec![
            (NETDEV_A_QUEUE_ID, id.to_ne_bytes().to_vec()),
            (NETDEV_A_QUEUE_IFINDEX, 2u32.to_ne_bytes().to_vec()),
            (NETDEV_A_QUEUE_TYPE, ty.to_ne_bytes().to_vec()),
            (NETDEV_A_QUEUE_NAPI_ID, napi.to_ne_bytes().to_vec()),
        ])
    }

    #[test]
    fn finds_the_rx_queue_of_a_napi() {
        // igc-style: tx and rx queue N share NAPI instance N
        let dump = [
            queue(0, 0, 8193),
            queue(1, 0, 8194),
            queue(0, 1, 8193),
            queue(1, 1, 8194),
            Reply::Done,
        ];
        assert_eq!(rx_queue_of(&dump, 8194), Some(1));
        assert_eq!(rx_queue_of(&dump, 9000), None);
    }

    #[test]
    fn describes_what_is_known() {
        let mut q = RxQueue {
            napi_id: 8195,
            ..Default::default()
        };
        assert_eq!(q.describe(), "NAPI 8195");
        q.ifname = Some("eno1".into());
        assert_eq!(q.describe(), "eno1");
        q.queue = Some(2);
        q.irq = Some(140);
        assert_eq!(q.describe(), "eno1 rx queue 2, IRQ 140");
    }

    /// Needs a kernel: an unknown NAPI id resolves to just the id.
    #[test]
    fn unknown_napi_is_just_its_id() {
        let q = rx_queue(u32::MAX);
        assert_eq!(q.ifname, None);
        assert_eq!(q.describe(), format!("NAPI {}", u32::MAX));
    }
}
