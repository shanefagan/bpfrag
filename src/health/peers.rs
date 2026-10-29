// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Who the game is receiving from: per remote address and port, counted
//! by the arrival meter (`game_peers`). A game also pings relays and other
//! servers now and then, so the "server" is the peer sending the most, at
//! a game's rate; when another peer takes over for a few seconds, the game
//! has moved to a new server, which can mean a new match without the game
//! ever going quiet (Deadlock's Street Brawl, back to back).
//!
//! Addresses aren't logged at info or written to captures: a game that
//! talks peer to peer would put other players' home addresses there. Each
//! address gets a letter in the order it became the server (A, B, ...),
//! shown with its port, so "A:27031 -> A:27044" (same address, new port)
//! and "A:27031 -> B:27031" (another address) stay apart.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::bpf_intf;

/// A remote address and port sending to one of the game's local ports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Peer {
    pub lport: u16,
    pub addr: IpAddr,
    pub port: u16,
}

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

impl Peer {
    /// From the meter's key: addresses in network order, IPv4 in word 0.
    pub fn from_key(k: &bpf_intf::flow_key) -> Option<Peer> {
        let addr = match k.family {
            AF_INET => IpAddr::V4(Ipv4Addr::from(k.raddr[0].to_ne_bytes())),
            AF_INET6 => {
                let mut b = [0u8; 16];
                for (chunk, w) in b.chunks_exact_mut(4).zip(k.raddr.iter()) {
                    chunk.copy_from_slice(&w.to_ne_bytes());
                }
                IpAddr::V6(Ipv6Addr::from(b))
            }
            _ => return None,
        };
        Some(Peer {
            lport: k.lport,
            addr,
            port: k.rport,
        })
    }
}

/// Packets a second before a peer counts as the server, not a ping.
const MIN_PPS: f64 = 10.0;
/// Readings averaged for each peer's rate.
const WINDOW: usize = 3;
/// Readings in a row a new peer must be the loudest before it's the
/// server: the old one can keep sending for a moment (an end screen).
const HOLD: u32 = 3;

#[derive(Clone, Debug, PartialEq)]
pub enum ServerEvent {
    /// The match's first server.
    First { peer: Peer, label: String, pps: f64 },
    /// Another peer took over.
    Changed {
        from: Peer,
        from_label: String,
        from_pps: f64,
        to: Peer,
        to_label: String,
        pps: f64,
    },
}

#[derive(Debug, Default)]
pub struct Servers {
    /// Addresses in the order they became the server, for labels.
    addrs: Vec<IpAddr>,
    prev: HashMap<Peer, u64>,
    rates: HashMap<Peer, VecDeque<f64>>,
    main: Option<Peer>,
    challenger: Option<(Peer, u32)>,
    changes: u32,
    active: usize,
}

impl Servers {
    /// One reading of cumulative packet counts per peer, `dt` seconds
    /// after the last.
    pub fn update(&mut self, dt: f64, peers: &[(Peer, u64)]) -> Vec<ServerEvent> {
        let dt = dt.max(0.001);
        let mut events = Vec::new();
        self.active = 0;
        let mut seen = HashMap::with_capacity(peers.len());
        for &(p, pkts) in peers {
            // a new entry, or one the LRU map dropped and started again
            let before = self
                .prev
                .get(&p)
                .copied()
                .filter(|b| *b <= pkts)
                .unwrap_or(0);
            let delta = pkts - before;
            if delta > 0 {
                self.active += 1;
            }
            let r = self.rates.entry(p).or_default();
            r.push_back(delta as f64 / dt);
            if r.len() > WINDOW {
                r.pop_front();
            }
            seen.insert(p, pkts);
        }
        self.rates.retain(|p, _| seen.contains_key(p));
        self.prev = seen;

        // The loudest peer in this reading (the current server wins a tie),
        // if it has been sending at a game's rate lately.
        let main = self.main;
        let Some((best, best_pps)) = self
            .rates
            .iter()
            .map(|(p, r)| (*p, r.back().copied().unwrap_or(0.0)))
            .max_by(|a, b| {
                a.1.total_cmp(&b.1)
                    .then((Some(a.0) == main).cmp(&(Some(b.0) == main)))
                    .then(b.0.cmp(&a.0))
            })
            .map(|(p, _)| (p, self.rate(&p)))
            .filter(|(_, r)| *r >= MIN_PPS)
        else {
            self.challenger = None;
            return events;
        };
        match self.main {
            // a full window first, so the rate logged isn't a partial second
            None if self.rates.get(&best).is_some_and(|r| r.len() < WINDOW) => {}
            None => {
                self.main = Some(best);
                let label = self.label_new(&best);
                events.push(ServerEvent::First {
                    peer: best,
                    label,
                    pps: best_pps,
                });
            }
            Some(m) if m == best => self.challenger = None,
            Some(m) => {
                let n = match self.challenger {
                    Some((c, n)) if c == best => n + 1,
                    _ => 1,
                };
                if n < HOLD {
                    self.challenger = Some((best, n));
                } else {
                    self.challenger = None;
                    self.main = Some(best);
                    self.changes += 1;
                    let from_label = self.label(&m);
                    let to_label = self.label_new(&best);
                    events.push(ServerEvent::Changed {
                        from: m,
                        from_label,
                        from_pps: self.rate(&m),
                        to: best,
                        to_label,
                        pps: best_pps,
                    });
                }
            }
        }
        events
    }

    /// Mean packets a second over the last few readings.
    fn rate(&self, p: &Peer) -> f64 {
        self.rates
            .get(p)
            .filter(|r| !r.is_empty())
            .map_or(0.0, |r| r.iter().sum::<f64>() / r.len() as f64)
    }

    fn label_new(&mut self, p: &Peer) -> String {
        if !self.addrs.contains(&p.addr) {
            self.addrs.push(p.addr);
        }
        self.label(p)
    }

    /// "A:27031": the address's letter and the port.
    pub fn label(&self, p: &Peer) -> String {
        let letter = match self.addrs.iter().position(|a| *a == p.addr) {
            Some(i) if i < 26 => char::from(b'A' + i as u8).to_string(),
            Some(i) => format!("#{}", i + 1),
            None => "?".into(),
        };
        format!("{letter}:{}", p.port)
    }

    /// The current server and its rate.
    pub fn main(&self) -> Option<(Peer, f64)> {
        self.main.map(|m| (m, self.rate(&m)))
    }

    /// Times the server changed this match.
    pub fn changes(&self) -> u32 {
        self.changes
    }

    /// Peers that sent anything since the last reading.
    pub fn active(&self) -> usize {
        self.active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(a: [u8; 4], port: u16) -> Peer {
        Peer {
            lport: 51234,
            addr: IpAddr::V4(Ipv4Addr::from(a)),
            port,
        }
    }

    struct Sim {
        s: Servers,
        counts: HashMap<Peer, u64>,
    }

    impl Sim {
        fn new() -> Self {
            Self {
                s: Servers::default(),
                counts: HashMap::new(),
            }
        }

        /// `secs` readings, each adding these packets per peer.
        fn run(&mut self, secs: usize, rates: &[(Peer, u64)]) -> Vec<ServerEvent> {
            let mut ev = Vec::new();
            for _ in 0..secs {
                for &(p, n) in rates {
                    *self.counts.entry(p).or_default() += n;
                }
                let now: Vec<(Peer, u64)> = self.counts.iter().map(|(p, n)| (*p, *n)).collect();
                ev.extend(self.s.update(1.0, &now));
            }
            ev
        }
    }

    #[test]
    fn the_server_is_the_busiest_peer_not_a_ping() {
        let a = peer([162, 254, 192, 73], 27031);
        let ping = peer([155, 133, 1, 1], 27017);
        let mut sim = Sim::new();
        let ev = sim.run(5, &[(a, 64), (ping, 1)]);
        assert_eq!(
            ev,
            vec![ServerEvent::First {
                peer: a,
                label: "A:27031".into(),
                pps: 64.0
            }]
        );
        assert_eq!(sim.s.main().map(|(p, _)| p), Some(a));
        assert_eq!(sim.s.active(), 2);
        assert_eq!(sim.s.changes(), 0);
    }

    #[test]
    fn a_new_server_takes_over_after_a_few_seconds() {
        let a = peer([162, 254, 192, 73], 27031);
        let a2 = peer([162, 254, 192, 73], 27044);
        let b = peer([155, 133, 2, 2], 27031);
        let mut sim = Sim::new();
        sim.run(10, &[(a, 64)]);
        // the end screen and loading: both for a moment, then only the new
        let ev = sim.run(2, &[(a, 64), (a2, 64)]);
        assert!(ev.is_empty(), "a tie isn't a change: {ev:?}");
        let ev = sim.run(5, &[(a2, 64)]);
        match &ev[..] {
            [
                ServerEvent::Changed {
                    from_label,
                    to_label,
                    ..
                },
            ] => {
                assert_eq!(
                    (from_label.as_str(), to_label.as_str()),
                    ("A:27031", "A:27044")
                );
            }
            other => panic!("{other:?}"),
        }
        // a new address gets the next letter
        let ev = sim.run(6, &[(b, 64)]);
        assert!(
            matches!(&ev[..], [ServerEvent::Changed { to_label, .. }] if to_label == "B:27031"),
            "{ev:?}"
        );
        assert_eq!(sim.s.changes(), 2);
    }

    #[test]
    fn a_short_burst_from_another_peer_isnt_a_change() {
        let a = peer([10, 0, 0, 1], 27031);
        let b = peer([10, 0, 0, 2], 27031);
        let mut sim = Sim::new();
        sim.run(5, &[(a, 64)]);
        // two seconds of something else, louder, then back
        sim.run(2, &[(a, 64), (b, 200)]);
        let ev = sim.run(5, &[(a, 64)]);
        assert!(ev.is_empty(), "{ev:?}");
        assert_eq!(sim.s.changes(), 0);
    }

    #[test]
    fn quiet_means_no_server_yet() {
        let mut sim = Sim::new();
        let ev = sim.run(5, &[(peer([10, 0, 0, 1], 1), 2)]);
        assert!(ev.is_empty());
        assert!(sim.s.main().is_none());
    }

    #[test]
    fn keys_become_peers() {
        let mut k = bpf_intf::flow_key {
            family: AF_INET,
            proto: 17,
            lport: 51234,
            rport: 27031,
            ..Default::default()
        };
        k.raddr[0] = u32::from_ne_bytes([162, 254, 192, 73]);
        assert_eq!(Peer::from_key(&k), Some(peer([162, 254, 192, 73], 27031)));
        let mut k6 = bpf_intf::flow_key {
            family: AF_INET6,
            lport: 1,
            rport: 2,
            ..Default::default()
        };
        k6.raddr = [
            u32::from_ne_bytes([0xfd, 0, 0, 0x99]),
            0,
            0,
            u32::from_ne_bytes([0, 0, 0, 1]),
        ];
        assert_eq!(
            Peer::from_key(&k6).map(|p| p.addr),
            Some("fd00:99::1".parse().unwrap())
        );
        k6.family = 0;
        assert_eq!(Peer::from_key(&k6), None);
    }
}
