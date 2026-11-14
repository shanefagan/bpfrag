// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! `bpfrag --selftest`: load the BPF object on *this* kernel and push
//! hand-built IPv4/IPv6 packets through both tc programs with
//! BPF_PROG_TEST_RUN. Nothing is attached and no system setting changes.
//!
//! For the DSCP marker it checks the rewritten DSCP / traffic class, that
//! ECN bits and the IPv6 flow label survive, that the IPv4 header checksum
//! is still valid, and that non-game, stale-owner and fragment packets are
//! left untouched; that the game's TCP connections are marked, and only
//! those (not another connection on the same local port, not TCP from the
//! game's UDP port); then that a bulk process's TCP and UDP flows are demoted
//! to the bulk class, unless the app marked them itself. For the arrival
//! meter, that packets to the game's port are counted, timed and counted
//! per sender, and nothing else is.

use std::mem::MaybeUninit;

use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, ProgramInput};

use crate::bpf_intf;
use crate::bpf_skel::{BpfSkel, BpfSkelBuilder};
use crate::config::{Config, parse_dscp};

const GAME_TGID: u32 = 4242;
const GAME_PORT: u16 = 27015;
const STALE_PORT: u16 = 27016; // owner no longer marked
const OTHER_PORT: u16 = 5000;
const GAME_TCP_PORT: u16 = 40100; // the game's TCP connection to PEER:443
const LOOPBACK_IFINDEX: u32 = 1; // test_run skbs come in on lo

fn csum16(bytes: &[u8]) -> u16 {
    let mut s: u32 = bytes
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

fn eth(ethertype: u16) -> Vec<u8> {
    let mut p = vec![0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01];
    p.extend_from_slice(&ethertype.to_be_bytes());
    p
}

fn udp(sport: u16, payload: usize) -> Vec<u8> {
    let mut u = Vec::new();
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&GAME_PORT.to_be_bytes());
    u.extend_from_slice(&((8 + payload) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend(std::iter::repeat_n(0x5a, payload));
    u
}

/// IPv4 UDP packet; `options` adds 4-byte option words (ihl > 5).
fn ipv4(tos: u8, sport: u16, frag_off: u16, options: u8) -> Vec<u8> {
    let ihl = 5 + options;
    let body = udp(sport, 120);
    let mut ip = vec![
        0x40 | ihl,
        tos,
        0,
        0,
        0x12,
        0x34,
        (frag_off >> 8) as u8,
        frag_off as u8,
        64,
        17,
        0,
        0,
        10,
        99,
        0,
        1,
        10,
        99,
        0,
        2,
    ];
    for _ in 0..options {
        ip.extend_from_slice(&[1, 1, 1, 0]); // NOP NOP NOP EOL
    }
    let tot = (ip.len() + body.len()) as u16;
    ip[2..4].copy_from_slice(&tot.to_be_bytes());
    let c = csum16(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    let mut p = eth(0x0800);
    p.extend(ip);
    p.extend(body);
    p
}

fn ipv6(tc: u8, flow: u32, sport: u16) -> Vec<u8> {
    let body = udp(sport, 120);
    let first = (6u32 << 28) | (u32::from(tc) << 20) | (flow & 0xfffff);
    let mut ip = first.to_be_bytes().to_vec();
    ip.extend_from_slice(&(body.len() as u16).to_be_bytes());
    ip.extend_from_slice(&[17, 64]);
    ip.extend_from_slice(&[0xfd, 0, 0, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    ip.extend_from_slice(&[0xfd, 0, 0, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let mut p = eth(0x86dd);
    p.extend(ip);
    p.extend(body);
    p
}

struct Case {
    name: String,
    pkt: Vec<u8>,
    /// expected DSCP+ECN byte after the run (tos / traffic class)
    expect: u8,
}

fn tos_of(p: &[u8]) -> u8 {
    if p[12..14] == [0x08, 0x00] {
        p[15]
    } else {
        ((p[14] & 0x0f) << 4) | (p[15] >> 4)
    }
}

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const TCP: u8 = 6;
const UDP: u8 = 17;
const HOST_V4: [u8; 4] = [10, 99, 0, 1];
const PEER_V4: [u8; 4] = [10, 99, 0, 2];
const HOST_V6: [u8; 16] = [0xfd, 0, 0, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const PEER_V6: [u8; 16] = [0xfd, 0, 0, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

/// A TCP (20-byte header, ACK set) or UDP header plus a small payload.
fn l4(proto: u8, sport: u16, dport: u16) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(&sport.to_be_bytes());
    h.extend_from_slice(&dport.to_be_bytes());
    if proto == TCP {
        h.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 0x50, 0x10, 0xff, 0xff, 0, 0, 0, 0]);
    } else {
        h.extend_from_slice(&108u16.to_be_bytes());
        h.extend_from_slice(&[0, 0]);
    }
    h.extend(std::iter::repeat_n(0x5a, 100));
    h
}

fn pkt4(tos: u8, proto: u8, src: [u8; 4], dst: [u8; 4], body: Vec<u8>) -> Vec<u8> {
    let mut ip = vec![0x45, tos, 0, 0, 0x12, 0x34, 0x40, 0, 64, proto, 0, 0];
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let tot = (ip.len() + body.len()) as u16;
    ip[2..4].copy_from_slice(&tot.to_be_bytes());
    let c = csum16(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    let mut p = eth(0x0800);
    p.extend(ip);
    p.extend(body);
    p
}

fn pkt6(tc: u8, proto: u8, src: [u8; 16], dst: [u8; 16], body: Vec<u8>) -> Vec<u8> {
    let first = (6u32 << 28) | (u32::from(tc) << 20) | 0x54321;
    let mut ip = first.to_be_bytes().to_vec();
    ip.extend_from_slice(&(body.len() as u16).to_be_bytes());
    ip.extend_from_slice(&[proto, 64]);
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let mut p = eth(0x86dd);
    p.extend(ip);
    p.extend(body);
    p
}

fn words(b: &[u8]) -> [u32; 4] {
    let mut w = [0u32; 4];
    for (i, c) in b.chunks(4).enumerate().take(4) {
        w[i] = u32::from_ne_bytes(c.try_into().unwrap());
    }
    w
}

/// A bulk_flows key as the kernel side builds it: addresses as they appear
/// in the packet, ports in host order, local first.
fn flow_key(family: u8, proto: u8, local: &[u8], lport: u16, remote: &[u8], rport: u16) -> Vec<u8> {
    let k = bpf_intf::flow_key {
        family,
        proto,
        lport,
        rport,
        laddr: words(local),
        raddr: words(remote),
        ..Default::default()
    };
    as_bytes(&k).to_vec()
}

fn as_bytes<T>(v: &T) -> &[u8] {
    // only used for the plain integer structs from intf.h
    unsafe { std::slice::from_raw_parts((v as *const T).cast::<u8>(), size_of::<T>()) }
}

/// Bulk flows through the marker and the meter. Returns (cases run,
/// failures).
fn check_bulk(skel: &mut BpfSkel, bulk: u8, game: u8) -> Result<(usize, usize)> {
    let m = &skel.maps;
    let owner = bpf_intf::bulk_flow { tgid: 777 };
    for key in [
        flow_key(AF_INET, TCP, &HOST_V4, 40000, &PEER_V4, 27016),
        // an unconnected UDP socket: protocol and local port only
        flow_key(0, UDP, &[0; 4], 40001, &[0; 4], 0),
        flow_key(AF_INET6, TCP, &HOST_V6, 40002, &PEER_V6, 443),
    ] {
        m.bulk_flows.update(&key, as_bytes(&owner), MapFlags::ANY)?;
    }
    crate::bpf::maps::bulk_tgid(skel, owner.tgid, true);
    crate::bpf::maps::bulk_active(skel, true);
    let b = bulk << 2;
    let af11 = 10u8 << 2;
    let cases = [
        Case {
            name: "IPv4 TCP bulk flow demoted".into(),
            pkt: pkt4(0, TCP, HOST_V4, PEER_V4, l4(TCP, 40000, 27016)),
            expect: b,
        },
        Case {
            name: "IPv4 bulk flow, ECT(0) kept".into(),
            pkt: pkt4(0x02, TCP, HOST_V4, PEER_V4, l4(TCP, 40000, 27016)),
            expect: b | 2,
        },
        Case {
            name: "IPv4 bulk flow the app marked AF11 left alone".into(),
            pkt: pkt4(af11, TCP, HOST_V4, PEER_V4, l4(TCP, 40000, 27016)),
            expect: af11,
        },
        Case {
            name: "IPv4 UDP from an unconnected bulk socket demoted".into(),
            pkt: pkt4(0, UDP, HOST_V4, PEER_V4, l4(UDP, 40001, 9999)),
            expect: b,
        },
        Case {
            name: "IPv4 TCP from a bulk port to another peer untouched".into(),
            pkt: pkt4(0, TCP, HOST_V4, PEER_V4, l4(TCP, 40000, 443)),
            expect: 0,
        },
        Case {
            name: "IPv6 TCP bulk flow demoted".into(),
            pkt: pkt6(0, TCP, HOST_V6, PEER_V6, l4(TCP, 40002, 443)),
            expect: b,
        },
        Case {
            name: "IPv4 game UDP keeps the game class while bulk is on".into(),
            pkt: pkt4(0, UDP, HOST_V4, PEER_V4, l4(UDP, GAME_PORT, 9999)),
            expect: game << 2,
        },
    ];
    // The same flows arriving, through the meter: local is the destination.
    let incoming = [
        Case {
            name: "incoming IPv4 TCP of a bulk flow demoted".into(),
            pkt: pkt4(0, TCP, PEER_V4, HOST_V4, l4(TCP, 27016, 40000)),
            expect: b,
        },
        Case {
            name: "incoming IPv6 TCP of a bulk flow demoted".into(),
            pkt: pkt6(0, TCP, PEER_V6, HOST_V6, l4(TCP, 443, 40002)),
            expect: b,
        },
        Case {
            name: "incoming UDP to an unconnected bulk socket demoted".into(),
            pkt: pkt4(0, UDP, PEER_V4, HOST_V4, l4(UDP, 9999, 40001)),
            expect: b,
        },
        Case {
            name: "incoming bulk packet the sender marked AF11 left alone".into(),
            pkt: pkt4(af11, TCP, PEER_V4, HOST_V4, l4(TCP, 27016, 40000)),
            expect: af11,
        },
        Case {
            name: "incoming game packet not demoted".into(),
            pkt: pkt4(0, UDP, PEER_V4, HOST_V4, l4(UDP, 9999, GAME_PORT)),
            expect: 0,
        },
    ];
    let mut failed = 0;
    let mut run = |skel: &BpfSkel, c: &Case, ingress: bool| match run_case_on(skel, c, ingress) {
        Ok(()) => println!("  PASS {}", c.name),
        Err(e) => {
            failed += 1;
            println!("  FAIL {}: {e}", c.name);
        }
    };
    for c in &cases {
        run(skel, c, false);
    }
    for c in &incoming {
        run(skel, c, true);
    }
    // Once its process is let go, a flow still in the map isn't demoted,
    // even one learned after the release (a send that raced it).
    crate::bpf::maps::bulk_tgid(skel, owner.tgid, false);
    for key in [
        flow_key(AF_INET, TCP, &HOST_V4, 40000, &PEER_V4, 27016),
        flow_key(0, UDP, &[0; 4], 40001, &[0; 4], 0),
    ] {
        skel.maps
            .bulk_flows
            .update(&key, as_bytes(&owner), MapFlags::ANY)?;
    }
    run(
        skel,
        &Case {
            name: "released bulk process: its flow no longer demoted".into(),
            pkt: pkt4(0, TCP, HOST_V4, PEER_V4, l4(TCP, 40000, 27016)),
            expect: 0,
        },
        false,
    );
    run(
        skel,
        &Case {
            name: "released bulk process: its unconnected UDP socket neither".into(),
            pkt: pkt4(0, UDP, PEER_V4, HOST_V4, l4(UDP, 9999, 40001)),
            expect: 0,
        },
        true,
    );
    crate::bpf::maps::bulk_tgid(skel, owner.tgid, true);
    // with the switch off, nothing is looked up or demoted
    crate::bpf::maps::bulk_active(skel, false);
    let off = Case {
        name: "bulk switched off: nothing demoted".into(),
        pkt: pkt4(0, TCP, HOST_V4, PEER_V4, l4(TCP, 40000, 27016)),
        expect: 0,
    };
    run(skel, &off, false);
    run(
        skel,
        &Case {
            name: "bulk switched off: nothing demoted on ingress".into(),
            pkt: pkt4(0, TCP, PEER_V4, HOST_V4, l4(TCP, 27016, 40000)),
            expect: 0,
        },
        true,
    );
    crate::bpf::maps::clear_bulk(skel);
    Ok((cases.len() + incoming.len() + 4, failed))
}

/// The packet with its UDP destination port set to `dport`.
fn to_port(mut p: Vec<u8>, dport: u16) -> Vec<u8> {
    let udp = if p[12..14] == [0x08, 0x00] {
        14 + usize::from(p[14] & 0x0f) * 4
    } else {
        14 + 40
    };
    p[udp + 2..udp + 4].copy_from_slice(&dport.to_be_bytes());
    p
}

/// The tc programs must return TCX_NEXT (-1), so other tcx programs and
/// classic tc filters on the interface still run. TC_ACT_OK would end the
/// chain there and, for example, skip a CAKE setup's redirect to its IFB.
fn check_verdict(ret: u32) -> Result<(), String> {
    if ret as i32 == -1 {
        Ok(())
    } else {
        Err(format!(
            "returned {} instead of TCX_NEXT (-1): later tc filters would be skipped",
            ret as i32
        ))
    }
}

/// Arrivals through the meter: packets to the game's port must be counted
/// and timed, packets to other ports, to an untracked owner's port, and
/// non-first fragments ignored.
fn check_meter(skel: &BpfSkel) -> Result<String, String> {
    let to_game = [
        to_port(ipv4(0, OTHER_PORT, 0x4000, 0), GAME_PORT),
        to_port(ipv4(0, OTHER_PORT, 0x4000, 2), GAME_PORT),
        to_port(ipv6(0, 1, OTHER_PORT), GAME_PORT),
        to_port(ipv4(0, OTHER_PORT, 0x4000, 0), GAME_PORT),
    ];
    let ignored = [
        to_port(ipv4(0, GAME_PORT, 0x4000, 0), OTHER_PORT),
        to_port(ipv4(0, GAME_PORT, 0x4000, 0), STALE_PORT),
        to_port(ipv4(0, OTHER_PORT, 0x00b9, 0), GAME_PORT),
    ];
    // The first three back to back are one update (a server splitting it
    // into packets); the fourth, 6 ms later, is the next one.
    for (i, pkt) in to_game.iter().chain(&ignored).enumerate() {
        if i == 3 {
            std::thread::sleep(std::time::Duration::from_millis(6));
        }
        let input = ProgramInput {
            data_in: Some(pkt),
            ..Default::default()
        };
        let res = skel
            .progs
            .bpfrag_rx
            .test_run(input)
            .map_err(|e| format!("test_run failed: {e}"))?;
        check_verdict(res.return_value)?;
    }
    let ports = crate::bpf::maps::read_port_rx(skel);
    let others: Vec<u16> = ports
        .iter()
        .map(|(p, _)| *p)
        .filter(|p| *p != GAME_PORT)
        .collect();
    if !others.is_empty() {
        return Err(format!("counted arrivals on other ports {others:?}"));
    }
    let r = ports
        .iter()
        .find(|(p, _)| *p == GAME_PORT)
        .map(|(_, r)| *r)
        .ok_or("no arrivals counted on the game port")?;
    // Test-run packets come from no receive queue: the kernel reports
    // NAPI id 0 for them, and the meter must keep it that way.
    if r.napi_id != 0 {
        return Err(format!(
            "recorded NAPI id {} for a packet with none",
            r.napi_id
        ));
    }
    let gaps: u32 = r.hist.iter().sum();
    let want = to_game.len() as u64;
    // one gap, between the two updates: at least the 6 ms slept
    let gap_ms = r.hist.iter().position(|n| *n > 0);
    if r.pkts != want || r.updates != 2 || gaps != 1 || gap_ms.is_none_or(|ms| ms < 5) {
        return Err(format!(
            "{} packets, {} updates, {gaps} gaps (at {gap_ms:?} ms), expected {want}, 2 and \
             1 of 6 ms or more",
            r.pkts, r.updates
        ));
    }
    // The same gap to the nanosecond, and no jitter yet: there's no gap
    // before it to differ from.
    if r.fine_n != 1 || r.sum_gap_ns != r.max_gap_ns || r.jitter_n != 0 {
        return Err(format!(
            "fine timing: {} gaps summing {} ns (longest {} ns), {} jitter samples; \
             expected 1 gap equal to the longest, none",
            r.fine_n, r.sum_gap_ns, r.max_gap_ns, r.jitter_n
        ));
    }
    // Who sent them: three from 10.99.0.1, one from fd00:99::1, both from
    // OTHER_PORT; the ignored packets count for nobody.
    let mut peers: Vec<(String, u16, u16, u64)> = crate::bpf::maps::read_game_peers(skel)
        .into_iter()
        .map(|(p, r)| (p.addr.to_string(), p.port, p.lport, r.pkts))
        .collect();
    peers.sort();
    let expect = vec![
        ("10.99.0.1".to_string(), OTHER_PORT, GAME_PORT, 3),
        ("fd00:99::1".to_string(), OTHER_PORT, GAME_PORT, 1),
    ];
    if peers != expect {
        return Err(format!(
            "arrivals per sender {peers:?}, expected {expect:?}"
        ));
    }
    Ok(format!(
        "{want} packets in 2 updates, {gaps} gap, {} senders",
        peers.len()
    ))
}

/// Each game port's longest gap per reading: after `check_meter`, its
/// 6 ms gap belongs to reading 0; once userspace starts reading 1, the next
/// gap starts that reading's longest afresh.
fn check_readings(skel: &mut BpfSkel) -> Result<String, String> {
    let game = |skel: &BpfSkel| {
        crate::bpf::maps::read_port_rx(skel)
            .into_iter()
            .find(|(p, _)| *p == GAME_PORT)
            .map(|(_, r)| r)
            .ok_or("no arrivals on the game port")
    };
    let r = game(skel)?;
    if r.reading != 0 || r.reading_max_ns != r.max_gap_ns || r.max_gap_ns < 5_000_000 {
        return Err(format!(
            "reading {} longest {} ns, overall {} ns: expected reading 0, both the 6 ms gap",
            r.reading, r.reading_max_ns, r.max_gap_ns
        ));
    }
    let first = r.reading_max_ns;
    if crate::bpf::maps::next_reading(skel) != 0 {
        return Err("the first reading wasn't 0".into());
    }
    std::thread::sleep(std::time::Duration::from_millis(10));
    let pkt = to_port(ipv4(0, OTHER_PORT, 0x4000, 0), GAME_PORT);
    let input = ProgramInput {
        data_in: Some(&pkt),
        ..Default::default()
    };
    let res = skel
        .progs
        .bpfrag_rx
        .test_run(input)
        .map_err(|e| format!("test_run failed: {e}"))?;
    check_verdict(res.return_value)?;
    let r = game(skel)?;
    if r.reading != 1 || r.reading_max_ns < 9_000_000 || r.max_gap_ns < r.reading_max_ns {
        return Err(format!(
            "reading {} longest {} ns, overall {} ns: expected reading 1's own gap of 10 ms or more",
            r.reading, r.reading_max_ns, r.max_gap_ns
        ));
    }
    // the second gap differs from the first by exactly their difference
    let want = r.reading_max_ns.abs_diff(first);
    if r.fine_n != 2 || r.jitter_n != 1 || r.sum_jitter_ns != want {
        return Err(format!(
            "fine timing: {} gaps, {} jitter samples summing {} ns; expected 2, 1 of {want} ns",
            r.fine_n, r.jitter_n, r.sum_jitter_ns
        ));
    }
    Ok(format!(
        "{} ms in reading 0, {} ms in reading 1",
        first / 1_000_000,
        r.reading_max_ns / 1_000_000
    ))
}

/// A quiet stretch of GAP_IDLE_MS or more isn't a gap or a stall, but is
/// reported on its own once the flow is back at game rate (GAP_RESUME
/// fast gaps), for user space to tell an outage from a lobby.
fn check_quiet(skel: &BpfSkel) -> Result<String, String> {
    let game = || {
        crate::bpf::maps::read_port_rx(skel)
            .into_iter()
            .find(|(p, _)| *p == GAME_PORT)
            .map(|(_, r)| r)
            .ok_or("no arrivals on the game port")
    };
    let before = game()?;
    let idle = u64::from(crate::bpf_intf::GAP_IDLE_MS);
    std::thread::sleep(std::time::Duration::from_millis(idle + 50));
    let pkt = to_port(ipv4(0, OTHER_PORT, 0x4000, 0), GAME_PORT);
    for i in 0..=crate::bpf_intf::GAP_RESUME {
        if i > 0 {
            std::thread::sleep(std::time::Duration::from_millis(6));
        }
        let input = ProgramInput {
            data_in: Some(&pkt),
            ..Default::default()
        };
        let res = skel
            .progs
            .bpfrag_rx
            .test_run(input)
            .map_err(|e| format!("test_run failed: {e}"))?;
        check_verdict(res.return_value)?;
    }
    let r = game()?;
    if r.quiets != before.quiets + 1 || r.quiet_ns < idle * 1_000_000 {
        return Err(format!(
            "{} quiet stretches (were {}), the latest {} ns: expected one more, of {idle} ms or over",
            r.quiets, before.quiets, r.quiet_ns
        ));
    }
    if r.stalls != before.stalls || r.max_gap_ns != before.max_gap_ns {
        return Err(format!(
            "stalls {} (were {}), longest gap {} ns (was {}): a long quiet stretch isn't either",
            r.stalls, before.stalls, r.max_gap_ns, before.max_gap_ns
        ));
    }
    Ok(format!("{} ms", r.quiet_ns / 1_000_000))
}

/// On loopback (flagged local), game packets are counted against the
/// interface but not timed or counted per sender: the game talking to
/// itself isn't the match.
fn check_local_meter(skel: &BpfSkel) -> Result<String, String> {
    let rx = &skel.maps.rx_ifaces;
    let key = LOOPBACK_IFINDEX.to_ne_bytes();
    let set = |local: bool| {
        rx.update(
            &key,
            &crate::bpf::maps::mark_iface_bytes(14, local),
            MapFlags::ANY,
        )
        .map_err(|e| format!("rx_ifaces update: {e}"))
    };
    crate::bpf::maps::clear_port_rx(skel);
    set(true)?;
    let pkt = to_port(ipv4(0, OTHER_PORT, 0x4000, 0), GAME_PORT);
    let mut result = Ok(());
    for _ in 0..3 {
        let input = ProgramInput {
            data_in: Some(&pkt),
            ..Default::default()
        };
        match skel.progs.bpfrag_rx.test_run(input) {
            Ok(r) => {
                if let Err(e) = check_verdict(r.return_value) {
                    result = Err(e);
                }
            }
            Err(e) => result = Err(format!("test_run failed: {e}")),
        }
    }
    let counted = crate::bpf::maps::meter_packets(skel)
        .into_iter()
        .find(|(i, _, _)| *i == LOOPBACK_IFINDEX)
        .map(|(_, n, local)| (n, local));
    let timed = crate::bpf::maps::read_port_rx(skel).len();
    let senders = crate::bpf::maps::read_game_peers(skel).len();
    set(false)?;
    result?;
    match counted {
        Some((3, true)) if timed == 0 && senders == 0 => Ok("3 counted, none timed".into()),
        other => Err(format!(
            "counted {other:?} on loopback, {timed} ports timed, {senders} senders; \
             expected 3, local, and none timed"
        )),
    }
}

fn run_case(skel: &BpfSkel, c: &Case) -> Result<(), String> {
    run_case_on(skel, c, false)
}

/// Run a case through the marker (egress) or the meter (ingress).
fn run_case_on(skel: &BpfSkel, c: &Case, ingress: bool) -> Result<(), String> {
    let mut out = vec![0u8; c.pkt.len() + 64];
    let input = ProgramInput {
        data_in: Some(&c.pkt),
        data_out: Some(&mut out),
        ..Default::default()
    };
    let prog = if ingress {
        &skel.progs.bpfrag_rx
    } else {
        &skel.progs.bpfrag_dscp
    };
    let res = prog
        .test_run(input)
        .map_err(|e| format!("test_run failed: {e}"))?;
    check_verdict(res.return_value)?;
    let got = res.data.ok_or("no output packet")?.to_vec();
    if got.len() != c.pkt.len() {
        return Err(format!("length changed {} -> {}", c.pkt.len(), got.len()));
    }
    let tos = tos_of(&got);
    if tos != c.expect {
        return Err(format!(
            "tos/class 0x{tos:02x}, expected 0x{:02x}",
            c.expect
        ));
    }
    let is_v4 = got[12..14] == [0x08, 0x00];
    // Only the DSCP byte (and, for IPv4, the header checksum) may change.
    let allowed: &[usize] = if is_v4 { &[15, 24, 25] } else { &[14, 15] };
    for (i, (a, b)) in c.pkt.iter().zip(&got).enumerate() {
        if a != b && !allowed.contains(&i) {
            return Err(format!("byte {i} changed 0x{a:02x} -> 0x{b:02x}"));
        }
    }
    if is_v4 {
        let ihl = usize::from(got[14] & 0x0f) * 4;
        if csum16(&got[14..14 + ihl]) != 0 {
            return Err("IPv4 header checksum invalid after rewrite".into());
        }
    } else {
        let flow_in = u32::from_be_bytes(c.pkt[14..18].try_into().unwrap()) & 0xfffff;
        let flow_out = u32::from_be_bytes(got[14..18].try_into().unwrap()) & 0xfffff;
        if flow_in != flow_out || got[14] >> 4 != 6 {
            return Err("IPv6 version/flow label damaged".into());
        }
    }
    Ok(())
}

/// Packets the fuzzer starts from: the cases' own, both directions'
/// bulk shapes, VLAN-tagged and non-IP frames.
fn fuzz_seeds(cases: &[Case]) -> Vec<Vec<u8>> {
    let mut seeds: Vec<Vec<u8>> = cases.iter().map(|c| c.pkt.clone()).collect();
    seeds.push(pkt4(0, TCP, HOST_V4, PEER_V4, l4(TCP, 40000, 443)));
    seeds.push(pkt6(0, TCP, HOST_V6, PEER_V6, l4(TCP, 40000, 443)));
    // IPv6 with a hop-by-hop header before UDP
    let mut hbh = ipv6(0, 0x1, GAME_PORT);
    hbh[20] = 0; // next header: hop-by-hop
    hbh.splice(54..54, [17u8, 0, 1, 4, 0, 0, 0, 0]);
    seeds.push(hbh);
    // VLAN-tagged IPv4, ARP
    let mut vlan = ipv4(0, GAME_PORT, 0x4000, 0);
    vlan.splice(12..12, [0x81, 0x00, 0x00, 0x01]);
    seeds.push(vlan);
    let mut arp = eth(0x0806);
    arp.extend([0u8; 28]);
    seeds.push(arp);
    seeds
}

/// xorshift64*: reproducible from its seed, which the output prints.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// One mutation of a seed: flipped bytes, a cut, an extension, or noise.
fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut p = seed.to_vec();
    match rng.below(5) {
        0 => {
            for _ in 0..1 + rng.below(8) {
                let i = rng.below(p.len());
                p[i] ^= 1 << rng.below(8);
            }
        }
        1 => {
            for _ in 0..1 + rng.below(4) {
                let i = rng.below(p.len());
                p[i] = rng.next() as u8;
            }
        }
        2 => p.truncate(14 + rng.below(p.len() - 13)),
        3 => p.extend((0..rng.below(64)).map(|_| rng.next() as u8)),
        _ => {
            let n = 14 + rng.below(120);
            p = (0..n).map(|_| rng.next() as u8).collect();
            // mostly IP, so the parsers past the Ethernet header get used
            let et: &[u8] = match rng.below(3) {
                0 => &[0x08, 0x00],
                1 => &[0x86, 0xdd],
                _ => &[p[12], p[13]],
            };
            let et = [et[0], et[1]];
            p[12..14].copy_from_slice(&et);
        }
    }
    p
}

fn v4_header_ok(p: &[u8]) -> Option<bool> {
    if p.len() < 34 || p[12..14] != [0x08, 0x00] || p[14] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(p[14] & 0x0f) * 4;
    (ihl >= 20 && p.len() >= 14 + ihl).then(|| csum16(&p[14..14 + ihl]) == 0)
}

/// Random and mutated packets through the marker and the meter: each must
/// be passed on (TCX_NEXT), the same length, with nothing changed but its
/// DSCP (and the IPv4 header checksum to match), and an IPv4 header that
/// was valid must stay valid. The verifier already proves the programs
/// can't crash; this checks they never damage or drop a packet.
fn check_fuzz(skel: &BpfSkel, seeds: &[Vec<u8>], n: usize, seed: u64) -> Result<String, String> {
    let mut rng = Rng(seed | 1);
    let (mut changed, mut refused) = (0, 0);
    for i in 0..n {
        let which = rng.below(seeds.len());
        let pkt = mutate(&mut rng, &seeds[which]);
        for (ingress, prog) in [
            (false, &skel.progs.bpfrag_dscp),
            (true, &skel.progs.bpfrag_rx),
        ] {
            let mut out = vec![0u8; pkt.len() + 64];
            let input = ProgramInput {
                data_in: Some(&pkt),
                data_out: Some(&mut out),
                ..Default::default()
            };
            let what = if ingress { "meter" } else { "marker" };
            let fail = |e: String| format!("{what}, packet {i} ({}): {e}", hex(&pkt));
            // The kernel turns some frames away before the program sees
            // them (EINVAL from setting up the skb): nothing to check.
            let res = match prog.test_run(input) {
                Ok(r) => r,
                Err(e) if e.kind() == libbpf_rs::ErrorKind::InvalidInput => {
                    refused += 1;
                    continue;
                }
                Err(e) => return Err(fail(format!("test_run failed: {e}"))),
            };
            check_verdict(res.return_value).map_err(fail)?;
            let got = res
                .data
                .ok_or_else(|| fail("no output packet".into()))?
                .to_vec();
            if got.len() != pkt.len() {
                return Err(fail(format!(
                    "length changed {} -> {}",
                    pkt.len(),
                    got.len()
                )));
            }
            let allowed: &[usize] = match &pkt[12..14] {
                [0x08, 0x00] => &[15, 24, 25],
                [0x86, 0xdd] => &[14, 15],
                _ => &[],
            };
            for (j, (a, b)) in pkt.iter().zip(&got).enumerate() {
                if a != b && !allowed.contains(&j) {
                    return Err(fail(format!("byte {j} changed 0x{a:02x} -> 0x{b:02x}")));
                }
            }
            if got != pkt {
                changed += 1;
                if v4_header_ok(&pkt) == Some(true) && v4_header_ok(&got) != Some(true) {
                    return Err(fail("a valid IPv4 header checksum broken".into()));
                }
                if pkt[12..14] == [0x86, 0xdd]
                    && (got[14] >> 4 != pkt[14] >> 4 || got[15] & 0x0f != pkt[15] & 0x0f)
                {
                    return Err(fail("IPv6 version or flow label changed".into()));
                }
            }
        }
    }
    Ok(format!(
        "{n} packets each way, {changed} remarked, {refused} turned away by the kernel, seed {seed:#x}"
    ))
}

fn hex(p: &[u8]) -> String {
    p.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn run(cfg: &Config) -> Result<bool> {
    let dscp = parse_dscp(&cfg.dscp.class)?;
    let over = cfg.dscp.override_app;

    let mut open_object = MaybeUninit::uninit();
    let mut open = BpfSkelBuilder::default()
        .open(&mut open_object)
        .context("opening BPF object")?;
    let rodata = open
        .maps
        .rodata_data
        .as_deref_mut()
        .context("BPF rodata missing")?;
    rodata.dscp = dscp;
    rodata.dscp_override = over;
    rodata.set_priority = cfg.dscp.set_priority;
    let bulk = parse_dscp(&cfg.bulk.class)?;
    rodata.bulk_dscp = bulk;
    // Only the tc program is under test; don't depend on the tracing hooks.
    let p = &mut open.progs;
    p.bpfrag_send_tp.set_autoload(false);
    p.bpfrag_recv_tp.set_autoload(false);
    p.bpfrag_exit.set_autoload(false);
    p.bpfrag_dscp.set_autoload(true);
    p.bpfrag_rx.set_autoload(true);
    let mut skel = open.load().context("loading the tc programs")?;

    let m = &skel.maps;
    for map in [&m.mark_ifaces, &m.rx_ifaces] {
        map.update(
            &LOOPBACK_IFINDEX.to_ne_bytes(),
            &crate::bpf::maps::mark_iface_bytes(14, false),
            MapFlags::ANY,
        )?;
    }
    m.game_tgids
        .update(&GAME_TGID.to_ne_bytes(), &[1u8], MapFlags::ANY)?;
    for (port, owner) in [(GAME_PORT, GAME_TGID), (STALE_PORT, 9999)] {
        let pm = bpf_intf::game_port { tgid: owner };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&pm as *const bpf_intf::game_port).cast::<u8>(),
                size_of_val(&pm),
            )
        };
        m.game_ports
            .update(&u32::from(port).to_ne_bytes(), bytes, MapFlags::ANY)?;
    }

    for key in [
        flow_key(AF_INET, TCP, &HOST_V4, GAME_TCP_PORT, &PEER_V4, 443),
        flow_key(AF_INET6, TCP, &HOST_V6, GAME_TCP_PORT, &PEER_V6, 443),
    ] {
        let owner = bpf_intf::game_port { tgid: GAME_TGID };
        m.game_tcp_flows
            .update(&key, as_bytes(&owner), MapFlags::ANY)?;
    }

    let d = dscp << 2;
    let ef = 46u8 << 2;
    let other_v4 = [10, 99, 0, 3];
    let cases = vec![
        Case {
            name: "IPv4 game port, unmarked".into(),
            pkt: ipv4(0x00, GAME_PORT, 0x4000, 0),
            expect: d,
        },
        Case {
            name: "IPv4 game port, ECT(1) kept".into(),
            pkt: ipv4(0x01, GAME_PORT, 0x4000, 0),
            expect: d | 1,
        },
        Case {
            name: "IPv4 game port, CE kept".into(),
            pkt: ipv4(0x03, GAME_PORT, 0, 0),
            expect: d | 3,
        },
        Case {
            name: format!(
                "IPv4 game port, app chose EF ({})",
                if over { "override" } else { "respected" }
            ),
            pkt: ipv4(ef, GAME_PORT, 0x4000, 0),
            expect: if over { d } else { ef },
        },
        Case {
            name: "IPv4 game port with IP options".into(),
            pkt: ipv4(0x00, GAME_PORT, 0x4000, 2),
            expect: d,
        },
        Case {
            name: "IPv4 non-first fragment untouched".into(),
            pkt: ipv4(0x00, GAME_PORT, 0x00b9, 0),
            expect: 0,
        },
        Case {
            name: "IPv4 other process's port untouched".into(),
            pkt: ipv4(0x00, OTHER_PORT, 0x4000, 0),
            expect: 0,
        },
        Case {
            name: "IPv4 port of an unmarked owner untouched".into(),
            pkt: ipv4(0x00, STALE_PORT, 0x4000, 0),
            expect: 0,
        },
        Case {
            name: "IPv6 game port, flow label kept".into(),
            pkt: ipv6(0x00, 0xabcde, GAME_PORT),
            expect: d,
        },
        Case {
            name: "IPv6 game port, ECT(0) kept".into(),
            pkt: ipv6(0x02, 0x12345, GAME_PORT),
            expect: d | 2,
        },
        Case {
            name: "IPv6 other process's port untouched".into(),
            pkt: ipv6(0x00, 0x1, OTHER_PORT),
            expect: 0,
        },
        Case {
            name: "IPv4 game port, the game's TCP connection".into(),
            pkt: pkt4(0, TCP, HOST_V4, PEER_V4, l4(TCP, GAME_TCP_PORT, 443)),
            expect: d,
        },
        Case {
            name: "IPv6 game port, the game's TCP connection".into(),
            pkt: pkt6(0, TCP, HOST_V6, PEER_V6, l4(TCP, GAME_TCP_PORT, 443)),
            expect: d,
        },
        Case {
            name: "IPv4 TCP on the same local port to another server untouched".into(),
            pkt: pkt4(0, TCP, HOST_V4, other_v4, l4(TCP, GAME_TCP_PORT, 443)),
            expect: 0,
        },
        Case {
            name: "IPv4 TCP from the number of the game's UDP port untouched".into(),
            pkt: pkt4(0, TCP, HOST_V4, PEER_V4, l4(TCP, GAME_PORT, 443)),
            expect: 0,
        },
    ];

    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    println!(
        "bpfrag selftest: DSCP marker on kernel {} ({} = {dscp}, override {})",
        kernel.trim(),
        cfg.dscp.class,
        if over { "on" } else { "off" }
    );
    let mut failed = 0;
    for c in &cases {
        match run_case(&skel, c) {
            Ok(()) => println!("  PASS {}", c.name),
            Err(e) => {
                failed += 1;
                println!("  FAIL {}: {e}", c.name);
            }
        }
    }
    // Every game packet that reached the marker is counted against the
    // interface; that is how bpfrag learns which link the game uses.
    let want = cases
        .iter()
        .filter(|c| c.name.contains("game port") && !c.name.contains("fragment"))
        .count() as u64;
    let got = crate::bpf::maps::game_packets(&skel)
        .into_iter()
        .find(|(i, _)| *i == LOOPBACK_IFINDEX)
        .map_or(0, |(_, n)| n);
    let mut total = cases.len() + 2;
    if got == want {
        println!("  PASS game packets counted per interface ({got})");
    } else {
        failed += 1;
        println!("  FAIL game packets counted per interface: {got}, expected {want}");
    }
    match check_meter(&skel) {
        Ok(what) => println!("  PASS arrivals on the game port timed ({what})"),
        Err(e) => {
            failed += 1;
            println!("  FAIL arrival meter: {e}");
        }
    }
    total += 1;
    match check_readings(&mut skel) {
        Ok(what) => println!("  PASS longest gap per reading ({what})"),
        Err(e) => {
            failed += 1;
            println!("  FAIL longest gap per reading: {e}");
        }
    }
    total += 1;
    match check_quiet(&skel) {
        Ok(what) => println!("  PASS long quiet stretch reported apart from gaps ({what})"),
        Err(e) => {
            failed += 1;
            println!("  FAIL long quiet stretch reported apart from gaps: {e}");
        }
    }
    total += 1;
    match check_local_meter(&skel) {
        Ok(what) => println!("  PASS loopback arrivals counted, not measured ({what})"),
        Err(e) => {
            failed += 1;
            println!("  FAIL loopback arrivals: {e}");
        }
    }
    let (n, f) = check_bulk(&mut skel, bulk, dscp)?;
    total += n;
    failed += f;
    // BPFRAG_FUZZ_SEED repeats a run; BPFRAG_FUZZ_PACKETS runs more
    let seed = std::env::var("BPFRAG_FUZZ_SEED")
        .ok()
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(1, |d| d.as_nanos() as u64)
        });
    let packets = std::env::var("BPFRAG_FUZZ_PACKETS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2000);
    total += 1;
    match check_fuzz(&skel, &fuzz_seeds(&cases), packets, seed) {
        Ok(what) => println!("  PASS random and damaged packets passed on unharmed ({what})"),
        Err(e) => {
            failed += 1;
            println!("  FAIL fuzzing: {e} (BPFRAG_FUZZ_SEED={seed:#x} repeats it)");
        }
    }
    println!("{}/{total} passed", total - failed);
    Ok(failed == 0)
}
