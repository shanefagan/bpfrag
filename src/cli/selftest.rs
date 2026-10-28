// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! `bpfrag --selftest`: load the BPF object on *this* kernel and push
//! hand-built IPv4/IPv6 packets through both tc programs with
//! BPF_PROG_TEST_RUN. Nothing is attached and no system setting changes.
//!
//! For the DSCP marker it checks the rewritten DSCP / traffic class, that
//! ECN bits and the IPv6 flow label survive, that the IPv4 header checksum
//! is still valid, and that non-game, stale-owner and fragment packets are
//! left untouched; then that a bulk process's TCP and UDP flows are demoted
//! to the bulk class, unless the app marked them itself. For the arrival
//! meter, that packets to the game's port are counted and timed and nothing
//! else is.

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
    for pkt in to_game.iter().chain(&ignored) {
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
    if r.pkts != want || u64::from(gaps) != want - 1 {
        return Err(format!(
            "{} packets and {gaps} gaps, expected {want} and {}",
            r.pkts,
            want - 1
        ));
    }
    Ok(format!("{want} packets, {gaps} gaps"))
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
            &crate::bpf::maps::mark_iface_bytes(14),
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

    let d = dscp << 2;
    let ef = 46u8 << 2;
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
    let (n, f) = check_bulk(&mut skel, bulk, dscp)?;
    total += n;
    failed += f;
    println!("{}/{total} passed", total - failed);
    Ok(failed == 0)
}
