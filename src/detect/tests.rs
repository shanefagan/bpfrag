// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Tests of the detector: counters in, actions out.

use super::*;

struct FakeProcs {
    games: Vec<u32>,
    excluded: Vec<u32>,
    dead: Vec<u32>,
    /// When each process started, in the simulation's seconds.
    started: HashMap<u32, f64>,
    now: f64,
}

impl ProcessLookup for FakeProcs {
    fn verdict(&mut self, tgid: u32) -> (Verdict, String) {
        if self.games.contains(&tgid) {
            (Verdict::Game("test".into()), format!("game{tgid}"))
        } else if self.excluded.contains(&tgid) {
            (Verdict::Excluded("test".into()), format!("proc{tgid}"))
        } else {
            (Verdict::NotGame("test".into()), format!("proc{tgid}"))
        }
    }
    fn alive(&mut self, tgid: u32) -> bool {
        !self.dead.contains(&tgid)
    }
    fn age_secs(&mut self, tgid: u32) -> Option<f64> {
        self.started.get(&tgid).map(|s| self.now - s)
    }
}

/// Drive the detector with constant per-second rates.
struct Sim {
    det: Detector,
    now: f64,
    counters: HashMap<u32, Sample>,
    procs: FakeProcs,
    /// What the arrival meter reports each window, when asked.
    arrivals: Arrivals,
    /// What the match exchanges with peers other than its server.
    others: f64,
    /// TCP bytes each game receives a second.
    tcp_rx: u64,
}

impl Sim {
    fn new(games: &[u32]) -> Self {
        Self {
            det: Detector::new(Detect::default()),
            now: 0.0,
            counters: HashMap::new(),
            procs: FakeProcs {
                games: games.to_vec(),
                excluded: vec![],
                dead: vec![],
                started: HashMap::new(),
                now: 0.0,
            },
            arrivals: Arrivals::default(),
            others: 0.0,
            tcp_rx: 0,
        }
    }

    /// Checking where the traffic goes, as the daemon does.
    fn with_paths(games: &[u32]) -> Self {
        let mut sim = Self::new(games);
        sim.det = Detector::new(Detect::default()).with_paths();
        sim
    }

    /// rates: (tgid, tx_pps, rx_pps, payload bytes)
    fn step(&mut self, rates: &[(u32, u64, u64, u64)]) -> Vec<Action> {
        for &(tgid, tx, rx, size) in rates {
            let c = self.counters.entry(tgid).or_insert(Sample {
                tgid,
                ..Default::default()
            });
            c.tx_pkts += tx;
            c.rx_pkts += rx;
            c.tx_bytes += tx * size;
            c.rx_bytes += rx * size;
            c.tcp_rx_bytes += self.tcp_rx;
        }
        self.now += 1.0;
        self.procs.now = self.now;
        let samples: Vec<Sample> = self.counters.values().copied().collect();
        if self.det.wants_paths() {
            self.det.paths(self.arrivals);
        }
        if self.det.session().is_some() {
            self.det.others(self.others);
        }
        self.det.tick(self.now, 1.0, &samples, &mut self.procs)
    }

    fn run(&mut self, secs: usize, rates: &[(u32, u64, u64, u64)]) -> Vec<Action> {
        (0..secs).flat_map(|_| self.step(rates)).collect()
    }

    /// The process exits: BPF deletes its map entry.
    fn exit(&mut self, tgid: u32) {
        self.counters.remove(&tgid);
    }
}

fn starts(a: &[Action]) -> Vec<&SessionInfo> {
    a.iter()
        .filter_map(|a| match a {
            Action::Start(i) => Some(i),
            _ => None,
        })
        .collect()
}

#[test]
fn tick_rate_game_starts_competitive_session() {
    let mut sim = Sim::new(&[42]);
    // 64-tick shooter: 64 up, 64 down, ~180 byte payloads
    // first tick is a baseline, then 3 steady windows
    assert!(starts(&sim.run(3, &[(42, 64, 64, 180)])).is_empty());
    let a = sim.run(1, &[(42, 64, 64, 180)]);
    let s = starts(&a);
    assert_eq!(s.len(), 1, "{a:?}");
    assert_eq!(s[0].tgid, 42);
    assert_eq!(s[0].tier, Tier::Competitive); // 128 pps total
}

#[test]
fn high_tick_goes_intense_and_quiet_ends() {
    let mut sim = Sim::new(&[7]);
    let a = sim.run(4, &[(7, 128, 128, 120)]);
    assert_eq!(starts(&a).len(), 1, "{a:?}");
    assert_eq!(starts(&a)[0].tier, Tier::Intense);
    // match over: back in menus with a trickle
    let a = sim.run(20, &[(7, 1, 1, 80)]);
    assert!(a.iter().any(|x| matches!(x, Action::End { .. })), "{a:?}");
    assert!(sim.det.session().is_none());
}

#[test]
fn loading_a_map_over_tcp_doesnt_end_the_match() {
    // Trackmania, 2026-11-08 13:44: a 49 MB map, then 16 seconds
    // without UDP while it loaded
    let mut sim = Sim::new(&[7]);
    let a = sim.run(4, &[(7, 190, 90, 120)]);
    assert_eq!(starts(&a).len(), 1, "{a:?}");
    sim.tcp_rx = 49_000_000;
    let mut a = sim.run(1, &[(7, 0, 0, 0)]);
    sim.tcp_rx = 0;
    a.extend(sim.run(16, &[(7, 0, 0, 0)]));
    a.extend(sim.run(2, &[(7, 1, 11, 80)]));
    a.extend(sim.run(30, &[(7, 190, 90, 120)]));
    assert!(!has(&a, |x| matches!(x, Action::End { .. })), "{a:?}");
    // gone for good, with nothing loading: over after the usual wait
    let a = sim.run(40, &[(7, 0, 0, 0)]);
    assert!(has(&a, |x| matches!(x, Action::End { .. })), "{a:?}");
}

#[test]
fn menus_with_ping_bursts_still_end_the_match() {
    let mut sim = Sim::new(&[7]);
    let a = sim.run(4, &[(7, 64, 128, 120)]);
    assert_eq!(starts(&a).len(), 1, "{a:?}");
    // Between matches: a packet a second, and every fourth second a
    // burst of relay pings well over the quiet threshold. Judged on the
    // latest second alone, every burst restarted the quiet countdown and
    // two matches merged into one.
    let mut ended = None;
    for i in 0..40 {
        let r = if i % 4 == 3 {
            (7, 25, 25, 80)
        } else {
            (7, 1, 1, 80)
        };
        if sim
            .step(&[r])
            .iter()
            .any(|x| matches!(x, Action::End { .. }))
        {
            ended = Some(i);
            break;
        }
    }
    let at = ended.expect("the match never ended");
    assert!(at <= 15 + 6, "ended after {at}s");
    // the next match is a new one, once its traffic fills the history
    let a = sim.run(12, &[(7, 64, 128, 120)]);
    assert_eq!(starts(&a).len(), 1, "{a:?}");
}

#[test]
fn a_ping_burst_across_two_readings_still_ends_the_match() {
    // The same menu, but each burst falls across two readings (where a
    // burst lands against bpfrag's clock is chance). Three of any five
    // readings can then hold traffic, which put the median over the
    // threshold once a cycle and started the countdown again every time.
    for (first, second) in [(20, 20), (30, 10), (10, 30)] {
        let mut sim = Sim::new(&[7]);
        let a = sim.run(4, &[(7, 64, 128, 120)]);
        assert_eq!(starts(&a).len(), 1, "{a:?}");
        let ended = (0..60).find(|i| {
            let r = match i % 4 {
                2 => (7, first, first, 80),
                3 => (7, second, second, 80),
                _ => (7, 1, 1, 80),
            };
            has(&sim.step(&[r]), |x| matches!(x, Action::End { .. }))
        });
        let at = ended.unwrap_or_else(|| panic!("{first}/{second}: the match never ended"));
        // two quiet readings in four: twice as long as an unbroken quiet
        assert!(at <= 2 * 15 + 8, "{first}/{second}: ended after {at}s");
    }
}

#[test]
fn play_resuming_after_a_quiet_spell_starts_the_countdown_again() {
    let mut sim = Sim::new(&[7]);
    sim.run(4, &[(7, 64, 128, 120)]);
    // ten quiet seconds, play for five, ten quiet again: neither spell
    // reaches the 15 s that end a match, and they don't add up
    let mut a = sim.run(10, &[(7, 1, 1, 80)]);
    a.extend(sim.run(5, &[(7, 64, 128, 120)]));
    a.extend(sim.run(10, &[(7, 1, 1, 80)]));
    assert!(!has(&a, |x| matches!(x, Action::End { .. })), "{a:?}");
    let a = sim.run(8, &[(7, 1, 1, 80)]);
    assert!(has(&a, |x| matches!(x, Action::End { .. })), "{a:?}");
}

#[test]
fn a_dip_mid_match_is_not_the_end() {
    let mut sim = Sim::new(&[7]);
    sim.run(4, &[(7, 64, 128, 120)]);
    assert!(sim.det.session().is_some());
    // dead and waiting to respawn: Deadlock still gets ~40-55 pkt/s
    let a = sim.run(60, &[(7, 32, 45, 120)]);
    assert!(!a.iter().any(|x| matches!(x, Action::End { .. })), "{a:?}");
    assert!(sim.det.session().is_some());
}

#[test]
fn discord_like_traffic_is_ignored_not_started() {
    let mut sim = Sim::new(&[]);
    // 50 pkt/s each way Opus: steady, small, bidirectional
    let a = sim.run(5, &[(99, 50, 50, 120)]);
    assert!(starts(&a).is_empty());
    let ign: Vec<_> = a
        .iter()
        .filter(|x| matches!(x, Action::Ignored { .. }))
        .collect();
    assert_eq!(ign.len(), 1, "should be logged once: {a:?}");
}

#[test]
fn bulk_and_one_way_traffic_never_qualify() {
    let mut sim = Sim::new(&[1, 2, 3]);
    // QUIC download: big packets
    // mDNS-ish: one way only
    // bursty: on/off
    let mut acts = Vec::new();
    for i in 0..10 {
        let burst = if i % 2 == 0 { 400 } else { 0 };
        acts.extend(sim.step(&[(1, 40, 900, 1350), (2, 60, 0, 90), (3, burst, burst, 200)]));
    }
    assert!(starts(&acts).is_empty(), "{acts:?}");
}

#[test]
fn tier_moves_up_with_confidence_and_dwell_and_never_down() {
    let mut sim = Sim::new(&[5]);
    let a = sim.run(4, &[(5, 50, 50, 150)]);
    assert_eq!(starts(&a)[0].tier, Tier::Competitive);
    // jump to 300 pps: should need dwell (5s) + 3 confident windows
    let a = sim.run(2, &[(5, 150, 150, 150)]);
    assert!(!a.iter().any(|x| matches!(x, Action::Retier { .. })));
    let a = sim.run(6, &[(5, 150, 150, 150)]);
    assert!(
        a.iter().any(|x| matches!(
            x,
            Action::Retier {
                from: Tier::Competitive,
                to: Tier::Intense
            }
        )),
        "{a:?}"
    );
    // drop to 100, then 30 pps: tiers only go up within a match
    let a = sim.run(20, &[(5, 50, 50, 150)]);
    let a2 = sim.run(20, &[(5, 15, 15, 150)]);
    assert!(
        !a.iter()
            .chain(&a2)
            .any(|x| matches!(x, Action::Retier { .. })),
        "{a:?} {a2:?}"
    );
    assert_eq!(sim.det.session().unwrap().tier, Tier::Intense);
}

#[test]
fn split_updates_dont_raise_the_tier() {
    // Deadlock in a fight: 64 updates a second each way, the server's
    // split into 2 or 3 packets
    let mut sim = Sim::new(&[5]);
    let a = sim.run(4, &[(5, 64, 64, 150)]);
    assert_eq!(starts(&a)[0].tier, Tier::Competitive);
    let a = sim.run(30, &[(5, 64, 170, 900)]);
    assert!(!has(&a, |x| matches!(x, Action::Retier { .. })), "{a:?}");
    // a 128-tick server is INTENSE
    let mut sim = Sim::new(&[6]);
    let a = sim.run(4, &[(6, 128, 128, 150)]);
    assert_eq!(starts(&a)[0].tier, Tier::Intense);
}

#[test]
fn a_short_menu_between_games_splits_them() {
    let mut sim = Sim::with_paths(&[7]);
    sim.arrivals = outside(64.0);
    let a = sim.run(8, &[(7, 64, 64, 200)]);
    assert_eq!(starts(&a).len(), 1);
    sim.run(60, &[(7, 64, 64, 200)]);
    // 12 seconds in the menu, then the next game
    sim.arrivals = local(128.0);
    let a = sim.run(12, &[(7, 128, 128, 220)]);
    assert!(has(&a, |x| matches!(x, Action::End { .. })), "{a:?}");
    sim.arrivals = outside(64.0);
    let a = sim.run(4, &[(7, 64, 64, 200)]);
    assert_eq!(starts(&a).len(), 1, "{a:?}");
}

#[test]
fn a_spare_relays_pings_dont_hold_the_match_open() {
    // Deadlock, 2026-11-11 12:59: it moved relays twice, and the relay it
    // had left kept pinging it, 5 to 10 packets a second on top of the
    // server, through the match and after it. On the end screen, with the
    // game back on its own server over loopback, those pings alone kept
    // the traffic from outside at about the threshold: the match didn't
    // end, and the loopback traffic raised its tier.
    let mut sim = Sim::with_paths(&[7]);
    sim.arrivals = outside(64.0 + 9.0);
    sim.others = 9.0;
    let a = sim.run(8, &[(7, 73, 73, 200)]);
    assert_eq!(starts(&a).len(), 1, "{a:?}");
    sim.run(60, &[(7, 73, 73, 200)]);
    // the end screen: the server stops, the spare relay doesn't
    sim.arrivals = Arrivals {
        outside_pps: 11.0,
        local_pps: 128.0,
    };
    sim.others = 11.0;
    let a = sim.run(15, &[(7, 139, 139, 220)]);
    assert!(!has(&a, |x| matches!(x, Action::Retier { .. })), "{a:?}");
    assert!(has(&a, |x| matches!(x, Action::End { .. })), "{a:?}");
}

#[test]
fn relay_pings_dont_raise_the_tier() {
    // every couple of minutes the client pings a couple of dozen
    // relays: 100 more packets a second for two seconds
    let mut sim = Sim::new(&[5]);
    let a = sim.run(4, &[(5, 64, 64, 150)]);
    assert_eq!(starts(&a)[0].tier, Tier::Competitive);
    let mut a = sim.run(10, &[(5, 64, 130, 300)]);
    a.extend(sim.run(2, &[(5, 164, 220, 120)]));
    a.extend(sim.run(10, &[(5, 64, 130, 300)]));
    assert!(!has(&a, |x| matches!(x, Action::Retier { .. })), "{a:?}");
}

#[test]
fn relay_pings_as_a_game_launches_arent_a_match() {
    // Deadlock, 2026-11-06 11:18: just launched, it pinged Steam's
    // relays for a few seconds before its menu server was up
    let mut sim = Sim::with_paths(&[5]);
    sim.procs.started.insert(5, 0.0);
    sim.arrivals = Arrivals {
        outside_pps: 13.0,
        local_pps: 0.0,
    };
    let a = sim.run(6, &[(5, 12, 13, 120)]);
    assert!(starts(&a).is_empty(), "{a:?}");
    // then the menu, over loopback
    sim.arrivals = local(128.0);
    let a = sim.run(20, &[(5, 128, 128, 200)]);
    assert!(starts(&a).is_empty(), "{a:?}");
    // a real match, minutes later: starts as usual
    sim.run(60, &[(5, 128, 128, 200)]);
    sim.arrivals = outside(64.0);
    let a = sim.run(3, &[(5, 64, 140, 150)]);
    assert_eq!(starts(&a).len(), 1, "{a:?}");
}

#[test]
fn pinging_relays_for_half_a_minute_doesnt_raise_the_tier() {
    // Deadlock, 2026-11-06: in a 64-tick match, the client pinged a
    // handful of relays for half a minute, 80 packets a second out
    // instead of 64, and each answered
    let mut sim = Sim::new(&[5]);
    let a = sim.run(4, &[(5, 64, 140, 150)]);
    assert_eq!(starts(&a)[0].tier, Tier::Competitive);
    sim.run(10, &[(5, 64, 140, 150)]);
    sim.others = 18.0;
    let mut a = sim.run(40, &[(5, 82, 210, 150)]);
    sim.others = 0.0;
    a.extend(sim.run(10, &[(5, 64, 140, 150)]));
    assert!(!has(&a, |x| matches!(x, Action::Retier { .. })), "{a:?}");
    // the same rates with nothing to tell the server apart: INTENSE,
    // as before
    let mut sim = Sim::new(&[6]);
    sim.run(14, &[(6, 64, 140, 150)]);
    let a = sim.run(40, &[(6, 82, 210, 150)]);
    assert!(has(&a, |x| matches!(x, Action::Retier { .. })), "{a:?}");
}

#[test]
fn exit_event_ends_immediately() {
    let mut sim = Sim::new(&[8]);
    sim.run(4, &[(8, 64, 64, 100)]);
    assert!(sim.det.session().is_some());
    assert!(matches!(sim.det.on_exit(8), Some(Action::End { .. })));
    assert!(sim.det.on_exit(8).is_none());
}

#[test]
fn busiest_game_wins_and_other_noise_does_not_matter() {
    let mut sim = Sim::new(&[10, 11]);
    let a = sim.run(
        4,
        &[(10, 30, 30, 100), (11, 64, 64, 100), (12, 5000, 5000, 1300)],
    );
    let s = starts(&a);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].tgid, 11);
}

#[test]
fn reused_pid_starts_fresh() {
    // pid 77: a busy non-game (rejected), then it exits and a game that
    // happens to get the same pid starts at a casual 60 pkt/s.
    let mut sim = Sim::new(&[]);
    let a = sim.run(5, &[(77, 100, 100, 150)]);
    assert!(a.iter().any(|x| matches!(x, Action::Ignored { .. })));
    sim.exit(77);
    sim.run(1, &[]);
    sim.procs.games.push(77);
    // baseline tick + 3 steady windows; no stale history or ignore entry
    assert!(starts(&sim.run(3, &[(77, 30, 30, 150)])).is_empty());
    let a = sim.run(1, &[(77, 30, 30, 150)]);
    let s = starts(&a);
    assert_eq!(s.len(), 1, "{a:?}");
    assert_eq!(
        s[0].tier,
        Tier::Casual,
        "must not inherit the old process's 200 pkt/s"
    );
    assert!((s[0].pps - 60.0).abs() < 1.0, "{}", s[0].pps);
}

#[test]
fn pid_reused_within_one_tick_resets_via_counter_regression() {
    let mut sim = Sim::new(&[]);
    sim.run(5, &[(88, 100, 100, 150)]);
    // entry deleted and recreated between two reads: counters go backwards
    sim.counters.insert(
        88,
        Sample {
            tgid: 88,
            tx_pkts: 3,
            rx_pkts: 3,
            tx_bytes: 300,
            rx_bytes: 300,
            ifindex: 0,
            ..Default::default()
        },
    );
    sim.procs.games.push(88);
    sim.now += 1.0;
    let samples: Vec<Sample> = sim.counters.values().copied().collect();
    assert!(
        sim.det
            .tick(sim.now, 1.0, &samples, &mut sim.procs)
            .is_empty()
    );
    assert!(starts(&sim.run(2, &[(88, 30, 30, 150)])).is_empty());
    let s = sim.run(1, &[(88, 30, 30, 150)]);
    assert_eq!(starts(&s).len(), 1, "{s:?}");
    assert_eq!(starts(&s)[0].tier, Tier::Casual);
}

#[test]
fn pinned_tier_sticks() {
    let mut sim = Sim::new(&[3]);
    sim.det = Detector::new(Detect {
        pin_tier: Some(Tier::Intense),
        ..Detect::default()
    });
    let a = sim.run(4, &[(3, 30, 30, 100)]);
    assert_eq!(starts(&a)[0].tier, Tier::Intense);
    let a = sim.run(10, &[(3, 15, 15, 100)]);
    assert!(!a.iter().any(|x| matches!(x, Action::Retier { .. })));
}

#[test]
fn hysteresis_matches_original_thresholds() {
    let cfg = Detect::default();
    assert_eq!(
        thresholds(&cfg),
        Thresholds {
            competitive_up: 85.0,
            competitive_down: 55.0,
            intense_up: 155.0,
            intense_down: 125.0,
        }
    );
    use Tier::*;
    for (current, pps, want) in [
        (Casual, 84.0, Casual),
        (Casual, 85.0, Competitive),
        (Casual, 155.0, Intense),
        (Competitive, 60.0, Competitive),
        (Competitive, 55.0, Casual),
        (Competitive, 155.0, Intense),
        (Intense, 130.0, Intense),
        (Intense, 125.0, Competitive),
    ] {
        assert_eq!(tier_for(&cfg, current, pps), want, "{current} @ {pps}");
    }
}

#[test]
fn end_carries_the_final_session_and_its_peak() {
    let mut sim = Sim::new(&[9]);
    sim.run(4, &[(9, 50, 50, 150)]);
    sim.run(12, &[(9, 150, 150, 150)]);
    let a = sim.run(1, &[(9, 50, 50, 150)]);
    assert!(a.is_empty(), "{a:?}");
    sim.procs.dead.push(9);
    sim.exit(9);
    let a = sim.run(1, &[]);
    match &a[..] {
        [Action::End { session, reason }] => {
            assert_eq!(session.tgid, 9);
            assert_eq!(session.peak_tier, Tier::Intense);
            assert!(session.peak_pps >= 290.0, "{}", session.peak_pps);
            assert_eq!(reason, "game exited");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn excluded_processes_are_flagged() {
    let mut sim = Sim::new(&[]);
    sim.procs.excluded.push(99);
    let a = sim.run(5, &[(99, 50, 50, 120), (98, 50, 50, 120)]);
    let flags: Vec<(u32, bool)> = a
        .iter()
        .filter_map(|x| match x {
            Action::Ignored { tgid, excluded, .. } => Some((*tgid, *excluded)),
            _ => None,
        })
        .collect();
    assert!(
        flags.contains(&(99, true)) && flags.contains(&(98, false)),
        "{flags:?}"
    );
}
fn local(pps: f64) -> Arrivals {
    Arrivals {
        outside_pps: 0.0,
        local_pps: pps,
    }
}

fn outside(pps: f64) -> Arrivals {
    Arrivals {
        outside_pps: pps,
        local_pps: 0.0,
    }
}

fn has(a: &[Action], f: impl Fn(&Action) -> bool) -> bool {
    a.iter().any(f)
}

#[test]
fn a_game_talking_to_itself_isnt_a_match() {
    // Deadlock's menu: 128 a second each way, all over loopback
    let mut sim = Sim::with_paths(&[7]);
    sim.arrivals = local(128.0);
    let a = sim.run(10, &[(7, 128, 128, 220)]);
    assert!(
        has(&a, |x| matches!(x, Action::Watch { tgid: 7, .. })),
        "{a:?}"
    );
    assert!(
        has(&a, |x| matches!(x, Action::Local { tgid: 7, .. })),
        "{a:?}"
    );
    assert!(starts(&a).is_empty(), "{a:?}");
    let a = sim.run(60, &[(7, 128, 128, 220)]);
    assert!(a.is_empty(), "nothing more while it stays local: {a:?}");
    assert_eq!(sim.det.watched(), Some((7, "game7", true)));
    assert!(sim.det.session().is_none());
}

#[test]
fn traffic_from_outside_starts_the_match_and_the_menu_ends_it() {
    let mut sim = Sim::with_paths(&[7]);
    sim.arrivals = local(128.0);
    sim.run(10, &[(7, 128, 128, 220)]);
    // a game on a server: 64 each way, from outside
    sim.arrivals = outside(64.0);
    let a = sim.run(3, &[(7, 64, 64, 200)]);
    assert_eq!(starts(&a).len(), 1, "{a:?}");
    // its tier comes from the game, not the menu before it
    assert_eq!(starts(&a)[0].tier, Tier::Competitive, "{a:?}");
    assert!(sim.det.watched().is_none());
    // a dip mid-game is still outside traffic
    sim.arrivals = outside(40.0);
    let a = sim.run(40, &[(7, 32, 40, 200)]);
    assert!(!has(&a, |x| matches!(x, Action::End { .. })), "{a:?}");
    // back to the menu: over in about QUIET_WINDOWS + linger seconds,
    // and the game is watched again
    sim.arrivals = local(128.0);
    let a = sim.run(25, &[(7, 128, 128, 220)]);
    let end = a.iter().position(|x| matches!(x, Action::End { .. }));
    let watch = a.iter().position(|x| matches!(x, Action::Watch { .. }));
    match (end, watch) {
        (Some(e), Some(w)) => assert!(e < w, "end, then watch: {a:?}"),
        _ => panic!("{a:?}"),
    }
    assert!(has(
        &a,
        |x| matches!(x, Action::End { reason, .. } if reason.contains("stayed on this machine"))
    ));
    assert_eq!(sim.det.watched(), Some((7, "game7", true)));
    // the next game is a match of its own
    sim.arrivals = outside(64.0);
    let a = sim.run(4, &[(7, 64, 64, 200)]);
    assert_eq!(starts(&a).len(), 1, "{a:?}");
}

#[test]
fn a_game_in_its_menu_doesnt_stop_another_being_tuned() {
    let mut sim = Sim::with_paths(&[7, 8]);
    // game 7 sits in its menu, confirmed as local
    sim.arrivals = local(128.0);
    let a = sim.run(10, &[(7, 128, 128, 220)]);
    assert!(
        has(&a, |x| matches!(x, Action::Local { tgid: 7, .. })),
        "{a:?}"
    );
    assert_eq!(sim.det.watched(), Some((7, "game7", true)));
    // game 8 starts talking to a server while 7 is still in its menu
    // (the meter follows whichever game is watched: still local while
    // 8 is picked up, outside once it's the one being measured)
    let both = [(7, 128, 128, 220), (8, 64, 64, 200)];
    let mut a = sim.run(4, &both);
    sim.arrivals = outside(64.0);
    a.extend(sim.run(6, &both));
    let unwatch = a
        .iter()
        .position(|x| matches!(x, Action::Unwatch { tgid: 7 }));
    let watch = a
        .iter()
        .position(|x| matches!(x, Action::Watch { tgid: 8, .. }));
    match (unwatch, watch) {
        (Some(u), Some(w)) => assert!(u < w, "7 is let go, then 8 watched: {a:?}"),
        _ => panic!("{a:?}"),
    }
    assert!(starts(&a).iter().any(|s| s.tgid == 8), "{a:?}");
    // and 7 isn't taken straight back while 8 plays
    let a = sim.run(30, &[(7, 128, 128, 220), (8, 64, 64, 200)]);
    assert!(
        !has(&a, |x| matches!(x, Action::Watch { tgid: 7, .. })),
        "{a:?}"
    );
}

#[test]
fn a_match_knows_when_its_traffic_began_and_stopped() {
    let mut sim = Sim::with_paths(&[7]);
    sim.arrivals = local(128.0);
    sim.run(10, &[(7, 128, 128, 220)]);
    // outside traffic from the window ending at 11
    sim.arrivals = outside(64.0);
    let a = sim.run(3, &[(7, 64, 64, 200)]);
    let s = starts(&a)[0];
    assert_eq!(s.began, 10.0, "{s:?}");
    assert!(s.began < sim.now - 1.0);
    sim.run(20, &[(7, 64, 64, 200)]);
    let last = sim.now;
    sim.arrivals = local(128.0);
    let a = sim.run(25, &[(7, 128, 128, 220)]);
    let ended = a
        .iter()
        .find_map(|x| match x {
            Action::End { session, .. } => Some(session.clone()),
            _ => None,
        })
        .expect("ended");
    // the end is reported well after the outside traffic stopped,
    // but knows when that was
    assert_eq!(ended.last_seen, last, "{ended:?}");
    assert_eq!(ended.began, 10.0);

    // without the meter: the steady traffic's start
    let mut sim = Sim::new(&[7]);
    let a = sim.run(6, &[(7, 64, 64, 200)]);
    let s = starts(&a)[0];
    assert!(s.began < sim.now - 1.0, "{s:?}");
    sim.run(5, &[(7, 64, 64, 200)]);
    let last = sim.now;
    let a = sim.run(30, &[]);
    assert!(
        has(
            &a,
            |x| matches!(x, Action::End { session, .. } if session.last_seen == last)
        ),
        "{a:?}"
    );
}

#[test]
fn outside_traffic_in_two_windows_starts_a_match() {
    let mut sim = Sim::with_paths(&[7]);
    sim.arrivals = outside(64.0);
    let a = sim.run(4, &[(7, 64, 64, 200)]);
    assert!(has(&a, |x| matches!(x, Action::Watch { .. })), "{a:?}");
    // candidate after the baseline and 3 steady windows, then two more
    // windows to see the traffic comes from outside
    assert!(starts(&a).is_empty(), "{a:?}");
    let a = sim.run(1, &[(7, 64, 64, 200)]);
    assert!(starts(&a).is_empty(), "one window isn't enough: {a:?}");
    let a = sim.run(1, &[(7, 64, 64, 200)]);
    assert_eq!(starts(&a).len(), 1, "{a:?}");
}

#[test]
fn the_menu_at_the_end_doesnt_change_the_tier() {
    let mut sim = Sim::with_paths(&[7]);
    sim.arrivals = outside(64.0);
    let a = sim.run(8, &[(7, 32, 32, 200)]);
    assert_eq!(starts(&a)[0].tier, Tier::Casual, "{a:?}");
    // back in the menu, 128 a second each way over loopback: as a rate
    // that's INTENSE, but it isn't the match
    sim.arrivals = local(128.0);
    let a = sim.run(25, &[(7, 128, 128, 220)]);
    assert!(has(&a, |x| matches!(x, Action::End { .. })), "{a:?}");
    assert!(!has(&a, |x| matches!(x, Action::Retier { .. })), "{a:?}");
}

#[test]
fn relay_pings_while_the_menu_runs_arent_a_match() {
    // the game starting: its menu over loopback, and for a few seconds
    // pings to a few relays from outside
    let mut sim = Sim::with_paths(&[7]);
    sim.arrivals = local(128.0);
    sim.run(4, &[(7, 128, 128, 220)]);
    sim.arrivals = Arrivals {
        outside_pps: 40.0,
        local_pps: 128.0,
    };
    let a = sim.run(4, &[(7, 170, 170, 220)]);
    assert!(starts(&a).is_empty(), "{a:?}");
    // then a match: the menu server goes quiet
    sim.arrivals = outside(64.0);
    let a = sim.run(3, &[(7, 64, 64, 200)]);
    assert_eq!(starts(&a).len(), 1, "{a:?}");
}

#[test]
fn one_window_from_outside_in_a_menu_isnt_a_match() {
    // Deadlock starting: its menu over loopback, and for one second
    // a little traffic from outside (2026-11-02, twice)
    let mut sim = Sim::with_paths(&[7]);
    sim.arrivals = local(128.0);
    let a = sim.run(4, &[(7, 128, 128, 220)]);
    assert!(has(&a, |x| matches!(x, Action::Watch { .. })), "{a:?}");
    sim.arrivals = Arrivals {
        outside_pps: 30.0,
        local_pps: 128.0,
    };
    let a = sim.run(1, &[(7, 128, 128, 220)]);
    assert!(starts(&a).is_empty(), "{a:?}");
    sim.arrivals = local(128.0);
    let a = sim.run(30, &[(7, 128, 128, 220)]);
    assert!(starts(&a).is_empty(), "{a:?}");
    assert!(has(&a, |x| matches!(x, Action::Local { .. })), "{a:?}");
}

#[test]
fn a_game_the_meter_cant_see_still_starts() {
    // nothing on any interface the meter is on (a path it isn't on, or
    // the meter couldn't attach): the rate alone decides, as before
    let mut sim = Sim::with_paths(&[7]);
    let a = sim.run(4 + UNSEEN_WINDOWS as usize, &[(7, 64, 64, 200)]);
    assert_eq!(starts(&a).len(), 1, "{a:?}");
    assert!(!has(&a, |x| matches!(x, Action::Local { .. })));
}

#[test]
fn a_watched_game_that_exits_or_goes_quiet_is_let_go() {
    let mut sim = Sim::with_paths(&[7]);
    sim.arrivals = local(128.0);
    sim.run(10, &[(7, 128, 128, 220)]);
    assert_eq!(sim.det.on_exit(7), Some(Action::Unwatch { tgid: 7 }));
    assert!(sim.det.watched().is_none());

    let mut sim = Sim::with_paths(&[8]);
    sim.arrivals = local(128.0);
    sim.run(10, &[(8, 128, 128, 220)]);
    // its menu goes quiet: let it go after QUIET_WINDOWS + linger
    sim.arrivals = local(0.0);
    let a = sim.run(25, &[(8, 1, 1, 80)]);
    assert!(
        has(&a, |x| matches!(x, Action::Unwatch { tgid: 8 })),
        "{a:?}"
    );
    assert!(sim.det.watched().is_none());
}
