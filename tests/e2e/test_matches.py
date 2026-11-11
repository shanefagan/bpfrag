# SPDX-License-Identifier: MIT
"""Where one match ends and the next begins."""

import time

from rig import SERVER2, sysctl


def test_menus_between_matches_make_two_matches(rig, match):
    """A match, then menus (a packet a second with a burst every fourth
    second, like relay pings), then another match, in one game process."""
    daemon, game = match
    time.sleep(3)
    # Where a burst lands against bpfrag's one-second readings is chance:
    # in one, or across two. Either way the menus end the match, within a
    # few cycles (linger_secs = 6 here, and each cycle has 2-3 quiet seconds).
    for _ in range(8):
        game.set_rate(1)
        time.sleep(3)
        game.set_rate(40)
        time.sleep(1)
        if daemon.logged("Match ended"):
            break
    else:
        raise AssertionError("the menus never ended the match:\n" + daemon.log()[-1500:])
    game.set_rate(64)
    # once the detector's history holds game traffic again, plus three
    # steady seconds: about 11 s, longer on a slow machine
    daemon.wait_for_match(count=2, timeout=40)
    time.sleep(3)
    game.exit()
    daemon.wait_for_end(count=2)

    assert len(daemon.lines("Match detected: fakeshooter")) == 2
    assert daemon.logged(r"Match ended after .*\(netcode quiet")
    daemon.health(count=2)  # a health line for each


def test_a_game_talking_to_itself_isnt_a_match(rig):
    """Deadlock's menu is a server of its own on 127.0.0.1. Here: the menu,
    a game on the real server, the menu again, and the next game."""
    rig.clear_timelines()
    config = rig.config("menu", append="[capture]\ntimeline = true\n")
    daemon = rig.daemon(config)
    game = rig.game(64, env={"PHASES": "local:12,remote:22,local:30,remote:30"})

    daemon.wait_for(rf"fakeshooter \(pid {game.pid}\): its traffic stays on this machine")
    assert not daemon.logged("Match detected")
    assert not rig.changed()
    assert (
        f"fakeshooter (pid {game.pid}) is running, its traffic staying on this machine"
        in daemon.monitor()
    )

    # 12 s in it moves to the real server
    daemon.wait_for_match(timeout=25)
    daemon.wait_for_profile("COMPETITIVE")
    assert sysctl("net.core.busy_poll") == "50", "the game's tier, not the menu's"

    # 34 s in, back to its own server
    daemon.wait_for(
        r"Match ended after \d+s \(its traffic stayed on this machine for 6s: "
        r"a menu or a local server\); settings restored",
        timeout=40,
    )
    rig.wait_restored()

    # 64 s in, the next game
    daemon.wait_for_match(count=2, timeout=45)
    game.exit()
    daemon.wait_for_end(count=2)
    assert len(rig.timelines()) == 2, "a timeline for each game"


def test_the_games_server_changing_is_followed(rig):
    """The same socket moves to a second server after ten seconds without
    a pause, like back-to-back games: one match, the change logged, and a
    timeline that names servers by letter, never by address."""
    rig.clear_timelines()
    config = rig.config("timeline", append="[capture]\ntimeline = true\nkeep = 3\n")
    daemon = rig.daemon(config)
    game = rig.game(64, env={"DEST2": SERVER2, "SWITCH_AFTER": "10"})

    daemon.wait_for(r"fakeshooter: receiving from server A:27015 on local port \d+ \(~\d+ pkt/s\)")
    daemon.wait_for(
        r"fakeshooter: server changed from A:27015 \(now ~\d+ pkt/s\) to B:27015 on local port \d+",
        timeout=25,
    )
    time.sleep(4)  # some rows on the new server
    assert not daemon.logged("Match ended"), "the change ended the match"
    game.exit()
    daemon.wait_for_end()
    daemon.stop()

    assert "the game's server changed once" in daemon.health()["line"]
    assert "10.99.0." not in daemon.log(), "server addresses in the log"

    (csv,) = rig.timelines()
    assert daemon.logged(f"fakeshooter: timeline written to {csv}")
    header, columns, *rows = csv.read_text().splitlines()
    assert f"fakeshooter (pid {game.pid}) [Steam app 4242]; experiment: none" in header
    names = columns.split(",")
    assert names[:5] == ["t", "unix", "tier", "udp_tx_pps", "udp_rx_pps"]
    rows = [dict(zip(names, r.split(","))) for r in rows]
    assert len(rows) >= 12, "about a row a second"

    on_b = [r for r in rows if r["server"] == "B:27015" and float(r["udp_tx_pps"] or 0) >= 50]
    assert on_b, "no rows on the new server at the game's rate"
    assert any(r["jitter_us"].isdigit() for r in rows)
    assert any(r["send_gap_max_ms"].isdigit() and int(r["send_gap_max_ms"]) < 100 for r in rows)
    events = " | ".join(r["events"] for r in rows)
    assert "server A:27015 -> B:27015" in events and "match ended (game exited)" in events
    assert "10.99." not in csv.read_text(), "addresses in the timeline"
