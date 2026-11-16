# SPDX-License-Identifier: MIT
"""Games that talk TCP (Path of Exile 2, MMOs): tuned like a match while
their traffic looks like a multiplayer game's, and only then."""

import csv
import re
import subprocess
import sys
import time

from rig import REPO, SERVER, dscps, run


def test_a_tcp_game_is_tuned_and_marked_until_it_exits(rig):
    rig.clear_timelines()
    daemon = rig.daemon(rig.config("tcp-timeline", append="[capture]\ntimeline = true\n"))
    # 20 small messages a second each way, to a server elsewhere
    game = rig.tcp_game(20)
    daemon.wait_for(
        rf"Match detected: fakemmo \(pid {game.pid}\) talks TCP like a multiplayer game, "
        r"~2\d sends/s and ~2\d receives/s -> COMPETITIVE until it stops \[Steam app 4243\]",
        timeout=30,
    )
    daemon.wait_for_profile("COMPETITIVE")
    assert rig.changed(), "the competitive profile changed nothing"
    packets = rig.capture(f"tcp and dst port 27016 and src 10.99.0.1 and dst {SERVER}", 40)
    assert dscps(packets) == {32}, packets

    game.exit()
    daemon.wait_for(r"Match ended after .* \(game exited\); settings restored")
    health = daemon.health("fakemmo")
    assert re.search(
        r"; TCP for \d+s: typically 2\d sends/s and 2\d receives/s, 9\d and 9\d bytes each",
        health["line"],
    ), health["line"]
    # 20 messages a second: its receives are about 50 ms apart
    assert 45 <= health["p50_ms"] <= 55 and health["stalls"] == 0, health["line"]
    assert health["tcp_retransmits"] == 0, health["line"]
    rig.wait_restored()
    # the match's lines report the session; the observer doesn't again
    assert not daemon.logged("TCP game session"), daemon.log()
    # its timeline has its TCP a second, and no gaps
    [timeline] = rig.timelines("fakemmo")
    rows = timeline.read_text().splitlines()
    assert rows[0].startswith("# bpfrag ") and "] over TCP; experiment: none" in rows[0], rows[0]
    assert "match detected (COMPETITIVE)" in rows[2], rows[:3]
    assert "match ended (game exited)" in rows[-1], rows[-1]
    seconds = list(csv.DictReader(rows[1:]))
    play = seconds[len(seconds) // 2]
    assert 18 <= int(play["tcp_rx_msgs_s"]) <= 22 and play["tcp_retransmits"] == "0", play
    assert 18 <= int(play["gaps"]) <= 22, play
    # docs/scripts/matches.py reads a TCP game's match too
    out = subprocess.run(
        [sys.executable, REPO / "docs/scripts/matches.py", "-", "--min-minutes", "0"],
        input=daemon.log(),
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    row = next(csv.DictReader(out.splitlines()))
    assert (row["game"], row["transport"], row["tcp_retransmits"]) == ("fakemmo", "tcp", "0"), out
    assert 45 <= int(row["gap_p50_ms"]) <= 55, out


def test_a_tcp_games_hiccup_is_a_stall(rig, daemon):
    """The game frozen for 300 ms, twice: what it would see if a lost
    segment held up everything behind it."""
    game = rig.tcp_game(20)
    daemon.wait_for("Match detected: fakemmo", timeout=30)
    time.sleep(4)
    for _ in range(2):
        game.freeze(0.3)
        time.sleep(2)
    game.exit()
    health = daemon.health("fakemmo")
    assert health["stalls"] == 2, health["line"]
    assert 250 <= health["longest_ms"] < 450, health["line"]


def test_a_tcp_games_lost_segments_are_counted(rig, daemon):
    """Nothing comes back from the server for a second and a half (its
    route to the game is a black hole), so what the game sent goes
    unacknowledged: its connection sends those segments again, and the
    health line counts them."""
    game = rig.tcp_game(20)
    daemon.wait_for("Match detected: fakemmo", timeout=30)
    time.sleep(3)
    hole = ("ip", "netns", "exec", "bpfrag-srv", "ip", "route")
    run(*hole, "add", "blackhole", "10.99.0.1/32")
    try:
        time.sleep(1.5)
    finally:
        run(*hole, "del", "blackhole", "10.99.0.1/32")
    time.sleep(3)
    game.exit()
    health = daemon.health("fakemmo")
    assert health["tcp_retransmits"] >= 1, health["line"]


def test_a_tagged_tcp_game_is_still_tuned(rig, daemon):
    """BPFRAG_OBSERVE=1 adds logging; the game is detected and tuned as
    usual. 0.17.0 left tagged processes out of TCP game detection, and a
    tagged Path of Exile 2 was never tuned."""
    game = rig.tcp_game(20, env={"BPFRAG_OBSERVE": "1"})
    daemon.wait_for(
        rf"Match detected: fakemmo \(pid {game.pid}\) talks TCP like a multiplayer game",
        timeout=30,
    )
    daemon.wait_for(rf"Observing fakemmo \(pid {game.pid}\): TCP", timeout=30)
    game.exit()
    daemon.wait_for(r"Match ended after .* \(game exited\); settings restored")
    daemon.wait_for(rf"Observed fakemmo \(pid {game.pid}\): TCP for \d+s")


def test_a_tcp_game_barely_talking_isnt_tuned(rig, daemon):
    """Two messages a second each way: a launcher's or a store page's
    connection, not a game being played online. The scenario is time
    passing without a match, so this one waits."""
    game = rig.tcp_game(2)
    time.sleep(20)
    assert not daemon.logged("Match detected"), daemon.log()
    assert not rig.changed()

    game.exit()
    daemon.wait_for(
        r"TCP game session, not tuned \(it didn't look like a multiplayer game\): "
        r"fakemmo for 1\ds: typically 2 sends/s and 2 receives/s"
    )
