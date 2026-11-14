# SPDX-License-Identifier: MIT
"""Games that talk TCP (Path of Exile 2, MMOs): tuned like a match while
their traffic looks like a multiplayer game's, and only then."""

import time

from rig import SERVER, dscps


def test_a_tcp_game_is_tuned_and_marked_until_it_exits(rig, daemon):
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
    daemon.wait_for(
        r"fakemmo: TCP for \d+s: typically 2\d sends/s and 2\d receives/s, 9\d and 9\d bytes each"
    )
    rig.wait_restored()
    # the match's lines report the session; the observer doesn't again
    assert not daemon.logged("TCP game session"), daemon.log()


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
