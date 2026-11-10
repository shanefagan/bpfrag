# SPDX-License-Identifier: MIT
"""What the match's health line counts."""

import time


def test_a_hiccup_is_a_stall_and_a_lobby_isnt(rig, match):
    """Two hiccups (the game frozen for 300 ms), then a lobby: a few seconds
    of one packet a second, the way games idle between rounds."""
    daemon, game = match
    time.sleep(4)  # some play before the first hiccup, for the usual rate
    for _ in range(2):
        game.freeze(0.3)
        time.sleep(2)
    game.set_rate(1)
    time.sleep(4)
    game.set_rate(64)
    time.sleep(4)
    game.exit()

    health = daemon.health()
    assert health["stalls"] == 2, health["line"]
    assert 250 <= health["longest_ms"] < 450, "the hiccup, not a keepalive: " + health["line"]
    # the fake game stops sending for each hiccup too, and keeps a
    # keepalive a second in the lobby: the same two going out
    assert health["send_stalls"] == 2, health["line"]
    assert 250 <= health["send_longest_ms"] < 450, health["line"]
