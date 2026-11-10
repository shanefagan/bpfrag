# SPDX-License-Identifier: MIT
"""Putting settings back, and leaving other people's alone."""

from rig import dscps, set_sysctl, sysctl


def test_a_value_someone_else_changed_is_left_alone(rig, match):
    daemon, game = match
    set_sysctl("net.core.busy_poll", 99)
    try:
        # a tier change re-applies the profile (intense wants busy_poll=75)
        game.set_rate(150)
        daemon.wait_for("COMPETITIVE -> INTENSE")

        assert sysctl("net.core.busy_poll") == "99", "the tier change overwrote it"
        assert sysctl("net.core.busy_read") == "75", "the rest of the profile applies"
        assert daemon.logged(
            r"net\.core\.busy_poll was changed by someone else during the match \(now 99\)"
        )
        game.exit()
        daemon.wait_for_end()
        assert sysctl("net.core.busy_poll") == "99", "restore overwrote it"
    finally:
        set_sysctl("net.core.busy_poll", rig.baseline["net.core.busy_poll"])


def test_bpftunes_sysctls_are_left_to_it(rig, daemon):
    rig.run_bpftune()
    before = sysctl("net.core.rmem_max")
    rig.game(64)
    daemon.wait_for_match()

    assert sysctl("net.core.rmem_max") == before, "wrote a sysctl bpftune manages"
    assert sysctl("net.core.busy_poll") == "50", "the others still apply"


def test_restore_after_kill_9(rig, match):
    daemon, _game = match
    daemon.kill()

    # the game keeps running: its packets must now leave unmarked, because
    # the marker was attached as a link that dies with the process
    assert dscps(rig.game_packets(30)) == {0}
    assert rig.changed(), "nothing was left changed: the test proves nothing"
    rig.restore()
    assert not rig.changed()
