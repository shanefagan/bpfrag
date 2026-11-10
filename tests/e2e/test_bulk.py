# SPDX-License-Identifier: MIT
"""Bulk transfers during a match: demoted, narrowly, and released."""

import pytest

from rig import SERVER, dscps

BULK = "[bulk]\nenabled = true\nmin_mbps = 2\nsecs = 2\nrelease_secs = 3\n"


def from_here(port):
    """The outgoing side of a TCP transfer from a local port."""
    return f"tcp and src 10.99.0.1 and src port {port}"


def to_here(port):
    """Its incoming side."""
    return f"tcp and src {SERVER} and dst port {port}"


@pytest.fixture
def bulk_config(rig):
    return rig.config("bulk", append=BULK)


def test_a_download_is_demoted_and_a_stream_isnt(rig, bulk_config):
    """"steam" downloads and "obs" uploads, both well over the rate. Only
    the download is bulk: OBS is on the never list, since demoting a
    stream would demote the player."""
    daemon = rig.daemon(bulk_config)
    game = rig.game(64)
    daemon.wait_for_match()
    steam = rig.app("steam", "bulk.py", "down", 10, 40100)
    rig.app("obs", "bulk.py", "up", 10, 40200)
    daemon.wait_for("Bulk transfer during the match: steam")

    # 1 is LE ("lower effort"), 0 is unmarked, 32 is the game's CS4
    assert dscps(rig.capture(from_here(40100))) == {1}
    assert dscps(rig.capture(from_here(40200))) == {0}
    # what a desktop CAKE would see, after the redirect to its IFB
    assert dscps(rig.capture(to_here(40100), where="ingress")) == {1}
    assert dscps(rig.capture(to_here(40200), where="ingress")) == {0}
    assert 32 in dscps(rig.game_packets(40)), "the game keeps CS4 alongside"
    assert not daemon.logged("Bulk transfer during the match: obs")
    assert any(
        "steam" in line and "marked LE" in line
        for line in daemon.monitor().splitlines()
        if "bulk:" in line
    ), daemon.monitor()

    steam.exit()
    daemon.wait_for("steam is no longer moving bulk data")
    rig.app("steam", "bulk.py", "up", 0.5, 40101)
    assert 1 not in dscps(rig.capture(from_here(40101))), "still demoting after release"

    game.exit()
    health = daemon.health()["line"]
    assert "; bulk: " in health and "steam" in health and "marked LE" in health, health


def test_a_dry_run_reports_bulk_and_marks_nothing(rig, bulk_config):
    daemon = rig.daemon(bulk_config, "--dry-run")
    rig.game(64)
    daemon.wait_for_match()
    rig.app("steam", "bulk.py", "down", 10, 40102)
    daemon.wait_for(r"Bulk transfer during the match: steam.*dry run: would mark LE")

    assert 1 not in dscps(rig.capture(from_here(40102)))
    assert 1 not in dscps(rig.capture(to_here(40102), where="ingress"))
