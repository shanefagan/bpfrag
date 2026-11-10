# SPDX-License-Identifier: MIT
"""IPv6, and the game's traffic moving to another interface."""

import pytest

from rig import GAME_PORT, SERVER, SERVER_V6, dscps, run


def test_ipv6_game_packets_are_marked(rig, daemon):
    if not rig.have_v6:
        pytest.skip("IPv6 is disabled on this host (the selftest covers the rewrite)")
    rig.game(64, env={"DEST": SERVER_V6})
    daemon.wait_for_match()

    packets = rig.capture(f"ip6 and udp and dst port {GAME_PORT}", 100)
    assert dscps(packets) == {32}, packets


def test_marking_follows_the_game_to_a_new_network_path(rig):
    """No fixed interface list: bpfrag uses the default-route interfaces.
    A default route through the test network appears mid-match (think of
    docking, or a VPN coming up), and bpfrag starts marking there."""
    config = rig.config(
        "auto", edit=lambda t: t.replace('[dscp]\ninterfaces = ["bpfrag0"]\n', "")
    )
    daemon = rig.daemon(config)
    rig.game(64)
    # the meter starts on the default-route interface, which doesn't carry
    # the game here, so it sees the game nowhere and the rate alone decides
    daemon.wait_for_match(timeout=30)

    route = ("default", "via", SERVER, "dev", "bpfrag0", "metric", "4242")
    run("ip", "route", "add", *route)
    try:
        daemon.wait_for("network path changed")
        daemon.wait_for("game traffic leaves via bpfrag0")
        assert 32 in dscps(rig.game_packets(60))
    finally:
        run("ip", "route", "del", *route, check=False)
