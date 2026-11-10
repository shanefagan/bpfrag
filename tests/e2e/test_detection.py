# SPDX-License-Identifier: MIT
"""What starts a match, what doesn't, and what a match changes."""

import json
import subprocess

from rig import bad_checksums, dscps, sysctl, wait_until


def test_bpf_selftest_passes(rig):
    """The packet vectors through the BPF programs, on this kernel."""
    out = rig.work / "selftest.log"
    with open(out, "w") as f:
        code = subprocess.run(
            [*rig.bpfrag, "-c", str(rig.config_path), "--selftest"],
            stdout=f,
            stderr=subprocess.STDOUT,
            check=False,
        ).returncode
    assert code == 0, out.read_text()


def test_other_programs_start_nothing(rig, daemon):
    """Voice chat, a browser and an unknown daemon all send steady UDP."""
    rig.app("Discord", "client.py", 50, 120)
    rig.app("firefox", "client.py", 300, 1300)
    rig.app("randomd", "client.py", 40, 100)
    # an unrecognised process is logged once at info: by then bpfrag has
    # looked at all three
    daemon.wait_for(r"Ignoring game-like UDP from randomd.*no game signals")

    assert not daemon.logged("Match detected")
    assert "not a game: deny list 'discord'" in daemon.monitor()
    # a deny-listed process is expected, so it stays out of the info log
    assert not daemon.logged("Ignoring game-like UDP from Discord")
    assert not rig.changed()


def test_a_game_is_detected_and_tuned(rig, match):
    daemon, _game = match
    assert daemon.logged(r"Match detected: fakeshooter.*COMPETITIVE")
    assert sysctl("net.core.busy_poll") == "50"
    # 64 echoes a second arrive about 15.6 ms apart
    line = wait_until(
        lambda: f"no gaps measured: {daemon.monitor()}",
        lambda: [l for l in daemon.monitor().splitlines() if "packet gaps half" in l],
    )[0]
    assert any(f"half ≤{ms} ms" in line for ms in (15, 16, 17, 18)), line


def test_the_games_packets_are_marked_and_still_valid(rig, match):
    errors = rig.server_ip_errors()
    packets = rig.game_packets(150)

    assert dscps(packets) == {32}, f"not all CS4: {packets}"
    assert bad_checksums(packets) == 0, packets
    assert rig.server_ip_errors() == errors
    # and the server's echoes come back: marked packets aren't dropped
    daemon, _ = match
    assert daemon.logged(r"Match detected: fakeshooter.*rx [1-9]")


def test_classic_tc_filters_still_run_under_bpfrag(rig, match):
    """A desktop CAKE setup redirects through IFB devices with classic tc
    filters. bpfrag's programs run first and must pass packets on."""
    for direction in ("ingress", "egress"):
        before = rig.ifb_packets(direction)
        wait_until(
            f"{direction} IFB starved under bpfrag",
            lambda: rig.ifb_packets(direction) - before > 20,
            timeout=5,
        )


def test_the_tier_follows_the_games_rate(rig, match):
    daemon, game = match
    game.set_rate(150)
    daemon.wait_for("COMPETITIVE -> INTENSE")

    assert sysctl("net.core.busy_poll") == "75"
    wait_until(
        lambda: f"waybar: {daemon.ask('--waybar')}",
        lambda: json.loads(daemon.ask("--waybar"))["text"] == "INTENSE",
        timeout=5,
    )


def test_the_game_exiting_ends_the_match(rig, match):
    daemon, game = match
    game.exit()
    daemon.wait_for_end(timeout=5)

    health = daemon.health()
    assert {"p50_ms", "stalls", "jitter_us", "send_longest_ms", "send_stalls"} <= set(health), health
    # the status bar reads what bpfrag last wrote, a reading later
    waybar = wait_until(
        lambda: f"waybar still shows the match: {daemon.ask('--waybar')}",
        lambda: [w for w in [json.loads(daemon.ask("--waybar"))] if w["alt"] == "idle"],
        timeout=5,
    )[0]
    assert "Last match: fakeshooter" in waybar["tooltip"], waybar
    rig.wait_restored()


def test_a_dry_run_changes_nothing_and_still_measures(rig):
    daemon = rig.daemon(None, "--dry-run")
    rig.game(64)
    daemon.wait_for_match()
    daemon.wait_for("would set")

    wait_until(
        lambda: f"no gaps measured in a dry run: {daemon.monitor()}",
        lambda: "connection: packet gaps half" in daemon.monitor(),
    )
    assert not rig.changed()
