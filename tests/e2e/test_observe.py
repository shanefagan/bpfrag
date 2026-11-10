# SPDX-License-Identifier: MIT
"""Things bpfrag watches and reports without tuning anything."""

from rig import Process


def test_a_tcp_game_is_observed_never_tuned(rig):
    config = rig.config(
        "tcp", edit=lambda t: t.replace("[detect]\n", '[detect]\ntcp = "observe"\n')
    )
    daemon = rig.daemon(config)
    game = rig.tcp_game(20)
    rig.app("randomd", "tcpgame.py", 20)

    daemon.wait_for(
        rf"TCP game seen: fakemmo \(pid {game.pid}\) at ~2\d sends/s and ~2\d receives/s "
        r"\[Steam app 4243\]; observing only",
        timeout=25,
    )
    assert not daemon.logged("TCP game seen: randomd"), "a non-game was reported"
    assert not daemon.logged("Match detected")
    assert not rig.changed()

    game.exit()
    daemon.wait_for(
        r"TCP game session: fakemmo for \d+s: typically 2\d sends/s and 2\d receives/s, "
        r"9\d and 9\d bytes each"
    )


def test_a_tagged_process_is_logged(rig, daemon):
    """BPFRAG_OBSERVE=1 in a process's environment gets its UDP and TCP
    logged, whatever it is. randomd is no game by any signal."""
    tag = {"BPFRAG_OBSERVE": "1"}
    tcp = rig.app("randomd", "tcpgame.py", 20, env=tag)
    udp = rig.app("randomd", "client.py", 30, 120, env=tag)
    untagged = rig.app("randomd", "tcpgame.py", 20, env={"BPFRAG_OBSERVE": "0"})

    # /proc is listed every 5 s, and a session reported after 10 s of traffic
    daemon.wait_for(
        rf"Observing randomd \(pid {tcp.pid}\): TCP at ~2\d sends/s and ~2\d receives/s "
        r"\[BPFRAG_OBSERVE=1\]",
        timeout=40,
    )
    daemon.wait_for(
        rf"Observing randomd \(pid {udp.pid}\): UDP at ~[23]\d sends/s and ~[23]\d receives/s",
        timeout=40,
    )
    assert not daemon.logged(f"pid {untagged.pid}"), "BPFRAG_OBSERVE=0 isn't a tag"
    assert not daemon.logged("Match detected"), "the tag started a match"
    assert not rig.changed()
    monitor = daemon.monitor()
    assert "Observing (BPFRAG_OBSERVE=1)" in monitor, monitor
    assert f"randomd (pid {tcp.pid}): TCP" in monitor, monitor
    assert "tagged BPFRAG_OBSERVE=1" in daemon.ask("--classify", str(tcp.pid))

    for p in (tcp, udp):
        Process.exit(p)
    daemon.wait_for(
        rf"Observed randomd \(pid {tcp.pid}\): TCP for \d+s: typically 2\d sends/s and "
        r"2\d receives/s, 9\d and 9\d bytes each"
    )
    daemon.wait_for(
        rf"Observed randomd \(pid {udp.pid}\): UDP for \d+s: typically [23]\d sends/s and "
        r"[23]\d receives/s, 120 and 120 bytes each"
    )
