# SPDX-License-Identifier: MIT
"""The D-Bus interface: read-only, and readable by anyone.

The tests give bpfrag a private bus with the system bus's default policy
plus bpfrag's own, so nothing here speaks on the machine's real one."""

import json
import os
import shutil
import subprocess
import time

import pytest

from rig import REPO, Process, wait_until

NAME = "com.performativenonsense.Bpfrag1"
PATH = "/com/performativenonsense/Bpfrag1"

BUS_CONFIG = """\
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <listen>{address}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow user="*"/>
    <deny own="*"/>
    <deny send_type="method_call"/>
    <allow send_type="signal"/>
    <allow send_requested_reply="true" send_type="method_return"/>
    <allow send_requested_reply="true" send_type="error"/>
    <allow receive_type="method_call"/>
    <allow receive_type="method_return"/>
    <allow receive_type="error"/>
    <allow receive_type="signal"/>
    <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus"/>
    <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus.Introspectable"/>
  </policy>
  <policy user="root">
    <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus.Monitoring"/>
  </policy>
  <include>{policy}</include>
</busconfig>
"""


class Bus:
    """A private bus, a recording of its signals, and two kinds of caller."""

    def __init__(self, rig):
        # an abstract socket needs no directory another user can reach
        self.address = f"unix:abstract=bpfrag-e2e-{os.getpid()}-{time.monotonic_ns()}"
        conf = rig.work / "bus.conf"
        conf.write_text(
            BUS_CONFIG.format(
                address=self.address,
                policy=REPO / "dist/com.performativenonsense.Bpfrag1.conf",
            )
        )
        self.daemon = Process(["dbus-daemon", "--nofork", f"--config-file={conf}"])
        self.signal_log = rig.work / f"signals-{time.monotonic_ns()}.log"
        self._out = open(self.signal_log, "wb")
        wait_until("the private bus didn't start", lambda: self._busctl([], "list").returncode == 0)
        self.monitor = Process(
            [
                "dbus-monitor", "--address", self.address,
                f"type='signal',interface='{NAME}'",
                "type='signal',member='PropertiesChanged'",
            ],
            stdout=self._out,
        )  # fmt: skip
        time.sleep(0.5)  # dbus-monitor has no "ready" to wait for

    def close(self):
        self.monitor.exit()
        self.daemon.exit()
        self._out.close()

    def _busctl(self, as_user, *args):
        return subprocess.run(
            [*as_user, "busctl", f"--address={self.address}", *args],
            capture_output=True,
            text=True,
            check=False,
        )

    # someone with no privileges at all
    NOBODY = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups"]

    def get(self, prop):
        """A property's value, read as an unprivileged user."""
        r = self._busctl(self.NOBODY, "--json=short", "get-property", NAME, PATH, NAME, prop)
        assert r.returncode == 0, f"{prop}: {r.stderr}"
        return json.loads(r.stdout)["data"]

    def try_set(self, prop, signature, value, as_root=False):
        """Try to set a property; True if the bus let it through."""
        who = [] if as_root else self.NOBODY
        r = self._busctl(who, "set-property", NAME, PATH, NAME, prop, signature, value)
        return r.returncode == 0

    def try_own_name(self):
        r = self._busctl(
            self.NOBODY, "call", "org.freedesktop.DBus", "/org/freedesktop/DBus",
            "org.freedesktop.DBus", "RequestName", "su", NAME, "4",
        )  # fmt: skip
        return r.returncode == 0

    def signals(self, member):
        """Each signal of that name recorded so far, as dbus-monitor's text."""
        out, current = [], None
        for line in self.signal_log.read_text(errors="replace").splitlines():
            if line.startswith("signal "):
                current = [] if f"member={member}" in line else None
                if current is not None:
                    out.append(current)
            if current is not None:
                current.append(line)
        return ["\n".join(block) for block in out]

    def wait_for_signal(self, member, containing="", timeout=10):
        return wait_until(
            lambda: f"no {member} signal containing {containing!r}: {self.signals(member)}",
            lambda: [s for s in self.signals(member) if containing in s],
            timeout,
        )[-1]


@pytest.fixture
def bus(rig):
    for tool in ("dbus-daemon", "dbus-monitor", "busctl", "setpriv"):
        if not shutil.which(tool):
            pytest.skip(f"the D-Bus tests need {tool}")
    b = Bus(rig)
    yield b
    rig.end_processes()  # bpfrag first, so it leaves the bus cleanly
    b.close()


@pytest.fixture
def on_bus(rig, bus):
    """bpfrag publishing on the private bus."""
    config = rig.config("dbus", edit=lambda t: t.replace("dbus = false", "dbus = true"))
    daemon = rig.daemon(config, env={"DBUS_SYSTEM_BUS_ADDRESS": bus.address})
    daemon.wait_for(f"D-Bus: publishing {NAME}")
    return daemon


def test_anyone_can_read_the_state(rig, bus, on_bus):
    assert bus.get("InMatch") is False
    assert bus.get("State") == "idle"

    before_ms = time.time() * 1000
    rig.game(64)
    on_bus.wait_for_match()
    wait_until("InMatch never became true", lambda: bus.get("InMatch"), timeout=5)

    assert bus.get("State") == "match"
    assert bus.get("Tier") == "competitive"
    assert bus.get("Reason") == "Steam app 4242"
    assert bus.get("AppId") == 4242
    on_bus.wait_for_profile()
    applied = wait_until(
        "Applied never listed the settings",
        lambda: {entry[0]: entry[1] for entry in bus.get("Applied")},
        timeout=5,
    )
    assert applied["net.core.busy_poll"] == "50"
    # when the match's traffic began (ms), which is before it was detected (s)
    started, since = bus.get("MatchStartedAt"), bus.get("MatchSince")
    assert before_ms - 2000 < started < since * 1000 + 1000, (before_ms, started, since)


def test_nobody_can_change_it(rig, bus, on_bus):
    assert not bus.try_set("Tier", "s", "intense"), "another user set a property"
    assert not bus.try_set("Tier", "s", "intense", as_root=True), "root set a property"
    assert not bus.try_own_name(), "another user took bpfrag's name"


def test_a_match_is_signalled_from_start_to_end(rig, bus, on_bus):
    game = rig.game(64)
    on_bus.wait_for_match()
    bus.wait_for_signal("MatchStarted")
    state = bus.wait_for_signal("StateChanged", 'string "match"')
    assert 'string "at_ms"' in state

    game.set_rate(150)
    on_bus.wait_for("COMPETITIVE -> INTENSE")
    bus.wait_for_signal("TierChanged", 'string "intense"')

    game.exit()
    on_bus.wait_for_end()
    ended = bus.wait_for_signal("MatchEnded", 'string "game exited"')
    assert 'string "gap_p50_ms"' in ended, "MatchEnded carries the match's health"
    bus.wait_for_signal("StateChanged", 'string "match_ended_at_ms"')
    assert bus.signals("PropertiesChanged")
    wait_until("still InMatch", lambda: bus.get("InMatch") is False, timeout=5)
    assert bus.get("State") == "idle"


def test_stopping_bpfrag_mid_match_ends_it_for_listeners(rig, bus, on_bus):
    rig.game(64)
    on_bus.wait_for_match()
    bus.wait_for_signal("MatchStarted")
    on_bus.stop()

    bus.wait_for_signal("MatchEnded", 'string "bpfrag stopped"')
    idle = bus.wait_for_signal("StateChanged", 'string "end_reason"')
    assert "bpfrag stopped" in idle


def test_without_a_bus_bpfrag_carries_on(rig):
    config = rig.config("dbus", edit=lambda t: t.replace("dbus = false", "dbus = true"))
    nowhere = f"unix:abstract=bpfrag-e2e-none-{os.getpid()}"
    daemon = rig.daemon(config, env={"DBUS_SYSTEM_BUS_ADDRESS": nowhere})
    rig.game(64)

    daemon.wait_for_match()
    assert daemon.logged("D-Bus: system bus not available")
