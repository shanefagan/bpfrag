# SPDX-License-Identifier: MIT
"""A/B experiments: the arm drawn decides what's applied, and is reported.

keep = 0 always draws the "off" arm and keep = 1 the "on" arm, so the
tests know which they get."""

import json
import subprocess
import sys

import pytest

from rig import REPO, sysctl


def experiment(rig, name, setting, keep, extra=""):
    return rig.config(
        name, append=f'[experiment]\nsetting = "{setting}"\nkeep = {keep}\n{extra}'
    )


def test_the_off_arm_leaves_its_setting_alone(rig):
    daemon = rig.daemon(experiment(rig, "exp-off", "busy_polling", 0))
    game = rig.game(64)
    daemon.wait_for_match()

    daemon.wait_for("Experiment: busy_polling off for this match")
    daemon.wait_for_profile()
    assert sysctl("net.core.busy_poll") == "0" and sysctl("net.core.busy_read") == "0"
    assert daemon.logged(r"net\.core\.netdev_budget="), "the other settings still apply"
    assert "experiment: busy_polling off" in daemon.monitor()

    game.exit()
    health = daemon.health()
    assert health.experiment == "busy_polling off", health["line"]
    # The count is machine-wide, and sockets opened while busy polling was
    # on (earlier tests, or anything else on a desktop) keep polling until
    # they close: a few dozen can show with it off.
    assert health.get("busy_polled", 0) < 1000, health["line"]


def test_the_on_arm_applies_it_as_usual(rig):
    daemon = rig.daemon(experiment(rig, "exp-on", "busy_polling", 1))
    game = rig.game(64)
    daemon.wait_for_match()
    daemon.wait_for_profile()
    assert sysctl("net.core.busy_poll") == "50"

    game.exit()
    health = daemon.health()
    assert health.experiment == "busy_polling on", health["line"]
    assert "busy_polled" in health, health["line"]

    # docs/scripts/matches.py turns the log into a CSV of matches
    out = subprocess.run(
        [sys.executable, REPO / "docs/scripts/matches.py", "-"],
        input=daemon.log(),
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    assert ",busy_polling,on," in out, out


def test_the_all_off_arm_changes_nothing_and_still_measures(rig):
    daemon = rig.daemon(experiment(rig, "exp-all", "all", 0))
    game = rig.game(64)
    daemon.wait_for_match()
    daemon.wait_for("Experiment: all off for this match")
    assert not rig.changed()

    game.exit()
    health = daemon.health()
    assert health.experiment == "all off" and "p50_ms" in health, health["line"]
    # nothing was applied, so nothing should claim to have been
    assert not daemon.logged("already tuned|no game traffic seen")


def test_a_random_experiment_keeps_one_setting_a_day(rig):
    """A one-setting pool makes the pick predictable."""
    config = experiment(rig, "exp-random", "random", 0, 'pool = ["backlog"]\n')
    first = rig.daemon(config)
    first.wait_for(
        r"Experiment for today: backlog, switched off in 100% of matches "
        r"\(picked at random from the configured pool: backlog\)"
    )
    saved = json.loads((rig.work / "state" / "experiment.json").read_text())
    assert saved["setting"] == "backlog", saved
    first.stop()

    daemon = rig.daemon(config)
    daemon.wait_for(r"Experiment for today: backlog, .*\(picked earlier today\)")
    backlog = sysctl("net.core.netdev_max_backlog")
    rig.game(64)
    daemon.wait_for_match()
    daemon.wait_for("Experiment: backlog off for this match")
    daemon.wait_for_profile()
    assert sysctl("net.core.netdev_max_backlog") == backlog
    assert sysctl("net.core.busy_poll") == "50", "the other settings still apply"

    check = daemon.ask("--check")
    assert any(
        "experiment" in line and "random, one setting per day (now: backlog)" in line
        for line in check.splitlines()
    ), check


@pytest.fixture(autouse=True)
def forget_todays_pick(rig):
    """The day's random pick is kept in the state directory."""
    yield
    (rig.work / "state" / "experiment.json").unlink(missing_ok=True)
