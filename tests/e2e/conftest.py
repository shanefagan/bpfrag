# SPDX-License-Identifier: MIT
"""Fixtures for the end-to-end tests. See rig.py for what they give a test."""

import os
import shutil
import subprocess

import pytest

from rig import REPO, Rig


def pytest_addoption(parser):
    parser.addoption(
        "--bpfrag",
        default=os.environ.get("BPFRAG_BIN", str(REPO / "target/release/bpfrag")),
        help="the bpfrag binary to test, or a wrapper such as tests/rig/unit-caps.sh",
    )


@pytest.fixture(scope="session")
def rig(request):
    """The test network, built once and removed at the end."""
    if os.geteuid() != 0:
        pytest.exit("the end-to-end tests need root (just e2e)", returncode=2)
    for tool in ("ip", "tc", "tcpdump", "sysctl"):
        if not shutil.which(tool):
            pytest.exit(f"the end-to-end tests need {tool}", returncode=2)
    # An installed bpfrag would see the fake game too, tune the system
    # under the test and write its matches into the real captures.
    if shutil.which("systemctl") and (
        subprocess.run(["systemctl", "is-active", "--quiet", "bpfrag"], check=False).returncode
        == 0
    ):
        pytest.exit(
            "bpfrag.service is running: it would tune for the fake game too.\n"
            "Stop it first (sudo systemctl stop bpfrag), and start it again after.",
            returncode=2,
        )
    r = Rig(request.config.getoption("--bpfrag"))
    try:
        r.up()
        yield r
    finally:
        r.down()


@pytest.fixture(autouse=True)
def clean_slate(rig):
    """Each test starts with nothing running and ends the same way, with
    every setting back as it was: the promise bpfrag makes about a match."""
    yield
    rig.end_processes()
    rig.restore()
    rig.wait_restored()


@pytest.fixture
def daemon(rig):
    """bpfrag running with the rig's base config."""
    return rig.daemon()


@pytest.fixture
def match(rig, daemon):
    """A match in progress: the fake game at 64 packets a second, detected.
    Gives (daemon, game)."""
    game = rig.game(64)
    daemon.wait_for_match("COMPETITIVE")
    return daemon, game
