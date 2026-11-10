# SPDX-License-Identifier: MIT
"""The end-to-end rig: a throwaway network, a fake game and bpfrag itself.

A network namespace "bpfrag-srv" (10.99.0.2, and .3 for a second server)
sits behind the veth "bpfrag0", with an echo server in it. A fake Steam
game and other processes send to it, and the tests check how bpfrag
reacts. Needs root; everything is removed afterwards.

Tests use three things from here, through the fixtures in conftest.py:

    rig     the network, the work directory, sysctls, packet captures
    daemon  starts bpfrag; .wait_for() a log line, .health(), .stop()
    game    starts the fake game; .set_rate(), .freeze(), .exit()

Nothing here sleeps for a fixed time to let something happen: wait_for()
polls for the event, so a slow machine is slow, not wrong.
"""

import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
PROGRAMS = REPO / "tests" / "rig"  # client.py, server.py, bulk.py, ...

SERVER = "10.99.0.2"
SERVER2 = "10.99.0.3"
SERVER_V6 = "fd00:99::2"
GAME_PORT = 27015

# The sysctls bpfrag may change. A match must leave every one as it was.
SYSCTLS = (
    "net.core.rmem_max",
    "net.core.wmem_max",
    "net.core.busy_poll",
    "net.core.busy_read",
    "net.core.netdev_budget",
    "net.core.netdev_max_backlog",
    "net.ipv4.udp_mem",
    "vm.dirty_bytes",
    "vm.dirty_ratio",
    "vm.dirty_background_bytes",
    "vm.dirty_background_ratio",
)

# The rig's base config. D-Bus stays off: a test instance must never speak
# on the machine's real system bus. busy_read/busy_poll are set per tier
# as the one sysctl with a fixed value (the built-in profiles' own are all
# raise-only), so tests can follow it through tier changes and restore.
BASE_CONFIG = """\
[general]
run_dir = "{work}/run"
state_dir = "{work}/state"
dbus = false
[dscp]
interfaces = ["bpfrag0"]
[detect]
linger_secs = 6
dwell_secs = 3
# the fake game starts its match the moment it launches
launch_secs = 0
[tier.casual]
sysctl = {{ "net.core.busy_read" = 25, "net.core.busy_poll" = 25 }}
[tier.competitive]
sysctl = {{ "net.core.busy_read" = 50, "net.core.busy_poll" = 50 }}
[tier.intense]
sysctl = {{ "net.core.busy_read" = 75, "net.core.busy_poll" = 75 }}
"""


def run(*cmd, check=True, **kw):
    """Run a command and return what it printed."""
    r = subprocess.run(
        [str(c) for c in cmd], capture_output=True, text=True, check=False, **kw
    )
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(map(str, cmd))}: {r.stderr.strip()}")
    return r.stdout


def sysctl(name):
    return " ".join(run("sysctl", "-n", name).split())


def set_sysctl(name, value):
    run("sysctl", "-qw", f"{name}={value}")


def wait_until(what, test, timeout=15.0, every=0.1):
    """Poll `test` until it returns something true, and return that.

    Fails with `what` (a string, or a function returning one for a message
    built at the time of failure) after `timeout` seconds.
    """
    deadline = time.monotonic() + timeout
    while True:
        got = test()
        if got:
            return got
        if time.monotonic() >= deadline:
            raise AssertionError(what() if callable(what) else what)
        time.sleep(every)


class Process:
    """A child process the rig started, stopped again at the test's end."""

    def __init__(self, argv, env=None, stdout=None):
        self.proc = subprocess.Popen(
            [str(a) for a in argv],
            env={**os.environ, **(env or {})},
            stdout=stdout or subprocess.DEVNULL,
            stderr=subprocess.STDOUT if stdout else subprocess.DEVNULL,
        )
        self.pid = self.proc.pid

    def running(self):
        return self.proc.poll() is None

    def exit(self, sig=signal.SIGTERM):
        if self.running():
            self.proc.send_signal(sig)
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


class Game(Process):
    """The fake game: a process that looks like a Steam game to bpfrag and
    sends `rate` packets a second of `size` bytes to the echo server."""

    def __init__(self, rig, rate=64, size=180, env=None):
        self.ctl = rig.work / f"rate-{time.monotonic_ns()}"
        self.ctl.write_text(str(rate))
        super().__init__(
            [rig.fakeshooter, rig.work / "client.py", rate, size, self.ctl],
            env={"SteamAppId": "4242", **(env or {})},
        )

    def set_rate(self, rate):
        """Change the send rate (the game reads it within a second)."""
        self.ctl.write_text(str(rate))

    def freeze(self, secs):
        """Stop the game dead for `secs`: a hiccup in both directions."""
        self.proc.send_signal(signal.SIGSTOP)
        time.sleep(secs)
        self.proc.send_signal(signal.SIGCONT)


class Health(dict):
    """A match's health line, as numbers.

    The one place that knows the line's wording. Keys: p50_ms, p99_ms,
    longest_ms, stalls, jitter_us, send_longest_ms, send_stalls (those
    present in the line), and `line`, the text itself.
    """

    FIELDS = (
        ("p50_ms", r"packet gaps half ≤(\d+) ms"),
        ("longest_ms", r"gaps half[^;]*?longest (\d+) ms"),
        ("stalls", r"gaps half[^;]*?(\d+) stalls? \(100 ms\+\)"),
        ("jitter_us", r"jitter (\d+) µs"),
        ("send_longest_ms", r"own sending: longest gap (\d+) ms"),
        ("send_stalls", r"own sending: longest gap \d+ ms, (\d+) stalls?"),
        ("busy_polled", r"busy-polled packets: (\d+)"),
    )

    def __init__(self, line):
        super().__init__(line=line)
        for key, pattern in self.FIELDS:
            m = re.search(pattern, line)
            if m:
                self[key] = int(m.group(1))


class Daemon:
    """One run of bpfrag, logging to a file the test can wait on."""

    def __init__(self, rig, config, *args, env=None):
        self.rig = rig
        self.config = config
        self.log_path = rig.work / f"daemon-{time.monotonic_ns()}.log"
        self._out = open(self.log_path, "wb")
        self.proc = subprocess.Popen(
            [*rig.bpfrag, "-c", str(config), *args],
            stdout=self._out,
            stderr=subprocess.STDOUT,
            env={**os.environ, **(env or {})},
        )
        self.wait_for(r"started.*; waiting for game traffic", timeout=20)

    # -- its log ---------------------------------------------------------

    def log(self):
        return self.log_path.read_text(errors="replace")

    def lines(self, pattern):
        """The log lines matching a regular expression."""
        rx = re.compile(pattern)
        return [line for line in self.log().splitlines() if rx.search(line)]

    def logged(self, pattern):
        return bool(self.lines(pattern))

    def wait_for(self, pattern, timeout=15.0, count=1):
        """Wait until `count` log lines match, and return the last."""

        def tail():
            last = "\n".join(self.log().splitlines()[-8:])
            return f"no {pattern!r} (x{count}) in {timeout:.0f} s; the log ends:\n{last}"

        def found():
            if self.proc.poll() is not None and not self.lines(pattern):
                raise AssertionError(f"bpfrag exited ({self.proc.returncode}):\n{self.log()}")
            got = self.lines(pattern)
            return got[-1] if len(got) >= count else None

        return wait_until(tail, found, timeout)

    def wait_for_match(self, tier=None, timeout=20.0, count=1):
        tier = f".*-> {tier}" if tier else ""
        return self.wait_for(rf"Match detected: \w+{tier}", timeout, count)

    def wait_for_end(self, timeout=15.0, count=1):
        return self.wait_for(r"Match ended", timeout, count)

    def health(self, game="fakeshooter", timeout=10.0, count=1):
        """The health line of the game's latest match, once it's logged."""
        return Health(self.wait_for(rf"{game}: packet gaps", timeout, count))

    # -- asking it things ------------------------------------------------

    def ask(self, *args):
        """Run the CLI against this daemon's config (--monitor 0, --waybar)."""
        r = subprocess.run(
            [*self.rig.bpfrag, "-c", str(self.config), *args],
            capture_output=True,
            text=True,
            check=False,
        )
        return r.stdout + r.stderr

    def monitor(self):
        return self.ask("--monitor", "0")

    # -- ending it -------------------------------------------------------

    def running(self):
        return self.proc.poll() is None

    def stop(self):
        """Ctrl-C: bpfrag restores settings and exits."""
        self._end(signal.SIGINT)

    def kill(self):
        """kill -9: no chance to restore anything."""
        self._end(signal.SIGKILL)

    def _end(self, sig):
        if self.running():
            self.proc.send_signal(sig)
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self._out.close()


class Rig:
    """The network and files every test shares. Built once per session."""

    def __init__(self, bpfrag):
        # one path, or a wrapper followed by nothing (tests/rig/unit-caps.sh)
        self.bpfrag = [str(Path(bpfrag).resolve())]
        self.work = Path(tempfile.mkdtemp(prefix="bpfrag-e2e."))
        self.have_v6 = Path("/proc/net/if_inet6").exists()
        self._started = []
        self._server = None
        self.baseline = {}

    # -- building and removing it ---------------------------------------

    def up(self):
        w = self.work
        for name in ("client.py", "server.py", "bulk.py", "tcpgame.py"):
            shutil.copy(PROGRAMS / name, w / name)
        # A process is a game to bpfrag by where its binary lives and what
        # it's called, so the fake ones are python under other names.
        self.fakeshooter = self._alias("steamapps/common/FakeShooter/fakeshooter")
        self.fakemmo = self._alias("steamapps/common/FakeMMO/fakemmo")
        self.apps = {
            n: self._alias(f"apps/{n}")
            for n in ("Discord", "firefox", "randomd", "steam", "obs")
        }
        # bpftune only has to be running under that name
        self.bpftune = self._alias("apps/bpftune", shutil.which("sleep"))
        self.config_path = w / "cfg.toml"
        self.config_path.write_text(BASE_CONFIG.format(work=w))

        run("ip", "netns", "add", "bpfrag-srv")
        run("ip", "link", "add", "bpfrag0", "type", "veth", "peer", "name", "bpfrag1")
        run("ip", "link", "set", "bpfrag1", "netns", "bpfrag-srv")
        run("ip", "addr", "add", "10.99.0.1/24", "dev", "bpfrag0")
        run("ip", "link", "set", "bpfrag0", "up")
        srv = ("ip", "-n", "bpfrag-srv")
        run(*srv, "addr", "add", f"{SERVER}/24", "dev", "bpfrag1")
        run(*srv, "link", "set", "bpfrag1", "up")
        run(*srv, "addr", "add", f"{SERVER2}/24", "dev", "bpfrag1")
        if self.have_v6:
            run("ip", "-6", "addr", "add", "fd00:99::1/64", "dev", "bpfrag0", "nodad")
            run(*srv, "-6", "addr", "add", f"{SERVER_V6}/64", "dev", "bpfrag1", "nodad")
        self._server = Process(
            ["ip", "netns", "exec", "bpfrag-srv", sys.executable, w / "server.py"]
        )
        # Classic tc filters redirecting through IFB devices, the way
        # desktop CAKE setups shape downloads. bpfrag's tcx programs run
        # first and must pass packets on to them, not end the chain.
        run("tc", "qdisc", "add", "dev", "bpfrag0", "clsact")
        for direction in ("ingress", "egress"):
            ifb = f"bpfrag-{direction}"
            run("ip", "link", "add", ifb, "type", "ifb")
            run("ip", "link", "set", ifb, "up")
            run(
                "tc", "filter", "add", "dev", "bpfrag0", direction,
                "protocol", "ip", "prio", "1", "u32", "match", "u32", "0", "0",
                "action", "mirred", "egress", "redirect", "dev", ifb,
            )  # fmt: skip
        self.baseline = self.sysctls()

    def down(self):
        self.end_processes()
        if self._server:
            self._server.exit()
        for cmd in (
            ("ip", "netns", "del", "bpfrag-srv"),
            ("ip", "link", "del", "bpfrag0"),
            ("ip", "link", "del", "bpfrag-ingress"),
            ("ip", "link", "del", "bpfrag-egress"),
        ):
            run(*cmd, check=False)
        self.restore()
        if os.environ.get("KEEP"):
            print(f"kept {self.work}")
        elif self.work.name.startswith("bpfrag-e2e."):
            shutil.rmtree(self.work, ignore_errors=True)

    def _alias(self, path, target=sys.executable):
        link = self.work / path
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target)
        return link

    # -- config ----------------------------------------------------------

    def config(self, name, append="", edit=None):
        """A copy of the base config: `append` added at the end, and/or
        passed through `edit` (a function from text to text)."""
        text = self.config_path.read_text()
        if edit:
            text = edit(text)
        path = self.work / f"cfg-{name}.toml"
        path.write_text(text + append)
        return path

    # -- processes -------------------------------------------------------

    def daemon(self, config=None, *args, env=None):
        d = Daemon(self, config or self.config_path, *args, env=env)
        self._started.append(d)
        return d

    def game(self, rate=64, size=180, env=None):
        g = Game(self, rate, size, env)
        self._started.append(g)
        return g

    def app(self, name, program, *args, env=None):
        """Another process under a familiar name (Discord, firefox, ...)
        running one of the rig's programs (client.py, bulk.py, ...)."""
        p = Process([self.apps[name], self.work / program, *args], env=env)
        self._started.append(p)
        return p

    def run_bpftune(self):
        """Something called bpftune, running: bpfrag leaves its sysctls be."""
        p = Process([self.bpftune, "600"])
        self._started.append(p)
        return p

    def end_processes(self):
        """Stop everything a test started: games first, then daemons."""
        for p in [p for p in self._started if not isinstance(p, Daemon)]:
            p.exit()
        for d in [p for p in self._started if isinstance(p, Daemon)]:
            d.stop()
        self._started.clear()

    def restore(self):
        """`bpfrag --restore`: what a user runs after a crash."""
        run(*self.bpfrag, "-c", self.config_path, "--restore", check=False)

    # -- the system's settings ------------------------------------------

    def sysctls(self):
        return {name: sysctl(name) for name in SYSCTLS}

    def changed(self):
        """Sysctls that differ from before the first test: {name: (was, now)}."""
        now = self.sysctls()
        return {
            k: (self.baseline[k], now[k]) for k in SYSCTLS if now[k] != self.baseline[k]
        }

    def wait_restored(self, timeout=5.0):
        """Every setting back as it was before the tests."""
        wait_until(
            lambda: f"settings not back to the baseline: {self.changed()}",
            lambda: not self.changed(),
            timeout,
        )

    # -- packets ---------------------------------------------------------

    def capture(self, what, count=40, where="server", secs=4):
        """Capture packets matching a tcpdump filter and summarise them.

        `where` is "server" (what arrives at the game server), or "ingress"
        / "egress" (what a desktop CAKE would see on its IFB device).
        Returns {(family, dscp, checksum): packets}, e.g.
        {("ipv4", 32, "ok"): 40}.
        """
        pcap = self.work / f"cap-{time.monotonic_ns()}.pcap"
        tcpdump = ["timeout", str(secs), "tcpdump", "-Z", "root", "-n"]
        if where == "server":
            tcpdump = ["ip", "netns", "exec", "bpfrag-srv", *tcpdump, "-i", "bpfrag1"]
        else:
            tcpdump += ["-i", f"bpfrag-{where}"]
        run(*tcpdump, "-c", count, "-w", pcap, what, check=False)
        out = {}
        for line in run(sys.executable, PROGRAMS / "pcap_check.py", pcap).splitlines():
            family, dscp, csum, n = line.split()
            out[(family, int(dscp.split("=")[1]), csum.split("=")[1])] = int(n)
        return out

    def game_packets(self, count=60, server=SERVER):
        """The game's packets as its server receives them."""
        return self.capture(
            f"udp and dst port {GAME_PORT} and src 10.99.0.1 and dst {server}", count
        )

    def ifb_packets(self, direction):
        """Packets redirected to the classic tc filter's IFB so far."""
        path = Path(f"/sys/class/net/bpfrag-{direction}/statistics/rx_packets")
        return int(path.read_text())

    def server_ip_errors(self):
        """IP checksum and header errors the server's kernel has counted."""
        out = run(
            "ip", "netns", "exec", "bpfrag-srv",
            "nstat", "-az", "IpExtInCsumErrors", "IpInHdrErrors",
            check=False,
        )  # fmt: skip
        return sum(int(line.split()[1]) for line in out.splitlines() if line.startswith("Ip"))


def dscps(packets):
    """The DSCP values in a capture() result."""
    return {dscp for (_family, dscp, _csum) in packets}


def bad_checksums(packets):
    return sum(n for (_f, _d, csum), n in packets.items() if csum == "BAD")
