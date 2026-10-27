# SPDX-License-Identifier: MIT
# Fake bulk transfer for the e2e rig: TCP to the server's port 27016 at about
# MBPS megabits per second, "up" (we send) or "down" (the server sends).
#   bulk.py up|down MBPS
import os, socket, sys, time
mode, mbps = sys.argv[1], float(sys.argv[2])
dest = os.environ.get("DEST", "10.99.0.2")
s = socket.create_connection((dest, 27016))
if mode == "down":
    s.sendall(f"d {mbps}".encode())
    while s.recv(65536):
        pass
    sys.exit()
s.sendall(b"u")
time.sleep(0.1)
per_sec = mbps * 1e6 / 8
chunk = b"x" * 16384
nxt = time.monotonic()
while True:
    s.sendall(chunk)
    nxt += len(chunk) / per_sec
    d = nxt - time.monotonic()
    if d > 0:
        time.sleep(d)
