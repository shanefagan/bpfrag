# SPDX-License-Identifier: MIT
# Echo server for the e2e rig: IPv4 10.99.0.2 and IPv6 fd00:99::2, port 27015.
import select, socket
socks = []
for fam, addr in ((socket.AF_INET, "10.99.0.2"), (socket.AF_INET6, "fd00:99::2")):
    try:
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.bind((addr, 27015))
    except OSError:
        continue  # e.g. IPv6 disabled on this host
    socks.append(s)
while True:
    for s in select.select(socks, [], [])[0]:
        data, peer = s.recvfrom(4096)
        s.sendto(data, peer)
