# SPDX-License-Identifier: MIT
# Summarise a pcap of game packets: DSCP/traffic class and IPv4 header
# checksum validity, as "family dscp=0xNN csum=ok|BAD count" lines.
import struct, sys
data = open(sys.argv[1], "rb").read()
end = "<" if struct.unpack("<I", data[:4])[0] in (0xA1B2C3D4, 0xA1B23C4D) else ">"
off, out = 24, {}
while off + 16 <= len(data):
    incl = struct.unpack(end + "IIII", data[off:off + 16])[2]
    pkt = data[off + 16:off + 16 + incl]
    off += 16 + incl
    et = pkt[12:14]
    if et == b"\x08\x00":
        ip = pkt[14:]
        ihl = (ip[0] & 0xF) * 4
        s = sum(struct.unpack("!%dH" % (ihl // 2), ip[:ihl]))
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        key = ("ipv4", ip[1] >> 2, "ok" if s == 0xFFFF else "BAD")
    elif et == b"\x86\xdd":
        ip = pkt[14:]
        tc = ((ip[0] & 0x0F) << 4) | (ip[1] >> 4)
        key = ("ipv6", tc >> 2, "n/a")
    else:
        continue
    out[key] = out.get(key, 0) + 1
for (fam, dscp, csum), n in sorted(out.items()):
    print(f"{fam} dscp={dscp} csum={csum} {n}")
