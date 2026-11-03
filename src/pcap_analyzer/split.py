"""Split a large capture into parts that each hold whole connections, without tshark.

tshark keeps state for every frame it reads, so one pass over a large capture needs memory in proportion to its size.
Each part goes to its own tshark through a pipe instead, and nothing is written to disk. A connection is found from
its innermost addresses and ports, also inside VXLAN, Geneve, GRE and IP-in-IP, so both directions and every copy
of one connection land in the same part.
"""
import struct
import zlib
from array import array
from dataclasses import dataclass, field

PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
PCAP_MODIFIED = {b"\x34\xcd\xb2\xa1": "<", b"\xa1\xb2\xcd\x34": ">"}  # Kuznetzov's format has 8 more bytes per record
SHB, IDB, PB, SPB, EPB, JOURNAL = 0x0A0D0D0A, 1, 2, 3, 6, 9
FRAME_BLOCKS = (PB, SPB, EPB, JOURNAL)  # tshark numbers these as frames
ETHERNET, NULL, LOOP, SLL, SLL2 = 1, 0, 108, 113, 276
RAW = (101, 12, 14, 228, 229)
VLAN = (0x8100, 0x88A8, 0x9100)
MPLS = (0x8847, 0x8848)
PPPOE = 0x8864
VXLAN_PORTS = (4789, 8472)
GENEVE_PORT = 6081
ICMP_ERRORS = {1: (3, 4, 5, 11, 12), 58: (1, 2, 3, 4)}  # they quote the header of the packet they answer
IPV6_EXTENSIONS = (0, 43, 60, 51)
FRAG_MEMORY = 4096
BATCH = 1 << 20


class Unsupported(ValueError):
    """Not a pcap or pcapng file."""


@dataclass
class Part:
    offsets: array = field(default_factory=lambda: array("Q"))
    lengths: array = field(default_factory=lambda: array("I"))
    frames: array = field(default_factory=lambda: array("I"))  # original frame number of each frame in this part


@dataclass
class Plan:
    head: bytes
    parts: list
    truncated: bool = False


class _Keys:
    """The connection a frame belongs to. Fragments after the first carry no ports, so they follow the first."""

    def __init__(self):
        self.fragments = {}

    def frame(self, link, data):
        try:
            if link == ETHERNET:
                return self.ether(data, 0)
            if link == SLL:
                return self.ethertype(data, struct.unpack_from(">H", data, 14)[0], 16)
            if link == SLL2:
                return self.ethertype(data, struct.unpack_from(">H", data, 0)[0], 20)
            if link in (NULL, LOOP):
                return self.ip(data, 4)
            if link in RAW:
                return self.ip(data, 0)
        except (struct.error, IndexError):
            pass
        return None

    def ether(self, data, off):
        return self.ethertype(data, struct.unpack_from(">H", data, off + 12)[0], off + 14)

    def ethertype(self, data, kind, off):
        while kind in VLAN:
            kind = struct.unpack_from(">H", data, off + 2)[0]
            off += 4
        if kind in MPLS:
            while not data[off + 2] & 1:
                off += 4
            return self.ip(data, off + 4)
        if kind == PPPOE:
            proto = struct.unpack_from(">H", data, off + 6)[0]
            return self.ip(data, off + 8) if proto in (0x21, 0x57) else None
        if kind in (0x0800, 0x86DD):
            return self.ip(data, off)
        return None

    def ip(self, data, off):
        version = data[off] >> 4
        if version == 4:
            ihl = (data[off] & 15) * 4
            ident, frag = struct.unpack_from(">HH", data, off + 4)
            proto, src, dst = data[off + 9], data[off + 12:off + 16], data[off + 16:off + 20]
            return self._l4(data, off + ihl, proto, src, dst, (src, dst, ident, proto), frag & 0x1FFF, frag & 0x2000)
        if version == 6:
            proto, src, dst, l4 = data[off + 6], data[off + 8:off + 24], data[off + 24:off + 40], off + 40
            frag_id = offset = more = None
            while proto in IPV6_EXTENSIONS or proto == 44:
                if proto == 44:
                    word, frag_id = struct.unpack_from(">HI", data, l4 + 2)
                    offset, more = word >> 3, word & 1
                    proto, l4 = data[l4], l4 + 8
                elif proto == 51:
                    proto, l4 = data[l4], l4 + (data[l4 + 1] + 2) * 4
                else:
                    proto, l4 = data[l4], l4 + (data[l4 + 1] + 1) * 8
            ident = (src, dst, frag_id, proto) if frag_id is not None else None
            return self._l4(data, l4, proto, src, dst, ident, offset or 0, more)
        return None

    def _l4(self, data, off, proto, src, dst, ident, frag_offset, more):
        if frag_offset:
            return self.fragments.get(ident)
        key = self._key(data, off, proto, src, dst)
        if more and ident is not None:
            if len(self.fragments) > FRAG_MEMORY:
                self.fragments.clear()
            self.fragments[ident] = key
        return key

    def _key(self, data, off, proto, src, dst):
        if proto in (6, 17, 132):
            sport, dport = struct.unpack_from(">HH", data, off)
            if proto == 17:
                inner = self._udp_tunnel(data, off + 8, sport, dport)
                if inner:
                    return inner
            return _pair(proto, src + struct.pack(">H", sport), dst + struct.pack(">H", dport))
        if proto in (4, 41):
            return self.ip(data, off)
        if proto == 47:
            return self._gre(data, off) or _pair(proto, src, dst)
        if proto in ICMP_ERRORS and data[off] in ICMP_ERRORS[proto]:
            return self.ip(data, off + 8)
        return _pair(proto, src, dst)

    def _udp_tunnel(self, data, off, sport, dport):
        if dport in VXLAN_PORTS or sport in VXLAN_PORTS:
            return self.ether(data, off + 8)
        if dport == GENEVE_PORT or sport == GENEVE_PORT:
            kind = struct.unpack_from(">H", data, off + 2)[0]
            inner = off + 8 + (data[off] & 0x3F) * 4
            return self.ether(data, inner) if kind == 0x6558 else self.ethertype(data, kind, inner)
        return None

    def _gre(self, data, off):
        flags, kind = struct.unpack_from(">HH", data, off)
        inner = off + 4 + 4 * (bool(flags & 0x8000) + bool(flags & 0x2000) + bool(flags & 0x1000))
        if kind == 0x6558:
            return self.ether(data, inner)
        return self.ethertype(data, kind, inner)


def _pair(proto, a, b):
    """The same key for both directions."""
    return bytes([proto]) + (a + b if a <= b else b + a)


def _records(f):
    """Return the pcap file header, and yield (offset, length, link or None, frame data or None) for every record.
    Frame data is None for pcapng blocks that each part needs, and the length is -1 where the file is cut short."""
    magic = f.read(4)
    f.seek(0)
    if magic in PCAP_MAGIC or magic in PCAP_MODIFIED:
        glob = f.read(24)
        return glob, _pcap_records(f, magic, glob)
    if magic == struct.pack("<I", SHB):
        return b"", _pcapng_records(f)
    raise Unsupported("not a pcap or pcapng file")


def _pcap_records(f, magic, glob):
    order = PCAP_MAGIC.get(magic) or PCAP_MODIFIED[magic]
    extra = 8 if magic in PCAP_MODIFIED else 0
    link = struct.unpack_from(order + "I", glob, 20)[0] & 0x0FFFFFFF
    pos = 24
    while True:
        rec = f.read(16 + extra)
        if not rec:
            return
        if len(rec) < 16 + extra:
            yield pos, -1, None, None
            return
        size = struct.unpack_from(order + "I", rec, 8)[0]
        data = f.read(size)
        if len(data) < size:
            yield pos, -1, None, None
            return
        yield pos, 16 + extra + size, link, data
        pos += 16 + extra + size


def _pcapng_records(f):
    order, links, pos = "<", [], 0
    while True:
        top = f.read(8)
        if not top:
            return
        if len(top) < 8:
            yield pos, -1, None, None
            return
        kind = struct.unpack_from("<I", top)[0]
        if kind == SHB:
            magic = f.read(4)
            order = "<" if magic == b"\x4d\x3c\x2b\x1a" else ">"
            f.seek(pos + 8)
            links = []
        kind, size = struct.unpack(order + "II", top)
        if size < 12:
            yield pos, -1, None, None
            return
        body = f.read(size - 8)
        if len(body) < size - 8:
            yield pos, -1, None, None
            return
        if kind == IDB:
            links.append(struct.unpack_from(order + "H", body)[0])
        if kind == EPB:
            iface, _, _, cap = struct.unpack_from(order + "IIII", body)
            yield pos, size, links[iface] if iface < len(links) else None, body[20:20 + cap]
        elif kind == PB:
            iface = struct.unpack_from(order + "H", body)[0]
            cap = struct.unpack_from(order + "I", body, 12)[0]
            yield pos, size, links[iface] if iface < len(links) else None, body[20:20 + cap]
        elif kind == SPB:
            yield pos, size, links[0] if links else None, body[4:]
        elif kind == JOURNAL:
            yield pos, size, None, b""
        else:
            yield pos, size, None, None
        pos += size


def part_of(key, count):
    return zlib.crc32(key) % count if key else 0


def plan(path, count):
    """Read the capture once and choose a part for every frame."""
    keys = _Keys()
    parts = [Part() for _ in range(count)]
    frame, truncated = 0, False
    with open(path, "rb") as f:
        head, records = _records(f)
        for pos, size, link, data in records:
            if size < 0:
                truncated = True
                break
            if data is None:  # pcapng section, interface and other blocks go to every part
                for p in parts:
                    p.offsets.append(pos)
                    p.lengths.append(size)
                continue
            frame += 1
            p = parts[part_of(keys.frame(link, data) if link is not None else None, count)]
            p.offsets.append(pos)
            p.lengths.append(size)
            p.frames.append(frame)
    return Plan(head, parts, truncated)


def feed(path, plan, k):
    """The bytes of one part, as a capture tshark can read from a pipe."""
    part = plan.parts[k]
    out = bytearray(plan.head)
    with open(path, "rb") as f:
        for pos, size in zip(part.offsets, part.lengths):
            f.seek(pos)
            out += f.read(size)
            if len(out) >= BATCH:
                yield bytes(out)
                out.clear()
    if out:
        yield bytes(out)
