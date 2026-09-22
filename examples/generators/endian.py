# -*- coding: utf-8 -*-
"""Generate the byte-order ``.pcap`` sample fixtures.

Classic PCAP declares its own byte order in the magic number of the global
header, and every 32-bit field after that -- the global header's own, and the
four in each record header -- is written in *that* order rather than in the
host's. A reader therefore carries a branch for it, and until this module there
was no ``.pcap`` fixture in the repository to take the big-endian side of that
branch: every capture under ``examples/captures/`` was little-endian, so on a
little-endian runner the branch was never taken and reading the host's order
instead of the file's produced the right answer anyway.

That is how GitHub issue #605 survived: ``Frame.unpack`` seeded the byte order
under the key ``bytesorder`` where ``byteorder_callback`` in
:file:`pcapkit/protocols/schema/misc/pcap/frame.py` reads ``byteorder``, so the
lookup always missed and always fell back to :data:`sys.byteorder`. Reading a
big-endian capture then byte-swapped ``ts_sec``, ``ts_usec``, ``incl_len`` and
``orig_len`` -- and because ``incl_len`` is the payload length, the first record
swallowed the rest of the file and the read that followed was handed a negative
payload length, raising
``ValueError: read length must be non-negative or -1`` out of
:file:`pcapkit/protocols/schema/schema.py`. A one-character fix, with nothing in
the suite able to tell whether it worked.

=============================== ==========================================
Fixture                         Exercises
=============================== ==========================================
``big_endian.pcap``             magic ``a1 b2 c3 d4`` -- big-endian,
                                microsecond timestamps
``little_endian.pcap``          magic ``d4 c3 b2 a1`` -- the same three
                                records in the little-endian container
``big_endian_nanosecond.pcap``  magic ``a1 b2 3c 4d`` -- big-endian,
                                nanosecond timestamps
=============================== ==========================================

The little-endian twin is the point of the set rather than a spare. It carries
the *same three records* as ``big_endian.pcap`` -- identical timestamps,
identical lengths, byte-identical packet data -- so a test can assert that the
two files parse to the same values instead of only that the big-endian one
parses to values hardcoded in the test. That is the property the byte-order
branch exists to provide, and it is not assertable from one file alone.

The packet data comes from :mod:`scapy`, as it does in :file:`pcap.py`, so the
frames carry real headers and real checksums. The *containers* are packed here
by hand with :mod:`struct`, for two reasons: :func:`scapy.utils.wrpcap` writes
the host's byte order and offers no way to ask for the other one, and the byte
order of the container is the whole subject of these fixtures -- spelling it out
where it can be read is worth more than delegating it.

Frame 3 is captured short: 1200 octets on the wire, ``snaplen`` 96 in the
global header, so ``incl_len`` is 96 and ``orig_len`` is 1200. That is what a
snapshot limit really does, and it makes the fixture prove something a set of
full-length frames cannot -- that the two fields are read separately, rather
than one of them being read and used for both. Frames 1 and 2 have them equal
and so cannot tell the difference.

"""

from __future__ import annotations

import hashlib
import pathlib
import struct
from typing import TYPE_CHECKING, NamedTuple

from scapy.all import ICMP, IP, UDP, Ether, Raw  # pylint: disable=no-name-in-module

if TYPE_CHECKING:
    from typing import Literal

__all__ = ['generate']

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]
#: Default destination directory for the generated captures.
SAMPLE = ROOT / 'examples' / 'captures'

#: PCAP file magic numbers, keyed by endianness and nanosecond-resolution flag.
#: The same table as ``_MAGIC_NUM`` in
#: :file:`pcapkit/protocols/misc/pcap/header.py`, which is the reader these
#: fixtures are written for; it is repeated rather than imported so that a
#: fixture stays generatable without :mod:`pcapkit` importing cleanly.
MAGIC_NUMBER = {
    ('big', False): b'\xa1\xb2\xc3\xd4',
    ('big', True): b'\xa1\xb2\x3c\x4d',
    ('little', False): b'\xd4\xc3\xb2\xa1',
    ('little', True): b'\x4d\x3c\xb2\xa1',
}

#: PCAP version, as every capture in this repository carries.
VERSION = (2, 4)
#: Snapshot length declared by the global header. Frames 1 and 2 are shorter
#: than this and are captured whole; frame 3 is longer and is cut to it.
SNAPLEN = 96
#: Data link type, i.e. ``LinkType.ETHERNET``. Spelled as the number the file
#: holds, for the same reason as :data:`MAGIC_NUMBER`.
NETWORK = 1

#: Capture start time, fixed so that regenerating gives identical files. The
#: same instant :file:`pcap.py` starts its captures at.
EPOCH = 1500000000

#: The fixtures this module writes, as ``(file name, byte order, nanosecond
#: flag)``. The two microsecond files carry byte-identical records in the two
#: containers; the nanosecond one holds the same packets, timed more finely.
FIXTURES = (
    ('big_endian.pcap', 'big', False),
    ('little_endian.pcap', 'little', False),
    ('big_endian_nanosecond.pcap', 'big', True),
)  # type: tuple[tuple[str, Literal['big', 'little'], bool], ...]


class _Record(NamedTuple):
    """One record of a capture: a record header's four fields, and its data.

    The record header is *not* stored as octets here, because the octets are
    what differs between the three fixtures. :func:`_pack` turns these numbers
    into a header in whichever byte order it was asked for.

    """

    #: Timestamp seconds, i.e. ``ts_sec``.
    ts_sec: 'int'
    #: Timestamp fraction: microseconds, or nanoseconds in a nanosecond-
    #: resolution file. Written to ``ts_usec`` either way.
    ts_usec: 'int'
    #: Length of the packet as it was on the wire, i.e. ``orig_len``. Equal to
    #: ``len(packet)`` unless the capture was cut short by ``snaplen``.
    orig_len: 'int'
    #: The packet data actually stored, i.e. ``incl_len`` octets of it.
    packet: 'bytes'


def _filler(length: 'int', tag: 'bytes') -> 'bytes':
    """Deterministic opaque payload bytes.

    The same construction :file:`pcap.py` uses, so that these fixtures are as
    reproducible as the rest and need no network and no clock.

    Args:
        length: Number of octets required.
        tag: Seed distinguishing one payload from another.

    Returns:
        Exactly ``length`` octets, the same on every machine and every run.

    """
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(b'%s/%d' % (tag, counter)).digest()
        counter += 1
    return bytes(out[:length])


def _records(nanosecond: 'bool' = False) -> 'list[_Record]':
    """Build the three records every fixture in this module carries.

    Args:
        nanosecond: Whether the timestamp fractions are nanoseconds. Only the
            fraction changes: a nanosecond capture holds the same packets at
            the same second, timed more finely.

    Returns:
        The records, in capture order.

    """
    # Fractions chosen so that no field reads the same after a byte swap, and
    # so that a swap gives a number nowhere near a plausible one: 123456 is
    # 0x0001e240, which read the wrong way round is 0x40e20100 -- 1088553216
    # microseconds, i.e. eighteen minutes into a second.
    fractions = (123456789, 987654321, 456789123) if nanosecond else (123456, 654321, 456789)

    # frame 1: an ICMP echo request, 74 octets on the wire
    echo = (Ether(src='00:0c:29:19:dc:61', dst='00:0c:29:7d:1d:b4')
            / IP(src='10.20.30.131', dst='10.20.30.130', ttl=64, id=0x4e21)
            / ICMP(type=8, id=0x3f21, seq=1)
            / Raw(load=_filler(32, b'endian-echo')))

    # frame 2: a small UDP datagram, 66 octets on the wire
    datagram = (Ether(src='00:0c:29:19:dc:61', dst='00:0c:29:7d:1d:b4')
                / IP(src='10.20.30.131', dst='10.20.30.130', ttl=64, id=0x4e22)
                / UDP(sport=41234, dport=9000)
                / Raw(load=_filler(24, b'endian-datagram')))

    # frame 3: a 1200-octet datagram, cut to SNAPLEN by the snapshot limit
    bulk = (Ether(src='00:0c:29:19:dc:61', dst='00:0c:29:7d:1d:b4')
            / IP(src='10.20.30.131', dst='10.20.30.130', ttl=64, id=0x4e23)
            / UDP(sport=41234, dport=9000)
            / Raw(load=_filler(1158, b'endian-bulk')))

    frames = [bytes(echo), bytes(datagram), bytes(bulk)]
    if [len(frame) for frame in frames] != [74, 66, 1200]:
        raise RuntimeError(f'unexpected frame lengths: {[len(frame) for frame in frames]}')

    return [
        _Record(EPOCH, fractions[0], len(frames[0]), frames[0]),
        _Record(EPOCH + 1, fractions[1], len(frames[1]), frames[1]),
        _Record(EPOCH + 2, fractions[2], len(frames[2]), frames[2][:SNAPLEN]),
    ]


def _pack(byteorder: 'Literal["big", "little"]', nanosecond: 'bool',
          entries: 'list[_Record]') -> 'bytes':
    """Pack a whole capture file, global header and records.

    Args:
        byteorder: Byte order to write every 32-bit field in.
        nanosecond: Whether to declare nanosecond-resolution timestamps, which
            is a property of the magic number rather than of the records.
        entries: The records to write, in capture order.

    Returns:
        The file's octets.

    """
    endian = '>' if byteorder == 'big' else '<'

    out = bytearray(MAGIC_NUMBER[(byteorder, nanosecond)])
    out += struct.pack(f'{endian}HHiIII', VERSION[0], VERSION[1], 0, 0, SNAPLEN, NETWORK)

    for entry in entries:
        out += struct.pack(f'{endian}IIII', entry.ts_sec, entry.ts_usec,
                           len(entry.packet), entry.orig_len)
        out += entry.packet

    return bytes(out)


def generate(dest: 'pathlib.Path | None' = None) -> 'list[pathlib.Path]':
    """Write the byte-order ``.pcap`` sample fixtures.

    Args:
        dest: Destination directory; ``examples/captures/`` under the repository
            root, if not given. Created if it does not exist.

    Returns:
        The paths written, in the order they were written.

    """
    dest = SAMPLE if dest is None else pathlib.Path(dest)
    dest.mkdir(parents=True, exist_ok=True)

    written = []  # type: list[pathlib.Path]
    for name, byteorder, nanosecond in FIXTURES:
        path = dest / name
        path.write_bytes(_pack(byteorder, nanosecond, _records(nanosecond)))
        written.append(path)

    return written


if __name__ == '__main__':
    for sample in generate():
        data = sample.read_bytes()
        print('%-32s %6d octets  magic %s' % (
            sample.relative_to(ROOT), len(data), data[:4].hex(' ')))
