# -*- coding: utf-8 -*-
"""A TSO capture reassembles to the same IPv4 datagrams as the unmodified one.

GitHub issue #1555. With the four IPv4 frames of :file:`tcp.pcap` given Total
Length 0, as TCP segmentation offload leaves them, ``extract(ipv4=True,
reassembly=True)`` reported four ``PARTIAL`` datagrams with no payload under
every engine, against four ``COMPLETE`` ones of 44, 32, 244 and 32 octets on
the unmodified capture: the reassembler took the data length from ``tl - ihl``.
Wireshark does not reassemble such a frame at all -- it is one segment -- so the
expected result is the unmodified capture's, the zeroed header aside.

A two-fragment UDP datagram with the Total Length of one fragment zeroed is
read the way Wireshark 4.6.9 reads it, as that fragment's captured length.

The captures are built in memory, the TSO one from a generated sample, so the
module belongs to the fixture-dependent tier.

"""
from __future__ import annotations

import importlib.util
import os
import struct
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import close_extractor, reimport_once_per_class, sample_path

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)
ENGINES = ('default',) + tuple(name for name in ('dpkt', 'scapy') if importlib.util.find_spec(name) is not None)

#: One-based numbers of the IPv4 frames of ``tcp.pcap``; the rest are IPv6.
IPV4_FRAMES = (1, 2, 6, 7)

#: A libpcap global header: little-endian, version 2.4, snaplen 65535, Ethernet.
PCAP_HEADER = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def _checksum(header: 'bytes') -> 'bytes':
    """RFC 1071 Internet checksum of ``header``, its checksum field zeroed."""
    total = sum(struct.unpack(f'!{len(header) // 2}H', header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return struct.pack('!H', ~total & 0xFFFF)


def _with_total_length(frame: 'bytes', total_length: 'int', *, fix_checksum: 'bool') -> 'bytes':
    """``frame``, an Ethernet frame carrying an option-less IPv4 header, with the given Total Length."""
    header = bytearray(frame[14:34])
    header[2:4] = struct.pack('!H', total_length)
    if fix_checksum:
        header[10:12] = b'\x00\x00'
        header[10:12] = _checksum(bytes(header))
    return frame[:14] + bytes(header) + frame[34:]


def _tso_capture(*, fix_checksum: 'bool') -> 'bytes':
    """``tcp.pcap`` with every IPv4 frame's Total Length zeroed."""
    with open(sample_path('tcp.pcap'), 'rb') as file:
        source = file.read()
    output, rest, number = bytearray(source[:24]), source[24:], 0
    while rest:
        number += 1
        record, incl_len = rest[:16], struct.unpack('<I', rest[8:12])[0]
        frame = rest[16:16 + incl_len]
        if number in IPV4_FRAMES:
            frame = _with_total_length(frame, 0, fix_checksum=fix_checksum)
        output += record + frame
        rest = rest[16 + incl_len:]
    return bytes(output)


def _fragment_capture(zeroed: 'int') -> 'tuple[bytes, bytes]':
    """A UDP datagram in two fragments, fragment ``zeroed`` with Total Length 0.

    Returns:
        The capture, and the datagram's payload (UDP header and data).

    """
    data = (bytes(range(1, 256)) * 2)[:96]
    payload = struct.pack('!HHHH', 1111, 2222, 8 + len(data), 0) + data
    ether = bytes.fromhex('020000000002 020000000001 0800')  # destination, source, IPv4
    output = bytearray(PCAP_HEADER)
    for index, (offset, more, chunk) in enumerate(((0, 1, payload[:56]), (7, 0, payload[56:]))):
        total_length = 0 if index == zeroed else 20 + len(chunk)
        header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, total_length, 0x1234,
                                       (more << 13) | offset, 64, 17, 0,
                                       bytes((192, 0, 2, 1)), bytes((198, 51, 100, 2))))
        header[10:12] = _checksum(bytes(header))
        frame = ether + bytes(header) + chunk
        output += struct.pack('<IIII', 1000 + index, 0, len(frame), len(frame)) + frame
    return bytes(output), payload


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TSOReassemblyTests(unittest.TestCase):
    """A Total Length of 0 reassembles to the datagram the frame carries, under every engine."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name

    def _write(self, name: 'str', octets: 'bytes') -> 'str':
        path = os.path.join(self.tmp, name)
        with open(path, 'wb') as file:
            file.write(octets)
        return path

    def _extract(self, fin: 'str', engine: 'str', strict: 'bool') -> 'Any':
        from pcapkit import extract

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=fin, nofile=True, engine=engine, ipv4=True,
                                reassembly=True, reasm_strict=strict)
        self.addCleanup(close_extractor, extractor)
        return extractor

    def test_tso_capture_reassembles_like_the_unmodified_one(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion

        for fix_checksum in (True, False):
            octets = _tso_capture(fix_checksum=fix_checksum)
            fin = self._write(f'tso-{fix_checksum}.pcap', octets)
            for engine in ENGINES:
                for strict in (True, False):
                    with self.subTest(engine=engine, strict=strict,
                                      checksum='fixed' if fix_checksum else 'stale'):
                        expected = self._extract(sample_path('tcp.pcap'), engine, strict).reassembly.ipv4
                        actual = self._extract(fin, engine, strict).reassembly.ipv4

                        self.assertEqual([datagram.completed for datagram in actual],
                                         [Completion.COMPLETE] * 4)
                        self.assertEqual([len(datagram.payload) for datagram in actual], [44, 32, 244, 32])
                        self.assertEqual([(datagram.completed, datagram.index, datagram.payload,
                                           datagram.conflict) for datagram in actual],
                                         [(datagram.completed, datagram.index, datagram.payload,
                                           datagram.conflict) for datagram in expected])
                        self.assertEqual([datagram.packet.info.to_dict() for datagram in actual],
                                         [datagram.packet.info.to_dict() for datagram in expected])

                        # the header is the frame's own, Total Length 0 and all
                        self.assertEqual([datagram.header[2:4] for datagram in actual], [b'\x00\x00'] * 4)
                        self.assertEqual([datagram.header[:2] + datagram.header[4:10]
                                          for datagram in actual],
                                         [datagram.header[:2] + datagram.header[4:10]
                                          for datagram in expected])

    def test_a_zero_total_length_fragment_is_reassembled(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion

        for zeroed in (0, 1):
            octets, payload = _fragment_capture(zeroed)
            fin = self._write(f'fragment-{zeroed}.pcap', octets)
            for engine in ENGINES:
                for strict in (True, False):
                    with self.subTest(zeroed=zeroed, engine=engine, strict=strict):
                        datagram, = self._extract(fin, engine, strict).reassembly.ipv4
                        self.assertIs(datagram.completed, Completion.COMPLETE)
                        self.assertEqual(datagram.index, (1, 2))
                        self.assertEqual(datagram.payload, payload)
                        self.assertEqual(datagram.header[2:4], b'\x00\x00' if zeroed == 0 else b'\x00\x4c')


if __name__ == '__main__':
    unittest.main()
