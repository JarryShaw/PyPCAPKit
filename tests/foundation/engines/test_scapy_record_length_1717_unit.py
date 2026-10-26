# -*- coding: utf-8 -*-
"""The scapy engine hands over each record whole (#1717).

``sniff`` reads a packet with ``recv()``, whose ``size`` defaults to Scapy's
``MTU`` of 65,535 octets, and every Scapy reader cuts a record to ``size`` --
Scapy 2.6's PCAP-NG reader to ``MTU`` whatever the ``size``. Scapy 2.8's PCAP
reader also reads at most ``MTU * 4`` octets of a record, 262,140, and skips
the rest. So, without the fix, a record longer than either reaches the
engine's frames short.
The reader subclass of :mod:`pcapkit.foundation.engines.scapy` reads it whole.

The captures are synthesised, so the module belongs to the unit tier.

"""
from __future__ import annotations

import importlib.util
import os
import struct
import tempfile
import unittest
import warnings

from tests._support import close_extractor, reimport_once_per_class

#: Test tier (#1958): drives Scapy, whose installable releases vary by interpreter; the
#: integration and pypcap-parity legs install it on every interpreter, and a test leg
#: off latest skips it.
__tier__ = 'ALL'

HAS_SCAPY = importlib.util.find_spec('scapy') is not None
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

#: ``LINKTYPE_ETHERNET``.
ETHERNET = 1

#: Record lengths: under ``MTU``; one over it; libpcap's ``MAXIMUM_SNAPLEN``,
#: over Scapy 2.8's ``MTU * 4``; and one read in more than one chunk.
LENGTHS = (60, 65_536, 262_144, 600_000)


def _frame(length: 'int') -> 'bytes':
    """An Ethernet frame of ``length`` octets, of an EtherType Scapy leaves raw."""
    header = b'\x02' + bytes(5) + b'\x02' + bytes(4) + b'\x01' + b'\x88\xb5'
    body = bytes(range(256)) * (length // 256 + 1)
    return header + body[:length - len(header)]


def _pcap(order: 'str', records: 'list[tuple[bytes, int]]', *, nanosecond: 'bool' = False) -> 'bytes':
    """A PCAP of ``(octets, orig_len)`` records, with a snaplen over all of them."""
    magic = 0xA1B23C4D if nanosecond else 0xA1B2C3D4
    out = [struct.pack(f'{order}IHHiIII', magic, 2, 4, 0, 0, 0x100000, ETHERNET)]
    for number, (octets, orig_len) in enumerate(records, 1):
        out.append(struct.pack(f'{order}IIII', 1_500_000_000 + number, number, len(octets), orig_len) + octets)
    return b''.join(out)


def _block(order: 'str', kind: 'int', body: 'bytes') -> 'bytes':
    body += bytes(-len(body) % 4)
    length = len(body) + 12
    return struct.pack(f'{order}II', kind, length) + body + struct.pack(f'{order}I', length)


def _pcapng(order: 'str', octets: 'bytes') -> 'bytes':
    """A PCAP-NG holding ``octets`` as an Enhanced, an obsolete and a Simple Packet Block."""
    caplen = len(octets)
    return b''.join([
        _block(order, 0x0A0D0D0A, struct.pack(f'{order}IHHq', 0x1A2B3C4D, 1, 0, -1)),
        _block(order, 1, struct.pack(f'{order}HHI', ETHERNET, 0, 0x100000)),
        _block(order, 6, struct.pack(f'{order}IIIII', 0, 0, 1, caplen, caplen) + octets),
        _block(order, 2, struct.pack(f'{order}HHIIII', 0, 0, 0, 2, caplen, caplen) + octets),
        _block(order, 3, struct.pack(f'{order}I', caplen) + octets),
    ])


@unittest.skipUnless(HAS_RUNTIME and HAS_SCAPY, 'runtime dependencies or scapy not installed')
class ScapyRecordLengthTests(unittest.TestCase):
    """Each frame of the scapy engine holds every octet of its record."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name

    def _write(self, name: 'str', data: 'bytes') -> 'str':
        path = os.path.join(self.tmp, name)
        with open(path, 'wb') as file:
            file.write(data)
        return path

    def _frames(self, fin: 'str') -> 'list[tuple[bytes, int | None]]':
        """The octets and the original length of each frame of the scapy engine."""
        from scapy.packet import Packet

        from pcapkit import extract

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=fin, engine='scapy', nofile=True, store=True)
        self.addCleanup(close_extractor, extractor)
        frames = []  # type: list[tuple[bytes, int | None]]
        for packet in extractor.frame:
            if not isinstance(packet, Packet):
                self.fail(f'not a Scapy packet: {packet!r}')
            frames.append((bytes(packet.original), packet.wirelen))
        return frames

    def test_a_pcap_record_is_read_whole(self) -> None:
        records = [(_frame(length), length) for length in LENGTHS]
        for order in ('<', '>'):
            for nanosecond in (False, True):
                with self.subTest(order=order, nanosecond=nanosecond):
                    fin = self._write(f'whole-{ord(order)}-{nanosecond}.pcap',
                                      _pcap(order, records, nanosecond=nanosecond))
                    frames = self._frames(fin)
                    self.assertEqual([len(octets) for octets, _ in frames], list(LENGTHS))
                    self.assertEqual(frames, records)

    def test_a_record_the_file_ends_inside_keeps_what_it_holds(self) -> None:
        # declared 300,000 octets long, of which the file holds 270,000
        octets = _frame(300_000)
        data = _pcap('<', [(_frame(60), 60), (octets, 300_000)])
        fin = self._write('cut.pcap', data[:-30_000])
        self.assertEqual(self._frames(fin), [(_frame(60), 60), (octets[:270_000], 300_000)])

    def test_a_pcapng_packet_block_is_read_whole(self) -> None:
        octets = _frame(70_000)
        for order in ('<', '>'):
            with self.subTest(order=order):
                fin = self._write(f'whole-{ord(order)}.pcapng', _pcapng(order, octets))
                self.assertEqual(self._frames(fin), [(octets, 70_000)] * 3)

    def test_an_explicit_size_still_cuts_a_pcap_record(self) -> None:
        # the PCAP reader's own; Scapy 2.6 reads a PCAP-NG block at ``MTU``,
        # and so the engine's at its default, whatever ``size`` is passed
        from pcapkit.foundation.engines.scapy import _reader_type

        octets = _frame(70_000)
        reader = _reader_type()(self._write('size.pcap', _pcap('<', [(octets, 70_000)] * 2)))
        self.addCleanup(reader.close)
        self.assertEqual(bytes(reader.recv(100).original), octets[:100])
        self.assertEqual(bytes(reader.recv().original), octets)


if __name__ == '__main__':
    unittest.main()
