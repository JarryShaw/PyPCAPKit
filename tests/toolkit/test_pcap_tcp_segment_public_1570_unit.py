# -*- coding: utf-8 -*-
"""``tcp_segment`` and ``TCPSegment`` are public in :mod:`pcapkit.toolkit.pcap`. C.f. #1570.

The helper the TCP adapters of :mod:`pcapkit.toolkit.pcap` and
:mod:`pcapkit.toolkit.pcapng` share was the private ``pcap._tcp_segment``, which
``pcapng`` imported across modules, and its result type was the private
``pcap._TCPSegment``. Under the rulings on #1519 a shared helper becomes public in
the module both callers already import, as ``test_start_line`` did in #1525, so the
two keep their names without the underscore and stay in ``pcap``, which ``pcapng``
already imports. The adapters' end-to-end behaviour is covered by
``tests/toolkit/test_pcap_tcp_segment_unit.py``; these tests pin the public surface
and that both toolkits read the segment through it.

Every frame is built here and read back through the default engine, so the module
reads no sample capture and belongs to the unit tier.

"""
from __future__ import annotations

import importlib.util
import io
import struct
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import close_extractor, reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: An Ethernet frame of IPv4 carrying a 20-octet TCP header, port 1234 to 80,
#: ``seq`` 1000, ``ack`` 2000, SYN and ACK, and the payload ``data``.
FRAME = (b'\xbb' * 6 + b'\xaa' * 6 + b'\x08\x00'
         + struct.pack('!BBHHHBBH4s4s', 0x45, 0, 44, 1, 0, 64, 6, 0,
                       bytes([192, 0, 2, 1]), bytes([198, 51, 100, 1]))
         + struct.pack('!HHIIBBHHH', 1234, 80, 1000, 2000, 5 << 4, 0x12, 65535, 0, 0) + b'data')

#: An Ethernet frame of ARP, which carries no IP layer and so no TCP segment.
ARP = b'\xff' * 6 + b'\xaa' * 6 + b'\x08\x06' + bytes.fromhex('0001080006040001') + bytes(20)

#: The fields of :class:`~pcapkit.toolkit.pcap.TCPSegment`, in order.
FIELDS = ('ip', 'srcport', 'dstport', 'seq', 'ack', 'syn', 'fin', 'rst', 'header', 'payload')


def pcap(octets: 'bytes') -> 'bytes':
    """A little-endian microsecond Ethernet PCAP holding the one record."""
    return (struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFF, 1)
            + struct.pack('<IIII', 1500000000, 774, len(octets), len(octets)) + octets)


def _block(block_type: 'int', body: 'bytes') -> 'bytes':
    body += b'\x00' * (-len(body) % 4)
    return struct.pack('<II', block_type, len(body) + 12) + body + struct.pack('<I', len(body) + 12)


def pcapng(octets: 'bytes') -> 'bytes':
    """A little-endian PCAP-NG holding the one record, on an Ethernet interface."""
    ticks = 1500000000 * 10 ** 6 + 774
    return (_block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
            + _block(1, struct.pack('<HHI', 1, 0, 0xFFFF))
            + _block(6, struct.pack('<IIIII', 0, ticks >> 32, ticks & 0xFFFFFFFF, len(octets), len(octets))
                     + octets))


class _Base(unittest.TestCase):

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _frame(self, capture: 'bytes') -> 'Any':
        """The one frame of ``capture``, read through the default engine."""
        from pcapkit import extract

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=io.BytesIO(capture), nofile=True, store=True)
        self.addCleanup(close_extractor, extractor)
        return extractor.frame[-1]


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestPublicSurface(_Base):

    def test_all(self) -> None:
        from pcapkit.toolkit import pcap

        self.assertEqual(pcap.__all__, ['ipv4_reassembly', 'ipv6_reassembly', 'tcp_reassembly',
                                        'tcp_traceflow', 'tcp_segment', 'TCPSegment'])

    def test_callers_share_the_public_helper(self) -> None:
        from pcapkit.toolkit import pcap, pcapng

        self.assertIs(pcapng.tcp_segment, pcap.tcp_segment)
        for module, name in ((pcap, '_tcp_segment'), (pcap, '_TCPSegment'), (pcapng, '_tcp_segment')):
            with self.subTest(module=module.__name__, name=name):
                self.assertFalse(hasattr(module, name))

    def test_result_type_is_the_public_named_tuple(self) -> None:
        from pcapkit.toolkit.pcap import TCPSegment

        self.assertTrue(issubclass(TCPSegment, tuple))
        self.assertEqual(TCPSegment._fields, FIELDS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestTCPSegment(_Base):

    def test_reads_a_parsed_segment_from_either_container(self) -> None:
        from pcapkit.toolkit.pcap import TCPSegment, tcp_segment

        for container, write in (('pcap', pcap), ('pcapng', pcapng)):
            with self.subTest(container=container):
                segment = tcp_segment(self._frame(write(FRAME)))
                self.assertIsInstance(segment, TCPSegment)
                assert segment is not None
                self.assertEqual((str(segment.ip.src), str(segment.ip.dst)), ('192.0.2.1', '198.51.100.1'))
                self.assertEqual((segment.srcport, segment.dstport, segment.seq, segment.ack),
                                 (1234, 80, 1000, 2000))
                self.assertEqual((segment.syn, segment.fin, segment.rst), (True, False, False))
                self.assertEqual((segment.header, segment.payload), (FRAME[34:54], b'data'))

    def test_no_segment_without_an_ip_layer(self) -> None:
        from pcapkit.toolkit.pcap import tcp_segment

        for container, write in (('pcap', pcap), ('pcapng', pcapng)):
            with self.subTest(container=container):
                self.assertIsNone(tcp_segment(self._frame(write(ARP))))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestAdaptersCallTheHelper(_Base):
    """Each TCP adapter reads the segment through the module-level ``tcp_segment``."""

    def test_both_toolkits_call_tcp_segment(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import pcap as toolkit_pcap
        from pcapkit.toolkit import pcapng as toolkit_pcapng

        pcap_frame = self._frame(pcap(FRAME))
        pcapng_frame = self._frame(pcapng(FRAME))
        cases = (
            ('pcap.tcp_reassembly', toolkit_pcap, pcap_frame, toolkit_pcap.tcp_reassembly, {}),
            ('pcap.tcp_traceflow', toolkit_pcap, pcap_frame, toolkit_pcap.tcp_traceflow,
             {'data_link': LinkType.ETHERNET}),
            ('pcapng.tcp_reassembly', toolkit_pcapng, pcapng_frame, toolkit_pcapng.tcp_reassembly, {}),
            ('pcapng.tcp_traceflow', toolkit_pcapng, pcapng_frame, toolkit_pcapng.tcp_traceflow, {}),
        )
        for name, module, frame, adapter, kwargs in cases:
            with self.subTest(adapter=name):
                with mock.patch.object(module, 'tcp_segment', wraps=toolkit_pcap.tcp_segment) as helper:
                    record = adapter(frame, **kwargs)
                helper.assert_called_once_with(frame)
                self.assertIsNotNone(record)
                assert record is not None
                self.assertEqual((record.header, bytes(record.payload)), (FRAME[34:54], b'data'))


if __name__ == '__main__':
    unittest.main()
