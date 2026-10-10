# -*- coding: utf-8 -*-
"""The default engine's TCP adapters read a TCP header the parser rejected (#1518).

A capture snapped inside the TCP header leaves a Data Offset running past the
captured octets, and the TCP parser rejects such a header by design (#1404), so
the segment arrives as ``Raw``. The flow tracing and reassembly adapters of
:mod:`pcapkit.toolkit.pcap` and :mod:`pcapkit.toolkit.pcapng` used to skip it;
they now take the ports, numbers and flags from the fixed 20-octet header, as
:mod:`dpkt`, :mod:`scapy` and Wireshark do.

Every frame is built here, written as PCAP and as PCAP-NG, and read back through
the default engine, so the adapters see the frames a capture produces. The
module reads no sample capture, so it belongs to the unit tier;
:mod:`tests.foundation.traceflow.test_traceflow_snapped_capture_runtime` covers
the snapped ``tcp.pcap`` of the issue.

"""
from __future__ import annotations

import importlib.util
import io
import struct
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import close_extractor, reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

ETH_IPV4 = b'\xbb' * 6 + b'\xaa' * 6 + b'\x08\x00'
ETH_IPV6 = b'\xbb' * 6 + b'\xaa' * 6 + b'\x86\xdd'

#: MSS, NOP, Window Scale, NOP, NOP and SACK Permitted: twelve octets, so a
#: 32-octet header.
OPTIONS = bytes.fromhex('020405b4' '01030306' '01010402')


def tcp(*, words: 'int' = 8, options: 'bytes' = OPTIONS, payload: 'bytes' = b'',
        flags: 'int' = 0x12) -> 'bytes':
    """A TCP segment from port 1234 to 80, ``seq`` 1000 and ``ack`` 2000."""
    return struct.pack('!HHIIBBHHH', 1234, 80, 1000, 2000, words << 4, flags, 65535, 0, 0) + options + payload


def ipv4(segment: 'bytes', *, offset: 'int' = 0, mf: 'bool' = False, protocol: 'int' = 6) -> 'bytes':
    """An Ethernet frame of IPv4 carrying ``segment`` as ``protocol``, TCP by
    default, at fragment ``offset`` octets."""
    fragment = (0x2000 if mf else 0) | offset // 8
    return ETH_IPV4 + struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(segment), 1, fragment, 64, protocol, 0,
                                  bytes([192, 0, 2, 1]), bytes([198, 51, 100, 1])) + segment


def ipv6(segment: 'bytes', *, fragment: 'tuple[int, bool] | None' = None) -> 'bytes':
    """An Ethernet frame of IPv6 carrying ``segment`` as TCP, behind a Fragment
    header of ``(offset, M flag)`` if given."""
    next_header = 6
    if fragment is not None:
        segment = struct.pack('!BBHI', 6, 0, fragment[0] // 8 << 3 | fragment[1], 99) + segment
        next_header = 44
    return ETH_IPV6 + struct.pack('!IHBB16s16s', 6 << 28, len(segment), next_header, 64,
                                  bytes.fromhex('20010db8' + '00' * 11 + '01'),
                                  bytes.fromhex('20010db8' + '00' * 11 + '02')) + segment


def whole(frame: 'bytes') -> 'tuple[bytes, int]':
    """``frame`` captured in full, and its original length."""
    return frame, len(frame)


def snap(frame: 'bytes', cut: 'int' = 4) -> 'tuple[bytes, int]':
    """``frame`` with its last ``cut`` octets left uncaptured, and its original length."""
    return frame[:len(frame) - cut], len(frame)


def pcap(octets: 'bytes', orig_len: 'int') -> 'bytes':
    """A little-endian microsecond Ethernet PCAP holding the one record."""
    return (struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFF, 1)
            + struct.pack('<IIII', 1500000000, 774, len(octets), orig_len) + octets)


def _block(block_type: 'int', body: 'bytes') -> 'bytes':
    body += b'\x00' * (-len(body) % 4)
    return struct.pack('<II', block_type, len(body) + 12) + body + struct.pack('<I', len(body) + 12)


def pcapng(octets: 'bytes', orig_len: 'int') -> 'bytes':
    """A little-endian PCAP-NG holding the one record, on an Ethernet interface."""
    ticks = 1500000000 * 10 ** 6 + 774
    return (_block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
            + _block(1, struct.pack('<HHI', 1, 0, 0xFFFF))
            + _block(6, struct.pack('<IIIII', 0, ticks >> 32, ticks & 0xFFFFFFFF, len(octets), orig_len) + octets))


#: SYN, as :func:`tcp` sets it by default with ACK, as ``(SYN, FIN, RST)``.
SYN = (True, False, False)

#: The record each adapter reports for a header TCP rejected, as
#: ``(header length, payload, (SYN, FIN, RST))``; the ports and numbers are
#: those :func:`tcp` writes.
DECODED = {
    'header cut by the snapshot': (snap(ipv4(tcp())), (28, b'', SYN)),
    'header cut, IPv6': (snap(ipv6(tcp())), (28, b'', SYN)),
    'header cut, first fragment': (snap(ipv4(tcp(), mf=True)), (28, b'', SYN)),
    'header cut, IPv6 first fragment': (snap(ipv6(tcp(), fragment=(0, True))), (28, b'', SYN)),
    # MSS with a length of 10, running past a 24-octet header: the header is
    # whole, so the payload after it is the segment's own
    'malformed option': (whole(ipv4(tcp(words=6, options=bytes.fromhex('020a0000'), payload=b'hello'))),
                         (24, b'hello', SYN)),
    # RST with ACK, then FIN with RST and ACK: each flag is read from its own bit
    'header cut, RST': (snap(ipv4(tcp(flags=0x14))), (28, b'', (False, False, True))),
    'header cut, FIN and RST': (snap(ipv4(tcp(flags=0x15))), (28, b'', (False, True, True))),
}

#: Frames the adapters still report nothing for, though their IP payload is a
#: ``Raw`` its parser rejected.
SKIPPED = {
    # 19 octets is short of even the fixed header
    'fewer than 20 octets': snap(ipv4(tcp()), 13),
    # a Data Offset of 4 declares a header shorter than the fixed one
    'data offset below 5': whole(ipv4(tcp(words=4, options=b'', payload=b'abcd'))),
    # a later fragment starts mid-datagram, so its first octets are no header
    'later fragment': whole(ipv4(tcp(words=15, options=b''), offset=8)),
    'IPv6 later fragment': whole(ipv6(tcp(words=15, options=b''), fragment=(8, False))),
    # IPv4 in IPv4, the inner header rejected: 30 octets whose 13th reads as a
    # Data Offset of 5, so only the protocol says it is no TCP segment
    'IPv4 in IPv4': whole(ipv4(bytes(12) + b'\x50' + bytes(17), protocol=4)),
}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TCPSegmentAdapterTests(unittest.TestCase):
    """The PCAP and PCAP-NG adapters take the frames TCP rejected, and only those."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _records(self, capture: 'bytes', **kwargs: 'Any') -> 'tuple[Any, Any, Any]':
        """``(traced flows, flow tracing record, reassembly record)`` of the one frame."""
        from pcapkit import extract
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import pcap as toolkit_pcap
        from pcapkit.toolkit import pcapng as toolkit_pcapng

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=io.BytesIO(capture), nofile=True, store=True, tcp=True,
                                trace=True, **kwargs)
        self.addCleanup(close_extractor, extractor)
        flows = [tuple(flow.index) for flow in extractor.trace.tcp]
        frame = extractor.frame[-1]
        if capture[:4] == b'\x0a\x0d\x0d\x0a':
            return flows, toolkit_pcapng.tcp_traceflow(frame), toolkit_pcapng.tcp_reassembly(frame)
        return (flows, toolkit_pcap.tcp_traceflow(frame, data_link=LinkType.ETHERNET),
                toolkit_pcap.tcp_reassembly(frame))

    def test_a_rejected_header_is_read_from_the_fixed_header(self) -> None:
        for name, ((octets, orig_len), (hdr_len, payload, flags)) in DECODED.items():
            for container, write in (('pcap', pcap), ('pcapng', pcapng)):
                with self.subTest(case=name, container=container):
                    flows, trace, reasm = self._records(write(octets, orig_len))
                    self.assertEqual(flows, [(1,)])
                    self.assertIsNotNone(trace)
                    self.assertIsNotNone(reasm)
                    assert trace is not None and reasm is not None
                    self.assertEqual((trace.srcport, trace.dstport, trace.seq, trace.ack),
                                     (1234, 80, 1000, 2000))
                    self.assertEqual((trace.syn, trace.fin, trace.rst), flags)
                    # the TCP octets are the frame's last, the header then the payload
                    start = len(octets) - len(payload) - hdr_len
                    self.assertEqual(trace.header, octets[start:start + hdr_len])
                    self.assertEqual(bytes(trace.payload), payload)
                    self.assertEqual((reasm.bufid[1], reasm.bufid[3], reasm.dsn, reasm.ack),
                                     (1234, 80, 1000, 2000))
                    self.assertEqual((reasm.syn, reasm.fin, reasm.rst), flags)
                    self.assertEqual((reasm.header, bytes(reasm.payload)), (trace.header, payload))
                    self.assertEqual((reasm.first, reasm.last, reasm.len),
                                     (1000, 1000 + len(payload) - 1, len(payload)))

    def test_no_tcp_header_is_read_where_there_is_none(self) -> None:
        for name, (octets, orig_len) in SKIPPED.items():
            for container, write in (('pcap', pcap), ('pcapng', pcapng)):
                with self.subTest(case=name, container=container):
                    self.assertEqual(self._records(write(octets, orig_len)), ([], None, None))

    def test_a_dissection_stopped_at_the_internet_layer_traces_nothing(self) -> None:
        # The payload is Raw because the caller asked for no more, not because TCP
        # rejected it, so the adapters leave it alone, as they did before #1518.
        for container, write in (('pcap', pcap), ('pcapng', pcapng)):
            for kwargs in ({'layer': 'Internet'}, {'protocol': 'IPv4'}):
                with self.subTest(container=container, **kwargs):
                    self.assertEqual(self._records(write(*snap(ipv4(tcp()))), **kwargs), ([], None, None))

    def test_a_parsed_segment_is_reported_as_before(self) -> None:
        octets = ipv4(tcp(payload=b'data'))
        for container, write in (('pcap', pcap), ('pcapng', pcapng)):
            with self.subTest(container=container):
                flows, trace, reasm = self._records(write(octets, len(octets)))
                self.assertEqual(flows, [(1,)])
                assert trace is not None and reasm is not None
                self.assertEqual((trace.header, bytes(trace.payload)), (octets[34:66], b'data'))
                self.assertEqual((reasm.header, bytes(reasm.payload), reasm.len), (octets[34:66], b'data', 4))


if __name__ == '__main__':
    unittest.main()
