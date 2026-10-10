# -*- coding: utf-8 -*-
"""The scapy engine takes a packet's link type and clock from its interface.

Three things :class:`scapy.utils.PcapNgReader` reads differently from the
default engine, all fixed in the reader subclass of
:mod:`pcapkit.foundation.engines.scapy`:

* #1503 -- a Simple Packet Block carries no timestamp. Scapy leaves the packet
  with the time it was built, i.e. the moment it was read; the default engine
  reads 0.
* #1517 -- the flow tracer looked the link type up by the name of the packet's
  first layer, and a raw IPv4 packet's is ``IP``, which names no link type, so
  tracing raised :exc:`~pcapkit.utilities.exceptions.MissingKeyError`.
* #1549 -- Scapy ignores an interface's ``if_tsoffset``, so each timestamp on it
  was short by the offset.

The captures are synthesised from :file:`tcp.pcap`, whose frames 1, 2, 6 and 7
are one IPv4 flow and 3, 4 and 5 one IPv6 flow, so the module belongs to the
fixture-dependent tier.

"""
from __future__ import annotations

import decimal
import importlib.util
import os
import struct
import tempfile
import unittest
import warnings

from tests._support import close_extractor, reimport_once_per_class, sample_path

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))
HAS_SCAPY = importlib.util.find_spec('scapy') is not None

#: ``LINKTYPE_ETHERNET`` and ``LINKTYPE_IPV4``.
ETHERNET, IPV4 = 1, 228

#: Frame numbers of :file:`tcp.pcap`'s two flows, as the default engine traces them.
FLOWS = [(1, 2, 6, 7), (3, 4, 5)]


def _block(order: 'str', kind: 'int', body: 'bytes') -> 'bytes':
    body += bytes(-len(body) % 4)
    length = len(body) + 12
    return struct.pack(f'{order}II', kind, length) + body + struct.pack(f'{order}I', length)


def _shb(order: 'str' = '<') -> 'bytes':
    return _block(order, 0x0A0D0D0A, struct.pack(f'{order}IHHq', 0x1A2B3C4D, 1, 0, -1))


def _idb(linktype: 'int', *, order: 'str' = '<', tsresol: 'int | None' = None,
         tsoffset: 'int | None' = None) -> 'bytes':
    options = b''
    if tsresol is not None:
        options += struct.pack(f'{order}HHB', 9, 1, tsresol) + bytes(3)
    if tsoffset is not None:
        options += struct.pack(f'{order}HHq', 14, 8, tsoffset)
    if options:
        options += struct.pack(f'{order}HH', 0, 0)
    return _block(order, 1, struct.pack(f'{order}HHI', linktype, 0, 0x40000) + options)


def _epb(interface: 'int', ticks: 'int', orig_len: 'int', octets: 'bytes', *,
         order: 'str' = '<') -> 'bytes':
    return _block(order, 6, struct.pack(f'{order}IIIII', interface, ticks >> 32, ticks & 0xFFFF_FFFF,
                                        len(octets), orig_len) + octets)


def _pkt(interface: 'int', ticks: 'int', orig_len: 'int', octets: 'bytes', *,
         order: 'str' = '<') -> 'bytes':
    """An obsolete Packet Block, which names its interface in 16 bits."""
    return _block(order, 2, struct.pack(f'{order}HHIIII', interface, 0, ticks >> 32, ticks & 0xFFFF_FFFF,
                                        len(octets), orig_len) + octets)


def _spb(orig_len: 'int', octets: 'bytes') -> 'bytes':
    return _block('<', 3, struct.pack('<I', orig_len) + octets)


def _records() -> 'list[tuple[int, int, int, bytes]]':
    """``(ts_sec, ts_usec, orig_len, octets)`` of each record of :file:`tcp.pcap`."""
    with open(sample_path('tcp.pcap'), 'rb') as file:
        rest = file.read()[24:]
    records = []
    while rest:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', rest[:16])
        records.append((ts_sec, ts_usec, orig_len, rest[16:16 + incl_len]))
        rest = rest[16 + incl_len:]
    return records


def _is_ipv4(octets: 'bytes') -> 'bool':
    return octets[12:14] == b'\x08\x00'


@unittest.skipUnless(HAS_RUNTIME and HAS_SCAPY, 'runtime dependencies or scapy not installed')
class ScapyReaderInterfaceTests(unittest.TestCase):
    """The scapy engine reads what the default engine reads, block for block."""

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

    def _extract(self, fin: 'str', engine: 'str', **kwargs: 'object'):  # type: ignore[no-untyped-def]
        from pcapkit import extract

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=fin, engine=engine, nofile=True, **kwargs)
        self.addCleanup(close_extractor, extractor)
        return extractor

    def _timestamps(self, fin: 'str') -> 'tuple[list, list]':
        """Each frame's timestamp, from the default engine and from Scapy's ``Packet.time``."""
        default = self._extract(fin, 'default', store=True)
        scapy = self._extract(fin, 'scapy', store=True)
        return ([frame.info.timestamp_epoch for frame in default.frame],
                [packet.time for packet in scapy.frame])

    def _assert_traces_agree(self, fin: 'str') -> 'list[tuple[str, tuple, bytes]]':
        """Trace both engines as PCAP and as JSON; return the default engine's PCAP flows."""
        result = []  # type: list[tuple[str, tuple, bytes]]
        for trace_format in ('pcap', 'json'):
            for nanosecond in (False, True):
                with self.subTest(trace_format=trace_format, nanosecond=nanosecond):
                    flows = {}
                    for engine in ('default', 'scapy'):
                        extractor = self._extract(fin, engine, tcp=True, trace=True, trace_format=trace_format,
                                                  trace_fout=tempfile.mkdtemp(dir=self.tmp),
                                                  trace_nanosecond=nanosecond)
                        flows[engine] = []
                        for flow in extractor.trace.tcp:
                            with open(flow.fpout, 'rb') as file:
                                flows[engine].append((flow.label, tuple(flow.index), file.read()))
                    self.assertEqual([index for _, index, _ in flows['default']], FLOWS)
                    if trace_format == 'pcap':
                        self.assertEqual(flows['scapy'], flows['default'])
                        if not nanosecond:
                            result = flows['default']
                    else:
                        # the JSON files hold each engine's own frame mapping
                        self.assertEqual([flow[:2] for flow in flows['scapy']],
                                         [flow[:2] for flow in flows['default']])
        return result

    def test_a_simple_packet_block_is_dated_0(self) -> None:
        # #1503: tcp.pcap with frame 4, of the IPv6 flow, as a Simple Packet Block
        blocks = [_shb(), _idb(ETHERNET)]
        for number, (ts_sec, ts_usec, orig_len, octets) in enumerate(_records(), 1):
            blocks.append(_spb(orig_len, octets) if number == 4 else
                          _epb(0, ts_sec * 10**6 + ts_usec, orig_len, octets))
        fin = self._write('spb.pcapng', b''.join(blocks))

        default, scapy = self._timestamps(fin)
        self.assertEqual(default[3], 0)
        self.assertEqual(scapy, default)

        # and so does every adapter that reads the packet's time
        from pcapkit.toolkit.scapy import packet2frame, tcp_reassembly, tcp_traceflow

        packet = self._extract(fin, 'scapy', store=True).frame[3]
        self.assertEqual(tcp_reassembly(packet).timestamp, 0)  # type: ignore[union-attr]
        self.assertEqual(tcp_traceflow(packet).timestamp, 0)  # type: ignore[union-attr]
        record = packet2frame(packet)
        self.assertEqual((record.frame_info.ts_sec, record.frame_info.ts_usec, record.time_epoch), (0, 0, 0))

        flows = self._assert_traces_agree(fin)
        # the IPv6 flow's second record is frame 4, at 0 s and 0 us
        _, _, data = flows[1]
        offset = 24 + 16 + struct.unpack_from('<I', data, 24 + 8)[0]
        self.assertEqual(struct.unpack_from('<II', data, offset), (0, 0))

    def test_an_interface_with_if_tsoffset_adds_it(self) -> None:
        # #1549: two sections of opposite byte order; in each, an interface with
        # an offset, one with a negative one and one with none
        records = _records()
        ipv4 = records[0][3][14:]
        expected = []  # type: list[decimal.Decimal]
        blocks = []
        for order in ('<', '>'):
            blocks.append(_shb(order))
            blocks.append(_idb(ETHERNET, order=order))
            blocks.append(_idb(IPV4, order=order, tsresol=0x8A, tsoffset=100))   # 2^-10 s, +100 s
            blocks.append(_idb(ETHERNET, order=order, tsoffset=-1_000_000))
            ts_sec, ts_usec, orig_len, octets = records[0]
            ticks = ts_sec * 10**6 + ts_usec
            ticks_bin = (ts_sec << 10) + 123
            blocks.extend([
                _epb(0, ticks, orig_len, octets, order=order),
                _epb(1, ticks_bin, len(ipv4), ipv4, order=order),
                _epb(2, ticks, orig_len, octets, order=order),
                # an obsolete Packet Block names its interface in 16 bits
                _pkt(1, ticks_bin, len(ipv4), ipv4, order=order),
                _pkt(2, ticks, orig_len, octets, order=order),
            ])
            micro = decimal.Decimal(ticks).scaleb(-6)
            binary = decimal.Decimal(ticks_bin) / 1024 + 100
            expected.extend([micro, binary, micro - 1_000_000, binary, micro - 1_000_000])
        fin = self._write('tsoffset.pcapng', b''.join(blocks))

        default, scapy = self._timestamps(fin)
        self.assertEqual(default, expected)
        self.assertEqual(scapy, default)

    def test_the_issues_tsoffset_value(self) -> None:
        # #1549, as reported: 2^-10 s ticks plus 100 s, in a big-endian section
        # after a little-endian one
        ticks = 1_500_000_000_000_123
        _, _, orig_len, octets = _records()[0]
        fin = self._write('issue.pcapng', b''.join([
            _shb('<'), _idb(ETHERNET), _epb(0, ticks, orig_len, octets),
            _shb('>'), _idb(IPV4, order='>', tsresol=0x8A, tsoffset=100),
            _epb(0, ticks, orig_len - 14, octets[14:], order='>'),
        ]))
        default, scapy = self._timestamps(fin)
        self.assertEqual(default[1], decimal.Decimal('1464843750100.1201171875'))
        self.assertEqual(scapy, default)

    def test_a_raw_ipv4_interface_traces_by_its_link_type(self) -> None:
        # #1517: tcp.pcap with its IPv4 frames on a LINKTYPE_IPV4 interface
        blocks = [_shb(), _idb(ETHERNET), _idb(IPV4)]
        for ts_sec, ts_usec, orig_len, octets in _records():
            interface = 0
            if _is_ipv4(octets):
                interface, octets, orig_len = 1, octets[14:], orig_len - 14
            blocks.append(_epb(interface, ts_sec * 10**6 + ts_usec, orig_len, octets))
        fin = self._write('raw.pcapng', b''.join(blocks))

        flows = self._assert_traces_agree(fin)
        self.assertEqual([struct.unpack_from('<I', data, 20)[0] for _, _, data in flows], [IPV4, ETHERNET])

    def test_a_raw_ipv4_pcap_traces_by_its_link_type(self) -> None:
        # #1517, in a PCAP: the global header's link type, for its IPv4 frames only
        with open(sample_path('tcp.pcap'), 'rb') as file:
            header = file.read(24)
        out = [header[:20] + struct.pack('<I', IPV4)]
        for ts_sec, ts_usec, orig_len, octets in _records():
            if _is_ipv4(octets):
                out.append(struct.pack('<IIII', ts_sec, ts_usec, len(octets) - 14, orig_len - 14) + octets[14:])
        fin = self._write('raw.pcap', b''.join(out))

        flows = {}
        for engine in ('default', 'scapy'):
            extractor = self._extract(fin, engine, tcp=True, trace=True, trace_format='pcap',
                                      trace_fout=tempfile.mkdtemp(dir=self.tmp))
            flows[engine] = []
            for flow in extractor.trace.tcp:
                with open(flow.fpout, 'rb') as file:
                    flows[engine].append((flow.label, tuple(flow.index), file.read()))
        self.assertEqual([index for _, index, _ in flows['default']], [(1, 2, 3, 4)])
        self.assertEqual(struct.unpack_from('<I', flows['default'][0][2], 20)[0], IPV4)
        self.assertEqual(flows['scapy'], flows['default'])


if __name__ == '__main__':
    unittest.main()
