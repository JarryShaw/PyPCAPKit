# -*- coding: utf-8 -*-
"""An IPv4 Total Length of 0 is TCP segmentation offload, not a payload of -20.

GitHub issue #1547. A capture taken on a host that offloads TCP segmentation
(TSO/GSO) records its outgoing IPv4 headers with ``total_length`` 0, since the
NIC fills it in later. :meth:`IPv4.read <pcapkit.protocols.internet.ipv4.IPv4.read>`
handed the next layer ``0 - hdr_len`` octets, so TCP fell back to
:class:`~pcapkit.protocols.misc.raw.Raw` and the flow was never traced. A Total
Length of 0 now means the rest of the captured frame, with no trailer, as dpkt
(``ip.py``) and Wireshark ("presumed TSO") read it, and the rebuild writes the 0
back. Following the owner's ruling to match Wireshark, any other Total Length
shorter than the header is a "Bogus IP length": no payload layer, the octets
after the header kept as the trailer, and the length written back as it was.

The cases are built in memory from :file:`tcp.pcap` with its four IPv4 frames'
Total Length zeroed, once with the header checksum fixed and once left stale,
since a TSO capture may show either. The module reads a generated sample, so it
belongs to the fixture-dependent tier.

"""
from __future__ import annotations

import importlib.util
import os
import struct
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import close_extractor, reimport_once_per_class, sample_path

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)
ENGINES = tuple(name for name in ('dpkt', 'scapy') if importlib.util.find_spec(name) is not None)

#: One-based numbers of the IPv4 frames of ``tcp.pcap``; the rest are IPv6.
IPV4_FRAMES = (1, 2, 6, 7)

#: The flows every engine traces in ``tcp.pcap``, TSO or not.
FLOWS = [(1, 2, 6, 7), (3, 4, 5)]


def _checksum(header: 'bytes') -> 'bytes':
    """RFC 1071 Internet checksum of ``header``, its checksum field zeroed."""
    total = sum(struct.unpack(f'!{len(header) // 2}H', header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return struct.pack('!H', ~total & 0xFFFF)


def _records() -> 'tuple[bytes, list[list[Any]]]':
    """``tcp.pcap``'s global header and ``[ts_sec, ts_usec, orig_len, octets]`` records."""
    with open(sample_path('tcp.pcap'), 'rb') as file:
        source = file.read()
    header, rest, records = source[:24], source[24:], []
    while rest:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', rest[:16])
        records.append([ts_sec, ts_usec, orig_len, rest[16:16 + incl_len]])
        rest = rest[16 + incl_len:]
    return header, records


def _with_total_length(frame: 'bytes', total_length: 'int', *, fix_checksum: 'bool') -> 'bytes':
    """``frame``, an Ethernet frame carrying IPv4, with the given Total Length."""
    header = bytearray(frame[14:34])
    header[2:4] = struct.pack('!H', total_length)
    if fix_checksum:
        header[10:12] = b'\x00\x00'
        header[10:12] = _checksum(bytes(header))
    return frame[:14] + bytes(header) + frame[34:]


def _tso_records(*, fix_checksum: 'bool') -> 'tuple[bytes, list[list[Any]]]':
    """``tcp.pcap`` with every IPv4 frame's Total Length zeroed."""
    header, records = _records()
    for number in IPV4_FRAMES:
        records[number - 1][3] = _with_total_length(records[number - 1][3], 0, fix_checksum=fix_checksum)
    return header, records


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TSOTotalLengthTests(unittest.TestCase):
    """A zero Total Length reads the rest of the frame and is written back as 0."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _parse(self, octets: 'bytes') -> 'Any':
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.utilities.warnings import SchemaWarning

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            parsed = Ethernet(octets, len(octets))
        self.assertEqual([str(w.message) for w in caught if issubclass(w.category, SchemaWarning)], [])
        return parsed

    def test_tcp_is_parsed_and_every_rebuild_is_byte_exact(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.protocols.transport.tcp import TCP

        _, original = _records()
        for fix_checksum in (True, False):
            _, records = _tso_records(fix_checksum=fix_checksum)
            for number in IPV4_FRAMES:
                with self.subTest(frame=number, checksum='fixed' if fix_checksum else 'stale'):
                    octets = records[number - 1][3]
                    parsed = self._parse(octets)
                    ipv4 = parsed.payload

                    self.assertIsInstance(ipv4, IPv4)
                    self.assertIsInstance(ipv4.payload, TCP)
                    self.assertEqual(ipv4.info.len, 0)
                    self.assertNotIn('trailer', ipv4.info)
                    self.assertEqual(ipv4.info.checksum, octets[24:26])
                    self.assertEqual(ipv4.payload.data, octets[34:])

                    # The same TCP header the frame carries with its real length.
                    expected = self._parse(original[number - 1][3]).payload.payload
                    self.assertEqual(ipv4.payload.info.to_dict(), expected.info.to_dict())

                    # parse -> rebuild, from the info object and from its dict
                    self.assertEqual(Ethernet.from_data(parsed.info).data, octets)
                    self.assertEqual(Ethernet.from_data(parsed.info.to_dict()).data, octets)
                    self.assertEqual(IPv4.from_data(ipv4.info).data, octets[14:])
                    self.assertEqual(IPv4.from_data(ipv4.info.to_dict()).data, octets[14:])

        first = self._parse(_tso_records(fix_checksum=True)[1][0][3]).payload.payload.info
        self.assertEqual((first.srcport.port, first.dstport.port), (22, 53406))

    def test_make_with_a_zero_total_length_round_trips(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.transport.tcp import TCP

        segment = _records()[1][0][3][34:]
        made = IPv4(total_length=0, protocol='TCP', ttl=64, src='10.20.30.130', dst='10.20.30.131',
                    payload=segment)
        self.assertEqual(made.data[2:4], b'\x00\x00')
        self.assertEqual(made.data[20:], segment)

        parsed = IPv4(made.data, len(made.data))
        self.assertIsInstance(parsed.payload, TCP)
        self.assertEqual(parsed.info.len, 0)
        self.assertEqual(IPv4.from_data(parsed.info).data, made.data)
        self.assertEqual(IPv4.from_data(parsed.info.to_dict()).data, made.data)

        # Without an explicit Total Length it is computed, as before.
        computed = IPv4(protocol='TCP', payload=segment)
        self.assertEqual(struct.unpack('!H', computed.data[2:4])[0], 20 + len(segment))

    def test_schema_splits_payload_and_trailer(self) -> None:
        from pcapkit.protocols.schema.internet.ipv4 import IPv4 as Schema_IPv4

        frame = _records()[1][0][3]
        # 0 is TSO: the rest is payload. 1 to 19 are bogus: the rest is trailer.
        for total_length, payload in ((0, frame[34:]), (1, b''), (10, b''), (19, b'')):
            with self.subTest(total_length=total_length):
                octets = _with_total_length(frame, total_length, fix_checksum=True)[14:]
                schema = Schema_IPv4.unpack(octets)
                self.assertEqual(schema.length, total_length)
                self.assertEqual(schema.payload, payload)
                self.assertEqual(schema.payload + schema.trailer, octets[20:])
                self.assertEqual(schema.pack(), octets)

    def test_a_bogus_total_length_is_not_dissected_further(self) -> None:
        # A non-zero Total Length shorter than the header is not TSO: Wireshark
        # 4.6.9 reports "Total Length: 10 bytes (bogus, less than header length
        # 20)" with the expert note "Bogus IP length", and its protocol list
        # stops at ``eth:ethertype:ip``. So no payload layer is parsed from it,
        # no negative length reaches one, the octets after the header are kept
        # as the trailer, and the Total Length is written back as it was.
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.protocols.misc.null import NoPayload

        frame = _records()[1][0][3]
        lengths: 'list[int]' = []
        decode = IPv4._decode_next_layer

        def spy(self: 'Any', dict_: 'Any', proto: 'Any', length: 'Any' = None, **kwargs: 'Any') -> 'Any':
            lengths.append(length)
            return decode(self, dict_, proto, length, **kwargs)

        for total_length in (1, 10, 19):
            for fix_checksum in (True, False):
                with self.subTest(total_length=total_length, checksum='fixed' if fix_checksum else 'stale'):
                    octets = _with_total_length(frame, total_length, fix_checksum=fix_checksum)
                    lengths.clear()
                    with mock.patch.object(IPv4, '_decode_next_layer', spy):
                        parsed = self._parse(octets)
                    ipv4 = parsed.payload

                    self.assertEqual(lengths, [0])
                    self.assertIsInstance(ipv4.payload, NoPayload)
                    self.assertEqual(str(parsed.protochain), 'Ethernet:IPv4')
                    self.assertEqual(ipv4.info.len, total_length)
                    self.assertEqual(ipv4.info.trailer, octets[34:])

                    self.assertEqual(Ethernet.from_data(parsed.info).data, octets)
                    self.assertEqual(Ethernet.from_data(parsed.info.to_dict()).data, octets)
                    self.assertEqual(IPv4.from_data(ipv4.info).data, octets[14:])
                    self.assertEqual(IPv4.from_data(ipv4.info.to_dict()).data, octets[14:])

        # make -> parse -> rebuild
        made = IPv4(total_length=10, protocol='TCP', trailer=frame[34:])
        self.assertEqual(made.data[2:4], b'\x00\x0a')
        parsed_made = IPv4(made.data, len(made.data))
        self.assertIsInstance(parsed_made.payload, NoPayload)
        self.assertEqual(IPv4.from_data(parsed_made.info.to_dict()).data, made.data)

    def test_a_total_length_past_the_capture_is_unchanged(self) -> None:
        # The other direction, which Wireshark reports as "IPv4 total length
        # exceeds packet length (64 bytes)" while still dissecting TCP: the
        # declared length is kept for the rebuild (#1155), and #1547 leaves it be.
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.protocols.transport.tcp import TCP

        frame = _records()[1][0][3]
        octets = _with_total_length(frame, 100, fix_checksum=True)
        parsed = self._parse(octets)
        ipv4 = parsed.payload
        self.assertIsInstance(ipv4.payload, TCP)
        self.assertEqual(ipv4.payload.data, octets[34:])
        self.assertEqual(ipv4.info.len, 100)
        self.assertNotIn('trailer', ipv4.info)
        self.assertEqual(Ethernet.from_data(parsed.info).data, octets)
        self.assertEqual(IPv4.from_data(ipv4.info.to_dict()).data, octets[14:])


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TSOTraceTests(unittest.TestCase):
    """The default engine traces a TSO capture's IPv4 flow, as dpkt and scapy do."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name

    def _write(self, name: 'str', header: 'bytes', records: 'list[list[Any]]') -> 'str':
        path = os.path.join(self.tmp, name)
        with open(path, 'wb') as file:
            file.write(header)
            for ts_sec, ts_usec, orig_len, octets in records:
                file.write(struct.pack('<IIII', ts_sec, ts_usec, len(octets), orig_len) + octets)
        return path

    def _extract(self, fin: 'str', engine: 'str') -> 'Any':
        from pcapkit import extract

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=fin, nofile=True, engine=engine, tcp=True, trace=True,
                                reassembly=True, trace_fout=tempfile.mkdtemp(dir=self.tmp),
                                trace_format='json')
        self.addCleanup(close_extractor, extractor)
        return extractor

    def test_flows_are_traced_and_reassembled(self) -> None:
        baseline = self._extract(sample_path('tcp.pcap'), 'default')
        expected_tcp = [tuple(datagram.index) for datagram in baseline.reassembly.tcp]
        for fix_checksum in (True, False):
            fin = self._write(f'tso-{fix_checksum}.pcap', *_tso_records(fix_checksum=fix_checksum))
            for engine in ('default',) + ENGINES:
                with self.subTest(engine=engine, checksum='fixed' if fix_checksum else 'stale'):
                    extractor = self._extract(fin, engine)
                    self.assertEqual([tuple(flow.index) for flow in extractor.trace.tcp], FLOWS)
                    self.assertEqual([tuple(datagram.index) for datagram in extractor.reassembly.tcp],
                                     expected_tcp)


if __name__ == '__main__':
    unittest.main()
