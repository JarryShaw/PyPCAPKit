# -*- coding: utf-8 -*-
"""An IGMPv3 group record cut inside its sources reads no source past the cut.

GitHub issue #2760: a Report the capture cut inside a group record's sources held, after the
source the cut lands inside, every source its Number of Sources counts, read as ``0.0.0.0``
from no octet of the capture. The source list ends with the data instead, as a list of
schema items does (#2756): the source the cut lands inside is read as far as it was captured,
with zeros after, and no source is made up past it. Behind IPv4, the records the data ends
inside are read from the zeros their list is filled out with (#2686), and their sources end
with the data too, so a framed cut reads as the same octets parsed on their own.

A Query cut inside its sources reads them the same way. The record and the Query keep the
Number of Sources they declare, which their rebuild writes as captured, so every cut
rebuilds as its octets, from its info and from the info's dict, the datagram and the IGMPv3
message alike; a cut Query whose sources are edited counts them again, as a whole one does.

The messages are built here; this module is unit-tier and reads no capture file.

"""
from __future__ import annotations

import ipaddress
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): hand-picked parse -> rebuild round trips.
__tier__ = 'ALL'


def record(kind: int, sources: 'tuple[str, ...]', aux: int = 0) -> bytes:
    """A record of type ``kind`` for 239.1.1.1 with ``sources`` and ``aux`` words of
    auxiliary data (RFC 3376, section 4.2.4)."""
    return (bytes([kind, aux]) + len(sources).to_bytes(2, 'big') + bytes([239, 1, 1, 1])
            + b''.join(ipaddress.IPv4Address(source).packed for source in sources) + b'AUX!' * aux)


def checksummed(head: bytes, rest: bytes) -> bytes:
    """``head`` and ``rest`` around a checksum of both."""
    return head + wire.checksum(head + bytes(2) + rest).to_bytes(2, 'big') + rest


#: MODE_IS_INCLUDE with three sources, then ALLOW_NEW_SOURCES with two and a word of
#: auxiliary data.
RECORDS = (record(1, ('10.0.0.1', '10.0.0.2', '10.0.0.3')), record(5, ('10.0.0.4', '10.0.0.5'), aux=1))
#: The Report.
REPORT = checksummed(b'\x22\x00', b'\x00\x00' + len(RECORDS).to_bytes(2, 'big') + b''.join(RECORDS))


def query(count: int) -> bytes:
    """A Group-and-Source-Specific Query for 239.1.2.3 with ``count`` sources, from 10.0.0.1."""
    return checksummed(b'\x11\x64', bytes([239, 1, 2, 3, 0x0A, 125]) + count.to_bytes(2, 'big')
                       + b''.join(ipaddress.IPv4Address(f'10.0.0.{index}').packed for index in range(1, count + 1)))


#: The Query with three sources; one with one is beside it in :data:`QUERIES`.
QUERY = query(3)
#: Queries cut at every offset from the end of their fixed fields, which IGMPv3 needs.
QUERIES = (query(1), QUERY)


def query_sources(message: bytes, keep: int) -> 'tuple[str, ...]':
    """The sources the first ``keep`` octets of the Query ``message`` begin, the last read as its
    octets with zeros after them."""
    cut = message[:keep]
    return tuple(str(ipaddress.IPv4Address(cut[at:at + 4].ljust(4, b'\x00'))) for at in range(12, keep, 4))


def expected(keep: int) -> 'list[tuple[int, int, tuple[str, ...], bytes]]':
    """The records the first ``keep`` octets of :data:`REPORT` begin, each as its type, Number
    of Sources, the sources those octets begin, the last read as its octets with zeros after
    them, and its auxiliary data, zero-filled to its length."""
    cut, out, start = REPORT[:keep], [], 8
    for item in RECORDS:
        if start >= keep:
            break
        head = cut[start:start + 8].ljust(8, b'\x00')
        count, aux = int.from_bytes(head[2:4], 'big'), head[1] * 4
        sources = tuple(str(ipaddress.IPv4Address(cut[at:at + 4].ljust(4, b'\x00')))
                        for at in range(start + 8, min(start + 8 + 4 * count, keep), 4))
        tail = start + 8 + 4 * count
        out.append((head[0], count, sources, cut[tail:tail + aux].ljust(aux, b'\x00')))
        start += len(item)
    return out


class SourceListCutTests(unittest.TestCase):
    """A record cut inside its sources holds the sources its octets begin, and rebuilds."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.protocols.internet.igmpv3.protocol import IGMPv3
        from pcapkit.protocols.internet.ipv4.protocol import IPv4

        self.IGMPv3, self.IPv4 = IGMPv3, IPv4
        catcher = warnings.catch_warnings()
        catcher.__enter__()
        self.addCleanup(catcher.__exit__, None, None, None)
        warnings.simplefilter('ignore')

    @staticmethod
    def records(layer: 'Any') -> 'list[tuple[int, int, tuple[str, ...], bytes]]':
        """``layer``'s records, each as its type, Number of Sources, sources and auxiliary data."""
        return [(int(item.record_type), item.num_sources, tuple(map(str, item.sources)), item.aux_data)
                for item in layer.info.records]

    def parses(self, message: bytes, keep: int) -> 'dict[str, tuple[Any, Any, bytes]]':
        """``message`` cut ``keep`` octets in, parsed on its own unsized and sized and behind
        IPv4 declaring all of it: each as the protocol, its IGMPv3 layer and the octets."""
        packet = wire.ipv4(message, proto=2)
        raw = packet[:len(packet) - len(message) + keep]
        alone, sized, framed = (self.IGMPv3(message[:keep]), self.IGMPv3(message[:keep], keep),
                                self.IPv4(raw))
        return {'alone': (alone, alone, message[:keep]), 'sized': (sized, sized, message[:keep]),
                'framed': (framed, framed.payload, raw)}

    def test_the_issue_repro(self) -> None:
        rec = bytes([1, 0, 0, 3, 224, 0, 0, 1, 10, 0, 0, 1, 10, 0, 0, 2, 10, 0, 0, 3])
        rep = bytes([0x22, 0, 0, 0, 0, 0, 0, 1]) + rec
        self.assertEqual([str(source) for source in self.IGMPv3(rep[:20]).info.records[0].sources],
                         ['10.0.0.1'])

    def test_the_cuts_reach_every_source(self) -> None:
        self.assertEqual(len(REPORT), 8 + 20 + 20)
        self.assertEqual(self.records(self.IGMPv3(REPORT)), expected(len(REPORT)))

    def test_a_cut_record_holds_the_sources_it_begins(self) -> None:
        for keep in range(8, len(REPORT)):
            for shape, (_, igmp, _) in self.parses(REPORT, keep).items():
                with self.subTest(captured=keep, shape=shape):
                    self.assertIsInstance(igmp, self.IGMPv3)
                    self.assertEqual(self.records(igmp), expected(keep))

    def test_a_cut_inside_the_second_source_reads_as_captured(self) -> None:
        # Two octets into the second source: it reads ``10.0.0.0``, and none follows it.
        for shape, (_, igmp, _) in self.parses(REPORT, 8 + 8 + 6).items():
            with self.subTest(shape=shape):
                self.assertEqual(self.records(igmp), [(1, 3, ('10.0.0.1', '10.0.0.0'), b'')])

    def test_a_cut_query_holds_the_sources_it_begins(self) -> None:
        held = set()
        for message in QUERIES:
            for keep in range(12, len(message)):
                for shape, (_, igmp, _) in self.parses(message, keep).items():
                    with self.subTest(sources=message[11], captured=keep, shape=shape):
                        self.assertEqual(igmp.info.num_sources, message[11])
                        self.assertEqual(tuple(map(str, igmp.info.sources)), query_sources(message, keep))
                        held.add(len(igmp.info.sources))
        # A cut leaves no source, one, and more than one.
        self.assertEqual(held, {0, 1, 2, 3})

    def test_an_edited_cut_query_counts_its_sources(self) -> None:
        """Sources no longer those a cut Query began with, zeros past the cut, are counted as a
        whole Query's are, not given the count the cut Query declares; its record still cuts it
        back to the octets it captured."""
        edits = (
            ('one source fewer', lambda sources: sources[:-1]),
            ('no sources', lambda sources: []),
            ('one source more', lambda sources: sources + ['10.9.9.9']),
            ('a value past the cut', lambda sources: sources[:-1] + ['10.1.1.1']),
        )
        whole = self.IGMPv3(QUERY).info
        for keep in range(13, len(QUERY)):
            for label, edit in edits:
                if label == 'a value past the cut' and (keep - 12) % 4 == 0:
                    continue  # the last source is whole, so no value of it is past the cut
                for shape, (_, igmp, _) in self.parses(QUERY, keep).items():
                    with self.subTest(captured=keep, edit=label, shape=shape):
                        sources = edit([str(source) for source in igmp.info.sources])
                        built = {}
                        for name, info in (('cut', igmp.info), ('whole', whole)):
                            data = info.to_dict()
                            data['sources'] = tuple(map(ipaddress.IPv4Address, sources))
                            built[name] = self.IGMPv3.from_data(data)
                        self.assertEqual(built['whole'].info.num_sources, len(sources))
                        self.assertEqual(built['cut'].info.num_sources, len(sources))
                        self.assertEqual(built['cut'].data, built['whole'].data[:keep])

    def test_make_writes_num_sources_as_given(self) -> None:
        # Counted from the sources when not given; a count above them is written as given, and one
        # below them, or that does not fit 16 bits, is refused.
        from pcapkit.const.igmp.type import Type
        from pcapkit.utilities.exceptions import ProtocolError

        sources = ['10.0.0.1', '10.0.0.2']
        self.assertEqual(self.IGMPv3(type=Type.IGMP_Membership_Query, sources=sources).info.num_sources, 2)
        made = self.IGMPv3(type=Type.IGMP_Membership_Query, sources=sources, num_sources=5)
        self.assertEqual(made.data[10:12], (5).to_bytes(2, 'big'))
        for count in (1, 0x10000, True, '2'):
            with self.subTest(num_sources=count), self.assertRaisesRegex(ProtocolError, 'num_sources'):
                self.IGMPv3(type=Type.IGMP_Membership_Query, sources=sources, num_sources=count)

    def test_a_cut_rebuilds_as_captured(self) -> None:
        for message in (REPORT, *QUERIES):
            for keep in range(12, len(message)):
                for shape, (proto, igmp, raw) in self.parses(message, keep).items():
                    for path, layer, octets in (('outer', proto, raw), ('igmpv3', igmp, message[:keep])):
                        with self.subTest(message=message[:1].hex(), captured=keep, shape=shape, layer=path):
                            cls = type(layer)
                            self.assertEqual(cls.from_data(layer.info).data, octets)
                            self.assertEqual(cls.from_data(layer.info.to_dict()).data, octets)

    def test_a_whole_report_is_the_control(self) -> None:
        for shape, (proto, igmp, raw) in self.parses(REPORT, len(REPORT)).items():
            with self.subTest(shape=shape):
                self.assertIsNone(igmp.info.get('__short_read__'))
                self.assertEqual(self.records(igmp), [
                    (1, 3, ('10.0.0.1', '10.0.0.2', '10.0.0.3'), b''),
                    (5, 2, ('10.0.0.4', '10.0.0.5'), b'AUX!'),
                ])
                self.assertEqual(type(proto).from_data(proto.info).data, raw)


if __name__ == '__main__':
    unittest.main()
