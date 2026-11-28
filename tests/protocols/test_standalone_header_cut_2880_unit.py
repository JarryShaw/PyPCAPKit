# -*- coding: utf-8 -*-
"""A layer built on its own from data ending inside its header reads the cut quietly. C.f. #2880.

Built on its own, a layer is given the octets captured as its length, so a cut inside its
header left every field past it running below that length: each warned
``packet length < 0``, and a field sized by what was left, or by the zeros the cut left,
resolved a negative length, which TCP, IPv4, AH and DNS refused. Behind an enclosing
layer the same cut is kept as ``Raw``, quietly. Outside a frame the header is now
unpacked as ending with the data, as #2848 reads an ICMP body, so ``Schema.unpack``
reads the fields past the cut as empty and warns nothing, and a length they resolve
below zero is zero; an IGMPv3 body is read as an ICMP body is. A protocol's own check of
a value the cut left as zero, or of a header length the data ends before, leaves it to
the short read through ``cut_on_its_own``, and the rebuild keeps the header length read.

Every concrete protocol class the registry names with a length hint is built from its
``make()`` defaults, and from the octets below, and cut at every length short of that
hint. Parsed on its own, each cut warns no ``packet length < 0``, records its short read
unless the octets left are a whole header, and rebuilds from the data model and from the
dict with the octets and values it parsed. The refusals kept, where the cut leaves
nothing to decide by, are listed below, in both directions. Inside a frame each cut is
kept as before. ``analyze``, which parses on its own too, keeps an empty payload as
``NoPayload``, as a frame does, rather than as a header of zeros.

The octets are built here; this module is unit-tier and reads no capture.

"""
from __future__ import annotations

import inspect
import re
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Iterator

#: Test tier (#1958): a sweep that cuts every registered protocol at every short length.
__tier__ = 'LATEST'

#: ``make()`` keywords for a class whose defaults build nothing it reads back: a Query
#: with a Max Resp Time of zero is IGMPv1's (RFC 3376, section 7.1), and a DHCP message
#: carries its Message Type (RFC 2131, section 3).
MAKE = {
    'DHCPV4': {'options': ({'code': 53, 'data': {'type': 1}},)},
    'IGMPV2': {'max_resp_time': 100},
}

#: Whole packets cut besides the ``make()`` header, for a class whose defaults build
#: nothing, or declare no header length past the fixed one.
OCTETS = {
    # a Data packet without extended sequence numbers, shorter than the DCCP-Request a
    # Type the cut left as zero reads as (RFC 4340, section 5.1)
    'DCCP': (bytes.fromhex('12345678' '0300abcd' '04000001'),),
    # an IHL of 7 over a Router Alert, three NOPs and an End of Option List (RFC 791)
    'IPV4': (bytes.fromhex('4700001c' '00014000' '40fd0000' '0a000001' '0a000002' '94040000' '01010100'),),
    # an NGSetupRequest in aligned PER, which no cut of leaves decodable
    'NGAP': (bytes.fromhex('00150036000004001b00080002f839100001020052400d0500706361706b69742d676e62'
                           '0066000d00000000010002f839000000080015400140'),),
    # a Data Offset of 8 over MSS, SACK-Permitted, two NOPs, Window Scale and an EOOL (RFC 9293)
    'TCP': (bytes.fromhex('12340050' '01020304' '05060708' '8012ffff' 'abcd0000'
                          '020405b4' '04020101' '03030700'),),
}

#: Classes with a length hint that no octets are cut for, and why.
NOT_CUT = {
    'FRAME': 'reads its record by the global header of its savefile',
    'IP_PSEUDO': 'is built from an IP layer, and is no header on the wire',
    'PCAPNG': 'reads its block by the section and interfaces before it',
}

#: The refusals a protocol's own checks keep making of a cut on its own, since the cut
#: leaves nothing to decide them by: the method, the messages, and why.
REFUSED = {
    'DTLS': ('SSL._validate_tls_record', (r'^DTLS: invalid format: unrecognised content type 0$',
                                          r'^DTLS: invalid format: legacy record version 0x0000 ',
                                          r'^DTLS: invalid format: record length 0 runs past '),
             'checks the framing that tells a record from octets that are none'),
    'DHCPV4': ('DHCPv4.read', (r'^DHCP: invalid format: no magic cookie opens the options field$',),
               'tells a DHCP message from a BOOTP one by its options, which the cut leaves out'),
    'HEADER': ('magic_number_callback', (r'^PCAP: invalid magic number: ',),
               'cannot tell the byte order of every later field from a cut magic number'),
    'HTTPV2': ('HTTPv2.unpack', (r'^HTTP/2: invalid format, packet \(\d+ octet\(s\)\) shorter than ',),
               'checks the framing that tells a frame from octets that are none'),
    'IGMPV1': ('IGMP.read', (r'^IGMP: <Type\.\w+: \d+> is not an IGMPv1 message ',),
               'classifies the message by its length, which the cut sets'),
    'IGMPV2': ('IGMP.read', (r'^IGMPv2: <Type\.\w+: \d+> is not an IGMPv2 message ',),
               'classifies the message by its length, which the cut sets'),
    'IGMPV3': ('IGMPv3.read', (r'^IGMPv3: <Type\.\w+: \d+> is not an IGMPv3 message ',
                               r'^IGMPv3: unsupported message type: <Type\.Reserved_0: 0>$'),
               'classifies the message by its length, which the cut sets'),
    'NGAP': ('NGAP.read', (r'^NGAP: malformed NGAP-PDU: ',),
             'decodes the PDU in aligned PER, which no cut of leaves decodable'),
    'SSLV3': ('SSL._validate_tls_record', (r'^TLS: invalid format: unrecognised content type 0$',
                                           r'^TLS: invalid format: legacy record version 0x0000 ',
                                           r'^TLS: invalid format: record length 0 runs past '),
              'checks the framing that tells a record from octets that are none'),
    'TLS': ('SSL._validate_tls_record', (r'^TLS: invalid format: unrecognised content type 0$',
                                         r'^TLS: invalid format: legacy record version 0x0000 ',
                                         r'^TLS: invalid format: record length 0 runs past '),
            'checks the framing that tells a record from octets that are none'),
}


def _differing(parsed: 'Any', rebuilt: 'Any') -> 'tuple[str, ...]':
    """The keys whose values ``parsed`` and ``rebuilt`` do not share, in order."""
    keys = list(dict.fromkeys([*parsed, *rebuilt]))
    return tuple(key for key in keys if key not in parsed or key not in rebuilt or parsed[key] != rebuilt[key])


def _negative(caught: 'list[warnings.WarningMessage]') -> 'list[str]':
    """The ``packet length < 0`` warnings among ``caught``."""
    return [str(item.message) for item in caught if str(item.message).startswith('packet length < 0')]


class StandaloneHeaderCutTests(unittest.TestCase):
    """Every registered protocol reads a cut inside its header on its own as a quiet short read."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def headed(self) -> 'Iterator[tuple[str, type, int]]':
        """Every registered concrete class with a length hint: its key, the class and the hint."""
        from pcapkit.protocols.protocol import ProtocolBase

        for name in sorted(ProtocolBase.registry):
            klass = ProtocolBase.get_protocol(name)
            if inspect.isabstract(klass):
                continue  # parses nothing; its members are registered under their own names
            # NOTE: Read from the class, as ``_short_of_hint`` reads it: each returns a constant.
            hint = klass.__length_hint__(None)  # type: ignore[arg-type]
            if isinstance(hint, int):
                yield name, klass, hint

    def wholes(self, name: str, klass: type) -> 'list[bytes]':
        """The whole packets of ``klass`` to cut: its ``make()`` header, if it builds, and its octets."""
        from pcapkit.utilities.exceptions import BaseError, CaughtByCaller, ProtocolError

        packets = list(OCTETS.get(name, ()))
        try:
            with warnings.catch_warnings(), CaughtByCaller(ProtocolError):
                warnings.simplefilter('ignore')
                packets.insert(0, klass.from_fields(**MAKE.get(name, {})).data)
        except (BaseError, TypeError):
            pass  # its defaults build nothing
        return packets

    def cuts(self, only: 'tuple[str, ...]' = ()) -> 'Iterator[tuple[str, type, bytes]]':
        """Each class cut, with the octets captured, at every length short of its hint."""
        for name, klass, hint in self.headed():
            if name in NOT_CUT or (only and name not in only):
                continue
            for whole in self.wholes(name, klass):
                for count in range(min(hint, len(whole))):
                    yield name, klass, whole[:count]

    def parse(self, klass: type, raw: bytes) -> 'tuple[Any, Any, list[warnings.WarningMessage]]':
        """``raw`` parsed on its own as ``klass``: the layer or the refusal, and the warnings."""
        from pcapkit.utilities.exceptions import CaughtByCaller, ProtocolError

        layer = refusal = None
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            try:
                with CaughtByCaller(ProtocolError):
                    layer = klass(raw, len(raw))
            except ProtocolError as error:
                refusal = error
        return layer, refusal, caught

    def test_every_class_with_a_header_is_cut(self) -> None:
        # a class whose header nothing builds is named, with its reason
        found = {name: klass for name, klass, _ in self.headed()}
        self.assertLessEqual(set(NOT_CUT) | set(MAKE) | set(OCTETS) | set(REFUSED), set(found))
        for name, klass in found.items():
            with self.subTest(protocol=name):
                self.assertEqual(name in NOT_CUT, not self.wholes(name, klass))

    def test_a_cut_on_its_own_is_a_quiet_short_read(self) -> None:
        for name, klass, raw in self.cuts():
            with self.subTest(protocol=name, captured=raw.hex()):
                layer, refusal, caught = self.parse(klass, raw)
                self.assertEqual(_negative(caught), [])
                if refusal is not None:
                    self.assertIn(name, REFUSED, str(refusal))
                    self.assertTrue(any(re.search(pattern, str(refusal)) for pattern in REFUSED[name][1]),
                                    str(refusal))
                    continue
                if layer.info.get('__short_read__') is None:
                    # the octets left are a whole header, as a compressed PPP Protocol field is
                    self.assertEqual(layer.length, len(raw))
                for path, data in (('model', layer.info), ('dict', layer.info.to_dict())):
                    with self.subTest(path=path):
                        rebuilt = type(layer).from_data(data)
                        self.assertEqual(rebuilt.data.hex(), raw.hex())
                        self.assertEqual(_differing(layer.info, rebuilt.info), ())

    def test_every_refusal_is_still_raised(self) -> None:
        # an entry each of whose messages some cut raises, so a fix deletes its entry
        raised = {name: set() for name in REFUSED}  # type: dict[str, set[str]]
        for name, klass, raw in self.cuts(tuple(REFUSED)):
            _, refusal, _ = self.parse(klass, raw)
            if refusal is not None:
                raised[name].update(pattern for pattern in REFUSED[name][1] if re.search(pattern, str(refusal)))
        for name, (_, patterns, _) in REFUSED.items():
            with self.subTest(protocol=name):
                self.assertEqual(raised[name], set(patterns))

    def test_the_fields_before_the_cut_are_read(self) -> None:
        # RFC 768: Source Port, Destination Port, Length, Checksum, two octets each
        from pcapkit.protocols.transport.udp.protocol import UDP

        header = bytes.fromhex('1234' '0035' '0010' 'abcd')
        for count, record in ((3, ('dstport', 1)), (5, ('len', 1)), (7, ('checksum', 1))):
            with self.subTest(count=count):
                layer, _, caught = self.parse(UDP, header[:count])
                self.assertEqual([str(item.message) for item in caught], [])
                self.assertEqual(layer.info.get('__short_read__'), record)
                self.assertEqual(int(layer.info.srcport), 0x1234)

    def test_a_header_length_the_data_ends_before_is_read(self) -> None:
        # the IHL, Data Offset and DCCP Data Offset read before the cut, in octets
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.transport.dccp.protocol import DCCP
        from pcapkit.protocols.transport.tcp.protocol import TCP

        for klass, whole, count, record, hdr_len in (
                (IPv4, OCTETS['IPV4'][0], 1, ('tos', 0), 28),
                (TCP, OCTETS['TCP'][0], 13, ('flags', 0), 32),
                (DCCP, OCTETS['DCCP'][0], 5, ('cscov', 0), 12)):
            with self.subTest(protocol=klass.__name__, count=count):
                layer, refusal, _ = self.parse(klass, whole[:count])
                self.assertIsNone(refusal)
                self.assertEqual(layer.info.get('__short_read__'), record)
                self.assertEqual(layer.info.hdr_len, hdr_len)

    def test_a_value_read_is_still_refused(self) -> None:
        # only a value the cut left is the short read's: one read before it is checked
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.transport.dccp.protocol import DCCP
        from pcapkit.protocols.transport.tcp.protocol import TCP

        for klass, raw, message in (
                (IPv4, bytes.fromhex('750000'), r'^\[IPv4\] invalid version: 7$'),
                (IPv6, bytes.fromhex('4000'), r'^\[IPv6\] invalid version: 4$'),
                (TCP, bytes.fromhex('12340050' '01020304' '05060708' '30'), r'^TCP: invalid format$'),
                (DCCP, bytes.fromhex('12345678' '02'), r'^DCCP: header length 8 is shorter than the 12 '
                                                       r'octets of any packet type$')):
            with self.subTest(protocol=klass.__name__, captured=raw.hex()):
                _, refusal, _ = self.parse(klass, raw)
                self.assertRegex(str(refusal), message)

    def test_a_header_given_no_octets_is_cut_at_its_first_field(self) -> None:
        # a length of zero given reaches the version checks with nothing read; with none
        # given, an empty stream ends the parse as before
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.link.pppoe.protocol import PPPoE
        from pcapkit.utilities.exceptions import StreamEOFError

        for klass, record in ((IPv4, ('vihl', 0)), (IPv6, ('hextet', 0)), (PPPoE, ('info', 0))):
            with self.subTest(protocol=klass.__name__):
                layer, refusal, _ = self.parse(klass, b'')
                self.assertIsNone(refusal)
                self.assertEqual(layer.info.get('__short_read__'), record)
                self.assertEqual(type(layer).from_data(layer.info).data, b'')
                with self.assertRaises(StreamEOFError):
                    klass(b'')

    def test_a_complete_malformed_header_still_refuses(self) -> None:
        # a guard, as on origin/main: values read, not left by a cut, are checked (#2874)
        from pcapkit.protocols.internet.hip.protocol import HIP
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.link.l2tpv2.protocol import L2TPv2
        from pcapkit.protocols.link.pppoe.protocol import PPPoE
        from pcapkit.protocols.transport.dccp.protocol import DCCP
        from pcapkit.protocols.transport.tcp.protocol import TCP

        for klass, octets, message in (
                (TCP, '0000000000000000000000003000ffff00000000',  # Data Offset 3
                 r"^Field padding resolved to a negative length; template='-8s'$"),
                (IPv4, '430000140000000000113bd97f00000100000000',  # IHL 3
                 r"^Field padding resolved to a negative length; template='-8s'$"),
                (IPv4, '050000140000000000113bd97f00000100000000', r'^\[IPv4\] invalid version: 0$'),
                (IPv6, '4000000000001140' + '00' * 15 + '01' + '00' * 16, r'^\[IPv6\] invalid version: 4$'),
                (DCCP, '0000000003000000010000000000000000000000',  # Data Offset 3
                 r'^DCCP: header length 12 is shorter than the 20 octets of a DCCP_Request$'),
                (L2TPv2, '000300000000', r'^L2TPv2: invalid version: 3$'),
                (PPPoE, '210000000000', r'^PPPoE: invalid version or type: 2, 1$'),
                (HIP, '11032021' + '00' * 36, r'^HIP: invalid header length: 3$')):
            with self.subTest(protocol=klass.__name__, octets=octets):
                _, refusal, _ = self.parse(klass, bytes.fromhex(octets))
                self.assertRegex(str(refusal), message)

    def test_cut_on_its_own_reads_the_record_and_the_frame(self) -> None:
        from pcapkit.corekit.schema.short_read import cut_on_its_own
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.utilities.contextvars import frame_depth

        header = IPv6(bytes.fromhex('6000'), 2).__header__  # cut inside its first field
        self.assertEqual(header.__dict__['__short_read__'], ('hextet', 2))
        self.assertFalse(cut_on_its_own(header, 'hextet', 2))
        self.assertTrue(cut_on_its_own(header, 'hextet', 3))
        self.assertTrue(cut_on_its_own(header, 'hextet'))
        self.assertTrue(cut_on_its_own(header, 'src'))
        self.assertTrue(cut_on_its_own(header))
        token = frame_depth.set(1)
        try:
            self.assertFalse(cut_on_its_own(header))
        finally:
            frame_depth.reset(token)
        whole = IPv6.from_fields().__header__
        self.assertFalse(cut_on_its_own(whole))
        self.assertFalse(cut_on_its_own(whole, 'hextet'))

    def test_a_cut_inside_a_frame_is_kept_as_before(self) -> None:
        # behind an enclosing layer, which declares the octets as the message, the layer is
        # kept as Raw with its warnings dropped, or as itself, a cut header still warning
        from pcapkit.corekit.decorators import beholder
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.protocols.protocol import Protocol

        @beholder
        def embed(_parent: 'Any', _proto: 'Any', length: int, *, klass: type, payload: bytes) -> 'Any':
            return Protocol._parse_next_layer(klass, payload, length)  # pylint: disable=protected-access

        for name, klass, raw in self.cuts():
            with self.subTest(protocol=name, captured=raw.hex()):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    layer = embed(None, None, len(raw), klass=klass, payload=raw)
                self.assertEqual(layer.data, raw)
                if type(layer) is Raw:  # pylint: disable=unidiomatic-typecheck
                    self.assertEqual(_negative(caught), [])
                    continue
                self.assertIs(type(layer), klass)
                if layer.info.get('__short_read__') is None:
                    self.assertEqual(layer.length, len(raw))
                    self.assertEqual(_negative(caught), [])
                else:
                    self.assertNotEqual(_negative(caught), [])


class AnalyzeEmptyPayloadTests(unittest.TestCase):
    """``analyze`` keeps an empty payload as ``NoPayload``, as a frame keeps an empty next layer.

    Parsed on its own, the class an empty payload was dispatched to would read a header cut
    before its first octet, so a reassembled IPv4 datagram carrying no TCP octets analysed
    as a TCP header of zeros.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def analysed(self) -> 'Iterator[tuple[str, Any]]':
        """An empty payload analysed for every code IPv4 and IPv6 and every port TCP and UDP dispatch on."""
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.transport.tcp.protocol import TCP
        from pcapkit.protocols.transport.udp.protocol import UDP

        for owner in (IPv4, IPv6):
            for code in sorted(owner.__proto__, key=int):
                yield f'{owner.__name__}/{int(code)}', owner.analyze(code, b'')
        for owner in (TCP, UDP):
            for port in sorted(owner.__proto__, key=int):
                yield f'{owner.__name__}/{int(port)}', owner.analyze((port, port), b'')

    def test_an_empty_payload_is_no_payload(self) -> None:
        from pcapkit.protocols.misc.no_payload.protocol import NoPayload
        from pcapkit.utilities.logging import logger
        from tests.utilities._harness import capture

        with capture(logger) as recorder, warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            results = list(self.analysed())
        self.assertGreater(len(results), 4)
        for case, result in results:
            with self.subTest(case=case):
                self.assertIs(type(result), NoPayload)
                self.assertEqual(result.data, b'')
        self.assertEqual([str(item.message) for item in caught], [])
        self.assertEqual(recorder.messages, [])

    def test_a_frame_keeps_the_same_payload_as_no_payload(self) -> None:
        # RFC 791: an IPv4 header whose Total Length is its own 20 octets carries nothing
        import struct

        from pcapkit.protocols.internet.ipv4.protocol import IPv4

        for code in sorted(IPv4.__proto__, key=int):
            with self.subTest(code=int(code)):
                header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20, 1, 0x4000, 64, int(code), 0,
                                     bytes([192, 0, 2, 1]), bytes([198, 51, 100, 2]))
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    frame = IPv4(header, len(header))
                self.assertIs(type(IPv4.analyze(code, b'')), type(frame.payload))

    def test_a_reassembled_empty_datagram_is_no_payload(self) -> None:
        # as the IPv4 datagrams of options-ipv4.pcap carry no TCP octets
        import ipaddress

        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.analysis import ip_datagram
        from pcapkit.foundation.reassembly.data import Completion
        from pcapkit.foundation.reassembly.ip.data import Datagram, DatagramID
        from pcapkit.protocols.misc.no_payload.protocol import NoPayload

        datagram = Datagram(completed=Completion.COMPLETE,
                            id=DatagramID(src=ipaddress.ip_address('192.0.2.1'),
                                          dst=ipaddress.ip_address('198.51.100.2'), id=1, proto=TransType.TCP),
                            index=(1,), header=b'', payload=b'', packet=None, conflict=())
        self.assertIs(type(ip_datagram(datagram)), NoPayload)


if __name__ == '__main__':
    unittest.main()
