# -*- coding: utf-8 -*-
"""DNS messages decode against RFC 1035, and rebuild byte for byte (#2816).

Each message is built here from octets whose field values the RFCs give, is
checked against them, and is rebuilt both ways round: parse then
``from_data`` (from the data model and from its ``to_dict()`` form), and
``make`` then parse. Compressed names keep the pointers they were read with,
and the TCP length field frames a message read from a TCP segment.

This module is unit-tier and reads no capture.

"""
from __future__ import annotations

import struct
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'

#: ``www.example.com``, uncompressed.
WWW = b'\x03www\x07example\x03com\x00'

#: A recursive query for ``www.example.com`` A, with an OPT record carrying a
#: client cookie (RFC 1035 section 4.1, RFC 6891 section 6.1.2, RFC 7873).
QUERY = (bytes.fromhex('1234' '0120' '0001' '0000' '0000' '0001') + WWW + b'\x00\x01\x00\x01'
         + b'\x00' + bytes.fromhex('0029' '1000' '00008000' '000c') + bytes.fromhex('000a0008')
         + bytes(range(1, 9)))

#: Its answer: a CNAME to ``foo.example.com``, which points into the question,
#: and that name's A record, whose owner points into the CNAME's RDATA.
RESPONSE = (bytes.fromhex('1234' '8180' '0001' '0002' '0000' '0000') + WWW + b'\x00\x01\x00\x01'
            + bytes.fromhex('c00c' '0005' '0001' '00000e10' '0006') + b'\x03foo\xc0\x10'
            + bytes.fromhex('c02d' '0001' '0001' '00000e10' '0004' '5db8d822'))


def _rr(rtype: int, rdata: bytes, name: bytes = b'\xc0\x0c') -> bytes:
    return name + struct.pack('!HHIH', rtype, 1, 300, len(rdata)) + rdata


def _answer(*records: bytes) -> bytes:
    """A response to the ``www.example.com`` question carrying ``records``."""
    return (struct.pack('!6H', 0xBEEF, 0x8180, 1, len(records), 0, 0) + WWW + b'\x00\x01\x00\x01'
            + b''.join(records))


class DNSTestCase(unittest.TestCase):
    """Shared helpers."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def assertRoundTrip(self, octets: bytes, **kwargs: object) -> object:
        """Parse ``octets``, and hold both rebuilds to them."""
        from pcapkit.protocols.application.dns.protocol import DNS

        parsed = DNS(octets, **kwargs)
        self.assertEqual(parsed.data, octets)
        self.assertEqual(DNS.from_data(parsed.info).data, octets)
        self.assertEqual(DNS.from_data(parsed.info.to_dict()).data, octets)
        self.assertEqual(DNS.from_data(parsed.info).info, parsed.info)
        return parsed


class DNSHeaderTests(DNSTestCase):
    """The header, the question and the OPT record of a query."""

    def test_query_fields(self) -> None:
        from pcapkit.const.dns.opcode import Opcode
        from pcapkit.const.dns.option import Option
        from pcapkit.const.dns.rcode import RCode
        from pcapkit.const.dns.rr_class import RRClass
        from pcapkit.const.dns.rr_type import RRType
        from pcapkit.protocols.application.dns.data import OPT, Cookie

        info = self.assertRoundTrip(QUERY).info
        self.assertEqual(info.id, 0x1234)
        flags = info.flags
        self.assertEqual((flags.qr, flags.opcode, flags.aa, flags.tc, flags.rd, flags.ra, flags.z,
                          flags.ad, flags.cd, flags.rcode),
                         (False, Opcode.Query, False, False, True, False, 0, True, False, RCode.NoError))
        self.assertEqual((info.qdcount, info.ancount, info.nscount, info.arcount), (1, 0, 0, 1))
        question = info.question[0]
        self.assertEqual(question.name.name, 'www.example.com.')
        self.assertEqual(question.name.labels, (b'www', b'example', b'com'))
        self.assertEqual((question.name.literal, question.name.pointer), (3, None))
        self.assertIs(question.type, RRType.A)
        self.assertIs(question['class'], RRClass.IN)

        opt = info.additional[0]
        self.assertIsInstance(opt, OPT)
        self.assertEqual(opt.name.name, '.')
        self.assertEqual((opt.udp_payload_size, opt.extended_rcode, opt.version, opt.do, opt.z, opt.rdlength),
                         (4096, 0, 0, True, 0, 12))
        option = opt.options[0]
        self.assertIs(option.code, Option.COOKIE)
        self.assertEqual(option.length, 8)
        self.assertEqual(option.data, Cookie(client=bytes(range(1, 9)), server=b''))
        self.assertNotIn('length', info)
        self.assertNotIn('trailer', info)

    def test_extended_rcode_combines_the_opt_bits(self) -> None:
        from pcapkit.const.dns.rcode import RCode
        from pcapkit.protocols.application.dns.protocol import DNS

        # RCODE 0 in the header and 1 in the OPT record's upper bits: 16, BADVERS (RFC 6891 section 7).
        octets = (struct.pack('!6H', 7, 0x8000, 0, 0, 0, 1) + b'\x00'
                  + bytes.fromhex('0029' '0200' '01000000' '0000'))
        dns = DNS(octets)
        self.assertIs(dns.rcode, RCode.BADVERS)
        self.assertIs(RCode.BADSIG, RCode.BADVERS)
        self.assertIs(DNS(struct.pack('!6H', 7, 0x8003, 0, 0, 0, 0)).rcode, RCode.NXDomain)

    def test_properties(self) -> None:
        from pcapkit.protocols.application.dns.protocol import DNS

        dns = DNS(QUERY)
        self.assertEqual(dns.name, 'Domain Name System')
        self.assertEqual(dns.alias, 'DNS')
        self.assertEqual(dns.length, len(QUERY))
        self.assertEqual(int(dns), 53)
        self.assertEqual(dns.__length_hint__(), 12)
        self.assertEqual(type(dns.payload).__name__, 'NoPayload')

    def test_trailer_is_kept(self) -> None:
        info = self.assertRoundTrip(QUERY + b'\xde\xad').info
        self.assertEqual(info.trailer, b'\xde\xad')


class DNSCompressionTests(DNSTestCase):
    """Names keep the compression they were read with (RFC 1035 section 4.1.4)."""

    def test_response_names_and_pointers(self) -> None:
        from ipaddress import IPv4Address

        from pcapkit.const.dns.rr_type import RRType

        info = self.assertRoundTrip(RESPONSE).info
        cname, a = info.answer
        self.assertIs(cname.type, RRType.CNAME)
        self.assertEqual(cname.name.name, 'www.example.com.')
        self.assertEqual((cname.name.literal, cname.name.pointer), (0, 12))
        self.assertEqual(cname.ttl, 3600)
        self.assertEqual(cname.rdata.cname.name, 'foo.example.com.')
        self.assertEqual((cname.rdata.cname.literal, cname.rdata.cname.pointer), (1, 16))
        self.assertEqual(a.name.name, 'foo.example.com.')
        self.assertEqual((a.name.literal, a.name.pointer), (0, 45))
        self.assertEqual(a.rdata.address, IPv4Address('93.184.216.34'))

    def test_make_compresses_and_parses_back(self) -> None:
        from pcapkit.const.dns.rr_type import RRType
        from pcapkit.protocols.application.dns.protocol import DNS

        kwargs = dict(id=9, qr=True, question=[{'name': 'example.org', 'type': RRType.MX}],
                      answer=[{'name': 'example.org', 'type': RRType.MX, 'ttl': 60,
                               'rdata': {'preference': 10, 'exchange': 'mail.example.org.'}}])
        plain = DNS.build(**kwargs).data
        packed = DNS.build(compress=True, **kwargs).data
        # The owner is a pointer to the question's name, and the exchange a
        # label then a pointer to the same.
        self.assertEqual(packed[29:31], b'\xc0\x0c')
        self.assertTrue(packed.endswith(b'\x04mail\xc0\x0c'))
        # Each pointer stands for the 13 octets of ``example.org`` in two.
        self.assertEqual(len(plain) - len(packed), 2 * (13 - 2))
        for octets in (plain, packed):
            parsed = self.assertRoundTrip(octets)
            self.assertEqual(parsed.info.answer[0].rdata.exchange.name, 'mail.example.org.')

    def test_name_forms(self) -> None:
        from pcapkit.protocols.application.dns.protocol import DNS

        for name in ('a.b', 'a.b.', (b'a', b'b'), {'labels': (b'a', b'b'), 'literal': 2, 'pointer': None}):
            with self.subTest(name=name):
                dns = DNS.build(question=[{'name': name}])
                self.assertEqual(dns.info.question[0].name.labels, (b'a', b'b'))
        self.assertEqual(DNS.build(question=[{'name': '.'}]).info.question[0].name.labels, ())

    def test_presentation_escapes(self) -> None:
        from pcapkit.protocols.application.dns.schema import name_to_text, text_to_labels

        labels = (b'a.b', b'c\\d', b'e f', b'\x00\xff')
        text = name_to_text(labels)
        self.assertEqual(text, 'a\\.b.c\\\\d.e\\032f.\\000\\255.')
        self.assertEqual(text_to_labels(text), labels)
        self.assertEqual(name_to_text(()), '.')
        self.assertEqual(text_to_labels(''), ())

    def test_malformed_names_are_refused(self) -> None:
        from pcapkit.protocols.application.dns.schema import make_name, read_name, text_to_labels
        from pcapkit.utilities.exceptions import CaughtByCaller, ProtocolError

        cases = (
            (b'\xc0\x00', 0, {}),                    # a pointer to itself loops
            (b'\x01a\xc0\x00', 0, {}),               # so does one to a label before it
            (b'\x41ab', 0, {}),                      # extended label type (RFC 6891 section 5)
            (b'\x05ab', 0, {}),                      # label past the end
            (b'\x01a', 0, {}),                       # no root label
            (b'\xc0', 0, {}),                        # pointer past the end
            (b'\x01a\xc0\x00', 0, {'compression': False}),
        )
        with CaughtByCaller(ProtocolError):
            for data, pos, kwargs in cases:
                with self.subTest(data=data), self.assertRaises(ProtocolError):
                    read_name(data, pos, **kwargs)
            for labels, kwargs in (((b'',), {}), ((b'x' * 64,), {}), ((b'a',), {'literal': 2}),
                                   ((b'a',), {'pointer': 0x4000}), ((b'a',), {'literal': True})):
                with self.subTest(labels=labels, kwargs=kwargs), self.assertRaises(ProtocolError):
                    make_name(labels, **kwargs)
            for text in ('a..b', 'a\\', 'a\\25'):
                with self.subTest(text=text), self.assertRaises(ProtocolError):
                    text_to_labels(text)


class DNSRDataTests(DNSTestCase):
    """Each registered RDATA decodes to its RFC's fields."""

    def test_rdata_fields(self) -> None:
        from ipaddress import IPv6Address

        from pcapkit.protocols.application.dns import data

        ns = b'\x02ns\xc0\x10'
        cases = (
            (2, ns, data.NS, lambda r: r.nsdname.name, 'ns.example.com.'),
            (12, ns, data.PTR, lambda r: r.ptrdname.name, 'ns.example.com.'),
            (6, ns + b'\x05admin\xc0\x10' + struct.pack('!5I', 1, 2, 3, 4, 5), data.SOA,
             lambda r: (r.mname.name, r.rname.name, r.serial, r.refresh, r.retry, r.expire, r.minimum),
             ('ns.example.com.', 'admin.example.com.', 1, 2, 3, 4, 5)),
            (15, b'\x00\x0a' + ns, data.MX, lambda r: (r.preference, r.exchange.name), (10, 'ns.example.com.')),
            (16, b'\x05hello\x00\x03abc', data.TXT, lambda r: r.strings, (b'hello', b'', b'abc')),
            (28, bytes(15) + b'\x01', data.AAAA, lambda r: r.address, IPv6Address('::1')),
            (33, struct.pack('!3H', 1, 2, 5060) + b'\x03sip\x00', data.SRV,
             lambda r: (r.priority, r.weight, r.port, r.target.name), (1, 2, 5060, 'sip.')),
            (257, b'\x80\x05issueca.example', data.CAA, lambda r: (r.flags, r.critical, r.tag, r.value),
             (128, True, b'issue', b'ca.example')),
        )
        for rtype, rdata, model, view, expected in cases:
            with self.subTest(type=rtype):
                record = self.assertRoundTrip(_answer(_rr(rtype, rdata))).info.answer[0]
                self.assertIsInstance(record.rdata, model)
                self.assertEqual(view(record.rdata), expected)
                self.assertEqual(record.rdlength, len(rdata))

    def test_unknown_and_rejected_rdata_stay_raw(self) -> None:
        from pcapkit.const.dns.rr_type import RRType

        cases = (
            (99, b'\x01\x02\x03'),             # SPF: no decoder registered
            (1, b'\x01\x02\x03\x04\x05'),      # an A record is four octets
            (28, b'\x00'),                     # an AAAA record is sixteen
            (2, b'\x02ns\x00\x00'),            # octets past the name
            (2, b''),                          # no name at all
            (6, b'\x00\x00' + bytes(19)),      # SOA one octet short
            (16, b''),                         # TXT needs a character-string
            (16, b'\x05ab'),                   # string past the RDATA
            (257, b'\x00\x00'),                # CAA with an empty tag
            (65280, b'\xff'),                  # private use
        )
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            for rtype, rdata in cases:
                with self.subTest(type=rtype, rdata=rdata):
                    record = self.assertRoundTrip(_answer(_rr(rtype, rdata))).info.answer[0]
                    self.assertEqual(record.rdata, rdata)
                    self.assertEqual(int(record.type), rtype)
        self.assertEqual(int(RRType.ANY), 255)

    def test_edns_options(self) -> None:
        from pcapkit.protocols.application.dns import data

        cases = (
            (8, b'\x00\x01\x18\x00\xc6\x33\x64', data.ClientSubnet,
             data.ClientSubnet(family=1, source_prefix=24, scope_prefix=0, address=b'\xc6\x33\x64')),
            (10, bytes(range(24)), data.Cookie, data.Cookie(client=bytes(range(8)), server=bytes(range(8, 24)))),
            (11, b'', data.TCPKeepalive, data.TCPKeepalive(timeout=None)),
            (11, b'\x02\x58', data.TCPKeepalive, data.TCPKeepalive(timeout=600)),
            (15, b'\x00\x12blocked', data.ExtendedError, data.ExtendedError(info_code=18, extra_text=b'blocked')),
            (12, bytes(5), bytes, bytes(5)),                # Padding: no decoder registered
            (10, bytes(9), bytes, bytes(9)),                # a cookie of 9 octets is neither form
            (11, b'\x01', bytes, b'\x01'),                  # keepalive of one octet
            (8, b'\x00\x01', bytes, b'\x00\x01'),           # client subnet header cut short
        )
        for code, value, model, expected in cases:
            with self.subTest(code=code, value=value):
                option = struct.pack('!HH', code, len(value)) + value
                octets = struct.pack('!6H', 1, 0, 0, 0, 0, 1) + b'\x00' + struct.pack(
                    '!HHIH', 41, 512, 0, len(option)) + option
                parsed = self.assertRoundTrip(octets).info.additional[0].options[0]
                self.assertIsInstance(parsed.data, model)
                self.assertEqual(parsed.data, expected)
                self.assertEqual(parsed.length, len(value))

    def test_malformed_options_keep_the_rdata(self) -> None:
        octets = struct.pack('!6H', 1, 0, 0, 0, 0, 1) + b'\x00' + struct.pack('!HHIH', 41, 512, 0, 5) + b'\x00\x0a\x00\x08\x01'
        opt = self.assertRoundTrip(octets).info.additional[0]
        self.assertEqual(opt.options, b'\x00\x0a\x00\x08\x01')


class DNSMakeTests(DNSTestCase):
    """What ``make`` writes, and what it refuses."""

    def test_header_and_counts(self) -> None:
        from pcapkit.const.dns.opcode import Opcode
        from pcapkit.const.dns.rcode import RCode
        from pcapkit.protocols.application.dns.protocol import DNS

        dns = DNS.build(id=0xABCD, qr=True, opcode=Opcode.Notify, aa=True, tc=True, rd=True, ra=True, z=1,
                        ad=True, cd=True, rcode=RCode.Refused, trailer=b'\x01')
        self.assertEqual(dns.data, struct.pack('!6H', 0xABCD, 0xA7F5, 0, 0, 0, 0) + b'\x01')
        self.assertEqual(DNS.build(opcode=6, rcode=3).data[2:4], b'\x30\x03')

    def test_every_rdata_and_option_builds_from_keywords(self) -> None:
        from pcapkit.const.dns.option import Option
        from pcapkit.const.dns.rr_type import RRType
        from pcapkit.protocols.application.dns.protocol import DNS

        records = [{'type': code} for code in DNS.__rdata__] + [{'type': RRType.SPF, 'rdata': b'x'}]
        options = [{'code': code} for code in DNS.__option__] + [{'code': Option.Padding, 'data': bytes(3)}]
        dns = DNS.build(answer=records, additional=[{'type': RRType.OPT, 'options': options}])
        self.assertEqual(DNS(dns.data).data, dns.data)
        self.assertEqual(len(DNS(dns.data).info.additional[0].options), len(options))

    def test_refusals(self) -> None:
        from pcapkit.const.dns.rr_type import RRType
        from pcapkit.protocols.application.dns.protocol import DNS
        from pcapkit.utilities.exceptions import CaughtByCaller, ProtocolError

        cases = (
            {'id': 1 << 16},
            {'opcode': 'Query'},
            {'rcode': 16},
            {'qr': 2},
            {'question': [b'\x00']},
            {'question': [{'name': 3}]},
            {'answer': [('www', 1)]},
            {'answer': [{'type': RRType.SPF, 'rdata': {'x': 1}}]},
            {'answer': [{'type': RRType.TXT, 'rdata': {'strings': [b'x' * 256]}}]},
            {'answer': [{'type': RRType.CAA, 'rdata': {'tag': b''}}]},
            {'answer': [{'type': RRType.CAA, 'rdata': {'value': 'text'}}]},
            {'additional': [{'type': RRType.OPT, 'options': [b'\x00']}]},
            {'additional': [{'type': RRType.OPT, 'options': [{'code': 12, 'data': {'x': 1}}]}]},
            {'additional': [{'type': RRType.OPT, 'options': [{'code': 10, 'data': {'server': bytes(4)}}]}]},
            {'additional': [{'type': RRType.OPT, 'options': [{'code': 8, 'data': {'address': 'x'}}]}]},
            {'additional': [{'type': RRType.OPT, 'options': [{'code': 15, 'data': {'extra_text': 'x'}}]}]},
            {'trailer': 'x'},
            {'message_length': -1},
        )
        with CaughtByCaller(ProtocolError):
            for kwargs in cases:
                with self.subTest(kwargs=kwargs), self.assertRaises(ProtocolError):
                    DNS.build(**kwargs)

    def test_generic_form_opt_parses_as_opt(self) -> None:
        from pcapkit.const.dns.rr_class import RRClass
        from pcapkit.const.dns.rr_type import RRType
        from pcapkit.protocols.application.dns.data import OPT
        from pcapkit.protocols.application.dns.protocol import DNS

        dns = DNS.build(additional=[{'name': '.', 'type': RRType.OPT, 'class': RRClass.get(1232), 'ttl': 0x8000,
                                     'rdata': b''}])
        opt = dns.info.additional[0]
        self.assertIsInstance(opt, OPT)
        self.assertEqual((opt.udp_payload_size, opt.do, opt.options), (1232, True, ()))
        self.assertRoundTrip(dns.data)


class DNSFramingTests(DNSTestCase):
    """The TCP length field (RFC 1035 section 4.2.2, RFC 7766 section 8)."""

    def _segment(self, payload: bytes, dport: int = 53) -> bytes:
        return struct.pack('!HHIIBBHHH', 40000, dport, 1, 0, 5 << 4, 0x18, 65535, 0, 0) + payload

    def test_framed_message(self) -> None:
        from pcapkit.protocols.application.dns.protocol import DNS

        framed = struct.pack('!H', len(QUERY)) + QUERY
        dns = self.assertRoundTrip(framed, framed=True)
        self.assertEqual(dns.info.length, len(QUERY))
        self.assertEqual(dns.info.id, 0x1234)
        self.assertEqual(dns.length, len(framed))
        # The length is sniffed when not given, as a TCP segment carries it.
        self.assertEqual(DNS(framed).info.get('length'), len(QUERY))
        self.assertNotIn('length', DNS(QUERY).info)
        self.assertEqual(DNS.build(id=0x1234, framed=True).data, b'\x00\x0c\x12\x34' + bytes(10))
        self.assertEqual(DNS.build(message_length=99).data[:2], b'\x00\x63')

    def test_tcp_segment_chains_messages(self) -> None:
        from pcapkit.protocols.transport.tcp.protocol import TCP

        first = struct.pack('!H', len(QUERY)) + QUERY
        second = struct.pack('!H', len(RESPONSE)) + RESPONSE
        segment = self._segment(first + second + b'\x00\x30\x00')
        tcp = TCP(segment)
        self.assertEqual(str(tcp.protochain), 'TCP:DNS:DNS:Raw')
        self.assertEqual(tcp.payload.info.id, 0x1234)
        self.assertEqual(tcp.payload.payload.info.answer[1].rdata.address.packed, b'\x5d\xb8\xd8\x22')
        self.assertEqual(TCP.from_data(tcp.info).data, segment)

    def test_message_the_segment_ends_inside_stays_raw(self) -> None:
        from pcapkit.protocols.transport.tcp.protocol import TCP

        cut = (struct.pack('!H', len(QUERY)) + QUERY)[:20]
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            tcp = TCP(self._segment(cut))
        self.assertEqual(str(tcp.protochain), 'TCP:Raw')
        self.assertIn('DNS', str(tcp.payload.info.error))

    def test_udp_datagram(self) -> None:
        from pcapkit.protocols.transport.udp.protocol import UDP

        datagram = struct.pack('!HHHH', 5353, 53, 8 + len(RESPONSE), 0) + RESPONSE
        udp = UDP(datagram)
        self.assertEqual(str(udp.protochain), 'UDP:DNS')
        self.assertNotIn('length', udp.payload.info)
        self.assertEqual(UDP.from_data(udp.info).data, datagram)

    def test_short_framed_length_is_refused(self) -> None:
        from pcapkit.protocols.application.dns.protocol import DNS
        from pcapkit.utilities.exceptions import CaughtByCaller, ProtocolError

        with CaughtByCaller(ProtocolError), self.assertRaises(ProtocolError):
            DNS(b'\x00\x05' + bytes(12), framed=True)


def _framed(message: bytes) -> bytes:
    return struct.pack('!H', len(message)) + message


def _query(ident: int, flags: int, labels: 'tuple[bytes, ...]', *, opt: bool = False, qtype: int = 1) -> bytes:
    """A one-question query, with an empty OPT record if ``opt``."""
    name = b''.join(bytes([len(label)]) + label for label in labels) + b'\x00'
    body = name + struct.pack('!HH', qtype, 1)
    if opt:
        body += b'\x00' + struct.pack('!HHIH', 41, 4096, 0, 0)
    return struct.pack('!6H', ident, flags, 1, 0, 0, int(opt)) + body


class DNSSniffTests(DNSTestCase):
    """What the framing sniff takes for a message."""

    def test_sections_end(self) -> None:
        from pcapkit.protocols.application.dns.protocol import _frames_message, _sections_end

        def header(qd: int = 0, an: int = 0) -> bytes:
            return struct.pack('!6H', 1, 0, qd, an, 0, 0)

        self.assertEqual(_sections_end(QUERY), len(QUERY))
        self.assertEqual(_sections_end(RESPONSE), len(RESPONSE))
        self.assertEqual(_sections_end(QUERY + b'\x00'), len(QUERY))
        for octets in (bytes(11),                                       # shorter than a header
                       header(qd=1) + b'\x00\x00\x01',               # question type past the end
                       header(an=1) + b'\x00' + bytes(9),              # record header past the end
                       header(an=1) + b'\x00' + bytes(8) + b'\x00\x05',  # RDATA past the end
                       header(qd=1) + b'\x41a\x00' + bytes(4)):       # a malformed name
            with self.subTest(octets=octets):
                self.assertIsNone(_sections_end(octets))
        self.assertTrue(_frames_message(_framed(QUERY)))
        self.assertFalse(_frames_message(QUERY))
        self.assertFalse(_frames_message(b'\x00'))
        # A length that counts a message which does not decode either.
        self.assertFalse(_frames_message(b'\x00\x0c' + header(qd=1)))
        # A framed message that ends short of its length, the plain reading decoding.
        self.assertFalse(_frames_message(_framed(struct.pack('!6H', 0, 0, 0, 0, 0, 0) + b'\x00')))

    def test_flags_of_zero_frame(self) -> None:
        """The plain reading of a framed message with flags of zero decodes too.

        The length is read as the ID and the real ID as the flags, so the
        question count is the zero flags: the plain reading then stops short
        of the end, or reads an octet run as an RDLENGTH counting the rest.

        """
        from pcapkit.protocols.application.dns.protocol import DNS, _frames_message, _sections_end

        # The reviewer's natural case: flags 0, an OPT record, and ``a.``.
        query = _query(0x2816, 0, (b'a',), opt=True)
        framed = _framed(query)
        self.assertIsNotNone(_sections_end(framed))
        self.assertTrue(_frames_message(framed))
        dns = self.assertRoundTrip(framed)
        self.assertEqual((dns.info.length, dns.info.id), (len(query), 0x2816))
        self.assertEqual(dns.info.question[0].name.name, 'a.')

        cases = []  # type: list[bytes]
        for labels in ((), (b'a',), (b'ab',), (b'abc',), (b'a', b'b'), (b'gjcpu', b'h'), (b'x' * 7,)):
            for opt in (False, True):
                for ident in (0, 1, 0x0C00, 0x1234, 0xFFFF):
                    for qtype in (1, 0x038E, 255):
                        cases.append(_query(ident, 0, labels, opt=opt, qtype=qtype))
        for query in cases:
            framed = _framed(query)
            for octets, count in ((framed, 1), (framed + framed, 2), (framed + framed + framed, 3),
                                  (framed + framed[:5], 1)):
                with self.subTest(octets=octets):
                    self.assertTrue(_frames_message(octets))
                    dns = DNS(octets)
                    self.assertEqual(dns.data, octets)
                    self.assertEqual(str(dns.protochain).count('DNS'), count)
                    self.assertEqual(DNS.from_data(dns.info).data, octets)

    def test_a_second_exact_message_decides_a_plain_reading_to_the_end(self) -> None:
        """Two framed answers, no question, flags of zero: the plain reading of
        the pair reads the second length as an RDLENGTH reaching the end.
        """
        from pcapkit.protocols.application.dns.protocol import DNS, _frames_message, _sections_end

        record = b'\x00' + struct.pack('!HHIH', 1, 1, 27, 0)
        framed = _framed(struct.pack('!6H', 7, 0, 0, 1, 0, 0) + record)
        octets = framed + framed
        self.assertEqual(_sections_end(octets), len(octets))
        self.assertTrue(_frames_message(octets))
        dns = DNS(octets)
        self.assertEqual(str(dns.protochain), 'DNS:DNS')
        self.assertEqual(DNS.from_data(dns.info).data, octets)

    def test_a_plain_message_whose_id_is_its_length_stays_plain(self) -> None:
        from pcapkit.protocols.application.dns.protocol import DNS, _frames_message

        for labels in ((b'a',), (b'example', b'com')):
            for flags in (0, 0x0100, 0x8180):
                for opt in (False, True):
                    query = _query(0, flags, labels, opt=opt)
                    query = struct.pack('!H', len(query) - 2) + query[2:]
                    with self.subTest(query=query):
                        self.assertFalse(_frames_message(query))
                        info = self.assertRoundTrip(query).info
                        self.assertNotIn('length', info)
                        self.assertEqual(info.id, len(query) - 2)
        self.assertNotIn('length', DNS(_answer(_rr(1, bytes(4)))).info)


class DNSEdgeTests(DNSTestCase):
    """Paths the cases above leave out."""

    def test_rcode_skips_other_additional_records(self) -> None:
        from pcapkit.const.dns.rcode import RCode
        from pcapkit.const.dns.rr_type import RRType
        from pcapkit.protocols.application.dns.protocol import DNS

        dns = DNS.build(rcode=2, additional=[{'name': 'a', 'type': RRType.A},
                                             {'type': RRType.OPT, 'extended_rcode': 1}])
        self.assertEqual(int(dns.rcode), 18)
        self.assertIs(DNS.build(rcode=2, additional=[{'type': RRType.A}]).rcode, RCode.ServFail)

    def test_empty_unknown_rdata_and_option(self) -> None:
        from pcapkit.const.dns.option import Option
        from pcapkit.const.dns.rr_type import RRType
        from pcapkit.protocols.application.dns.protocol import DNS

        dns = DNS.build(answer=[{'type': RRType.SPF}],
                        additional=[{'type': RRType.OPT, 'options': [{'code': Option.Padding}]}])
        self.assertEqual(dns.info.answer[0].rdata, b'')
        self.assertEqual(dns.info.additional[0].options[0].data, b'')

    def test_name_running_past_its_rdata_stays_raw(self) -> None:
        octets = _answer(_rr(2, b'\x02ns')) + b'\x00'
        info = self.assertRoundTrip(octets).info
        self.assertEqual(info.answer[0].rdata, b'\x02ns')
        self.assertEqual(info.trailer, b'\x00')

    def test_compression_reuses_a_recorded_name(self) -> None:
        from pcapkit.protocols.application.dns.protocol import DNS

        name = DNS.build(question=[{'name': 'example.com'}]).info.question[0].name
        dns = DNS.build(compress=True, question=[{'name': name}, {'name': 'www.example.com'}])
        self.assertTrue(dns.data.endswith(b'\x03www\xc0\x0c\x00\x01\x00\x01'))

    def test_offsets_past_the_pointer_limit_are_not_recorded(self) -> None:
        from pcapkit.const.dns.rr_type import RRType
        from pcapkit.protocols.application.dns.protocol import DNS

        bulk = {'type': RRType.TXT, 'rdata': {'strings': [b'x' * 255] * 65}}
        late = {'name': 'late.example', 'type': RRType.A}
        dns = DNS.build(compress=True, answer=[bulk, late, late])
        first, second = dns.info.answer[1:]
        self.assertEqual((first.name.literal, first.name.pointer), (2, None))
        self.assertEqual((second.name.literal, second.name.pointer), (2, None))
        self.assertRoundTrip(dns.data)


class DNSRegistryTests(DNSTestCase):
    """``register_dns_rdata`` and ``register_dns_option`` write the class maps."""

    def test_registration(self) -> None:
        from pcapkit.const.dns.option import Option
        from pcapkit.const.dns.rr_type import RRType
        from pcapkit.foundation.registry.protocols import register_dns_option, register_dns_rdata
        from pcapkit.protocols.application.dns.protocol import DNS
        from pcapkit.utilities.warnings import RegistryWarning

        pair = (lambda code, data, *, message, offset: data.hex(),
                lambda code, data, *, offset, table: bytes.fromhex(data))
        rdata, option = dict(DNS.__rdata__), dict(DNS.__option__)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('error')
                register_dns_rdata(RRType.A, 'a')
                register_dns_rdata(RRType.SPF, pair)
                register_dns_option(Option.COOKIE, 'cookie')
                register_dns_option(Option.Padding, (lambda code, data: len(data),
                                                     lambda code, data: bytes(data)))
            with self.assertWarns(RegistryWarning):
                register_dns_rdata(RRType.A, 'unknown')
            with self.assertWarns(RegistryWarning):
                register_dns_option(Option.COOKIE, 'unknown')

            record = DNS(_answer(_rr(99, b'\xab\xcd'))).info.answer[0]
            self.assertEqual(record.rdata, 'abcd')
            self.assertEqual(DNS.build(answer=[{'type': RRType.SPF, 'rdata': 'ef'}]).data[-3:], b'\x00\x01\xef')
            self.assertEqual(DNS(_answer(_rr(1, bytes(4)))).info.answer[0].rdata, bytes(4))
            padded = DNS.build(additional=[{'type': RRType.OPT, 'options': [{'code': Option.Padding,
                                                                             'data': [0, 0, 0]}]}])
            self.assertEqual(padded.info.additional[0].options[0].data, 3)

            # Handing the shipped entries back restores the maps as shipped.
            with self.assertWarns(RegistryWarning):
                register_dns_rdata(RRType.A, rdata[RRType.A])
            with self.assertWarns(RegistryWarning):
                register_dns_option(Option.COOKIE, option[Option.COOKIE])
            del DNS.__rdata__[RRType.SPF]
            del DNS.__option__[Option.Padding]
            self.assertEqual(dict(DNS.__rdata__), rdata)
            self.assertEqual(dict(DNS.__option__), option)
        finally:
            DNS.__rdata__.clear()
            DNS.__rdata__.update(rdata)
            DNS.__option__.clear()
            DNS.__option__.update(option)

    def test_wrappers_refuse_a_bad_code_or_name(self) -> None:
        from pcapkit.const.dns.option import Option
        from pcapkit.const.dns.rr_type import RRType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.registry.protocols import register_dns_option, register_dns_rdata
        from pcapkit.protocols.application.dns.protocol import DNS
        from pcapkit.utilities.exceptions import RegistryError

        rdata, option = dict(DNS.__rdata__), dict(DNS.__option__)
        cases = (
            (register_dns_rdata, 1, 'a'),
            (register_dns_rdata, LinkType(1), 'a'),
            (register_dns_rdata, Option.COOKIE, 'a'),
            (register_dns_rdata, RRType.A, 'nosuch'),
            (register_dns_option, 10, 'cookie'),
            (register_dns_option, RRType.A, 'cookie'),
            (register_dns_option, Option.COOKIE, 'nosuch'),
        )
        for func, code, meth in cases:
            with self.subTest(func=func.__name__, code=code, meth=meth), self.assertRaises(RegistryError):
                func(code, meth)
        self.assertEqual(dict(DNS.__rdata__), rdata)
        self.assertEqual(dict(DNS.__option__), option)


class DNSConstTests(DNSTestCase):
    """The crawled registries name what IANA assigns."""

    def test_members(self) -> None:
        from pcapkit.const.dns.opcode import Opcode
        from pcapkit.const.dns.option import Option
        from pcapkit.const.dns.rcode import RCode
        from pcapkit.const.dns.rr_class import RRClass
        from pcapkit.const.dns.rr_type import RRType

        self.assertEqual((RRClass.IN, RRClass.CH, RRClass.HS, RRClass.NONE, RRClass.ANY), (1, 3, 4, 254, 255))
        self.assertEqual((RRType.A, RRType.NSAP_PTR, RRType.OPT, RRType.ANY, RRType.CAA), (1, 23, 41, 255, 257))
        self.assertEqual((Opcode.Query, Opcode.IQuery, Opcode.DSO), (0, 1, 6))
        self.assertEqual((RCode.NotAuth, RCode.BADVERS, RCode.BADCOOKIE), (9, 16, 23))
        self.assertEqual((Option.edns_client_subnet, Option.COOKIE, Option.Extended_DNS_Error), (8, 10, 15))
        self.assertEqual(RRClass.get(300).name, 'Unassigned')
        self.assertEqual(RCode.get(3900).name, 'Reserved_for_Private_Use')


if __name__ == '__main__':
    unittest.main()
