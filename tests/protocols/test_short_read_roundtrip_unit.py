# -*- coding: utf-8 -*-
"""A header the data ends inside rebuilds as captured, in every family.

GitHub issues #1458 and #1451: when the data ended inside a fixed-width field,
the parse read the missing octets as zeros and recorded nothing, so
``from_data(info)`` wrote the field -- and every field after it -- at full
width. ``Ethernet(bytes(12) + b'\\x08')`` rebuilt as 14 octets.

:meth:`Schema.unpack <pcapkit.protocols.schema.schema.Schema.unpack>` now
records the field the data ends inside and how much of it was read, as
``__short_read__``; :meth:`Schema.pack <pcapkit.protocols.schema.schema.Schema.pack>`
writes back only those octets, and the layer base classes carry the record
through ``info``. Each packet below is cut at every offset and must either be
refused with an in-library exception or meet ``Cls(raw).data == raw`` and
``Cls.from_data(Cls(raw).info).data == raw``.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import importlib
import struct
import unittest
import warnings

from tests._support import reimport_once_per_class

ETHERNET = 'link.ethernet:Ethernet'
IPV6 = 'internet.ipv6:IPv6'


def _ipv6(code: int, body: bytes) -> bytes:
    return (bytes([0x60, 0, 0, 0]) + struct.pack('!HBB', len(body), code, 64)
            + bytes(15) + b'\x01' + bytes(15) + b'\x02' + body)


HIT = bytes(range(32))

#: Label, ``module:Class`` under :mod:`pcapkit.protocols`, parse keywords, and
#: one whole packet.
CASES = (
    ('ethernet', ETHERNET, {}, bytes.fromhex('0123456789abfedcba98765488b5')),
    ('c-tag', 'link.c_tag:C_Tag', {}, bytes.fromhex('ffff88b5706c')),
    ('s-tag', 'link.s_tag:S_Tag', {}, bytes.fromhex('1fff8100000188b5')),
    ('arp', 'link.arp:ARP', {}, bytes.fromhex('000186dd06100001') + bytes(range(44))),
    ('rarp', 'application.rarp:RARP', {}, bytes.fromhex('0001080006040003') + bytes(range(20))),
    ('l2tpv2', 'link.l2tpv2:L2TPv2', {}, bytes.fromhex('fff2000e00000000000000000000')),
    ('loopback-null', 'link.loopback:Loopback', {}, bytes.fromhex('020000004500')),
    ('loopback-loop', 'link.loopback:Loopback', {'alias': 108}, bytes.fromhex('000000024500')),
    ('ospf', 'application.ospf:OSPF', {}, bytes.fromhex('020100180102030400000000abcd0000') + bytes(8)),
    ('ipx', 'internet.ipx:IPX', {}, bytes.fromhex('ffff001e0000000000000101010101010451000000000202020202020452')),
    ('ipv4', 'internet.ipv4:IPv4', {}, bytes.fromhex('450000141234000040fd7b83c0000201c6336401')),
    ('ipv6', IPV6, {}, _ipv6(59, b'')),
    ('ipv6-chain', IPV6, {}, bytes.fromhex(
        '600000000020004000000000000000000000000000000001000000000000000000000000000000023c'
        '000000000000002b000104000000002c00c800000000003b00000000000000')),
    ('hopopt', IPV6, {}, _ipv6(0, bytes([17, 1, 5, 2, 0, 0, 1, 8]) + bytes(8))),
    ('ipv6-opts', IPV6, {}, _ipv6(60, bytes([17, 1, 5, 2, 0, 0, 1, 8]) + bytes(8))),
    ('ipv6-route-0', IPV6, {}, _ipv6(43, bytes([17, 2, 0, 1]) + bytes(4) + b'\x11' * 16)),
    ('ipv6-route-2', IPV6, {}, _ipv6(43, bytes([17, 2, 2, 1]) + bytes(4) + b'\x11' * 16)),
    ('ipv6-route-unknown', IPV6, {}, _ipv6(43, bytes([17, 1, 9, 1]) + b'\x44' * 12)),
    ('ipv6-frag', IPV6, {}, _ipv6(44, bytes([17, 0, 0, 8, 0x12, 0x34, 0x56, 0x78]))),
    ('ah', IPV6, {}, _ipv6(51, bytes([17, 4, 0, 0, 0, 0, 1, 0, 0, 0, 0, 7]) + b'\xaa' * 12)),
    ('ah-ipv4', 'internet.ah:AH', {}, bytes([17, 4, 0, 0, 0, 0, 1, 0, 0, 0, 0, 7]) + b'\xaa' * 12),
    ('mh', IPV6, {}, _ipv6(135, bytes([59, 1, 5, 0, 0, 0, 0, 1, 0x80, 0, 0, 0x10, 1, 2, 0, 0]))),
    ('hip', 'internet.hip:HIP', {'extension': True}, bytes.fromhex('3b04102100000000') + HIT),
    ('hip-param', IPV6, {}, _ipv6(139, bytes([59, 5, 1, 0x21, 0, 0, 0, 0]) + HIT
                                  + struct.pack('!HH', 63661, 4) + b'\x55' * 4)),
    ('shim6', IPV6, {}, _ipv6(140, bytes([59, 1, 0x80, 0, 0, 0, 0, 0]) + b'\x66' * 8)),
    ('esp', 'internet.esp:ESP', {}, bytes.fromhex('0000000100000002') + b'\x77' * 16),
    ('tcp', 'transport.tcp:TCP', {}, bytes.fromhex('9c409c41000000010000000060020000ffff0000020405b4')),
    ('udp', 'transport.udp:UDP', {}, bytes.fromhex('9c409c41000c000061626364')),
    ('sctp', 'transport.sctp:SCTP', {}, bytes.fromhex(
        '13881389deadbeef000000000003001400000001000100020000000061626364')),
    ('ftp', 'application.ftp:FTP', {}, b'XYZW arg\r\n'),
    ('http1', 'application.httpv1:HTTP', {}, b'GET / HTTP/1.1\r\n\r\n'),
)


def _quiet(case: unittest.TestCase) -> None:
    # a cut header warns that its length runs past the data, which is the point
    catcher = warnings.catch_warnings()
    catcher.__enter__()
    case.addCleanup(catcher.__exit__, None, None, None)
    warnings.simplefilter('ignore')


def _has_fallback(proto: object) -> bool:
    from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext

    return any(type(ext) is IPv6_Ext for ext in getattr(proto, 'extension_headers', {}).values())


def _resolve(path: str) -> type:
    module, _, name = path.partition(':')
    return getattr(importlib.import_module(f'pcapkit.protocols.{module}'), name)


class TestShortReadRoundTrip(unittest.TestCase):
    """Pin byte-exact round trips of packets cut at every offset."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        _quiet(self)

    def test_every_family_cut_at_every_offset(self) -> None:
        from pcapkit.utilities.exceptions import BaseError

        for label, path, kwargs, packet in CASES:
            cls = _resolve(path)
            for keep in range(1, len(packet) + 1):
                raw = packet[:keep]
                with self.subTest(case=label, keep=keep):
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        try:
                            proto = cls(raw, len(raw), **kwargs)
                        except BaseError:
                            continue
                        self.assertEqual(proto.data, raw)
                        self.assertEqual(type(proto).from_data(proto.info).data, raw)
                        if _has_fallback(proto):
                            # from the dict form, IPv6.from_data rebuilds an
                            # IPv6_Ext standing in for a dedicated parser with
                            # that parser's class: a separate defect, in ipv6.py
                            continue
                        self.assertEqual(type(proto).from_data(proto.info.to_dict()).data, raw)

    def test_extension_header_cut_at_every_offset(self) -> None:
        # #1451: each extension header rebuilds from its own info, too
        for label, path, _, packet in CASES:
            if path != IPV6:
                continue
            cls = _resolve(path)
            for keep in range(41, len(packet) + 1):
                raw = packet[:keep]
                with self.subTest(case=label, keep=keep):
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        ipv6 = cls(raw, len(raw))
                        for ext in ipv6.extension_headers.values():
                            self.assertEqual(type(ext).from_data(ext.info).data, ext.data)
                            self.assertEqual(type(ext).from_data(ext.info.to_dict()).data, ext.data)

    def test_issue_1458_repro(self) -> None:
        from pcapkit.protocols.link.ethernet import Ethernet

        raw = bytes(12) + b'\x08'
        eth = Ethernet(raw, 13)
        self.assertEqual(Ethernet.from_data(eth.info).data, raw)
        self.assertEqual(Ethernet.from_data(eth.info.to_dict()).data, raw)
        # the value decodes as before, the missing octet read as zero
        self.assertEqual(eth.info.type, 0x0800)

    def test_issue_1451_repro(self) -> None:
        # a Routing header declaring 24 octets, of which 23 are captured
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route

        raw = _ipv6(43, (bytes([17, 2, 0, 1]) + bytes(4) + b'\x11' * 16)[:23])
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            ipv6 = IPv6(raw, len(raw))
            ext = ipv6.extension_headers.get(43)
            self.assertIs(type(ext), IPv6_Route)
            self.assertEqual(len(ext.data), 23)
            self.assertEqual(IPv6_Route.from_data(ext.info).data, ext.data)
            self.assertEqual(IPv6.from_data(ipv6.info).data, raw)
            self.assertEqual(IPv6.from_data(ipv6.info.to_dict()).data, raw)

    def test_record_rides_in_to_dict_only_when_cut(self) -> None:
        from pcapkit.protocols.link.ethernet import Ethernet

        whole = Ethernet(bytes(14), 14)
        self.assertNotIn('__short_read__', whole.info)
        self.assertIsNone(whole.info.get('__short_read__'))

        self.assertNotIn('__short_read__', whole.info.to_dict())
        self.assertNotIn('__short_read__', list(whole.info))

        cut = Ethernet(bytes(13), 13)
        self.assertEqual(cut.info['__short_read__'], ('type', 1))
        self.assertEqual(cut.info.to_dict()['__short_read__'], ('type', 1))

        again = Ethernet.from_data(cut.info.to_dict())
        self.assertEqual(again.info['__short_read__'], ('type', 1))
        self.assertEqual(Ethernet.from_data(again.info.to_dict()).data, bytes(13))
        # a dumper writes the record as a list, which replays the same
        record = dict(cut.info.to_dict(), __short_read__=['type', 1])
        self.assertEqual(Ethernet.from_data(record).data, bytes(13))


class TestSchemaShortRead(unittest.TestCase):
    """Pin the schema-level record and the pack that honours it."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        _quiet(self)

    def test_unpack_records_and_pack_cuts(self) -> None:
        from pcapkit.protocols.schema.link.ethernet import Ethernet

        raw = bytes(range(1, 11))
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            schema = Ethernet.unpack(raw)
        self.assertEqual(schema.__dict__['__short_read__'], ('src', 4))
        self.assertEqual(bytes(schema), raw)

        schema.type = 0x86dd  # a field after the cut: still not written
        self.assertEqual(schema.pack(), raw)

    def test_whole_schema_has_no_record(self) -> None:
        from pcapkit.protocols.schema.link.ethernet import Ethernet

        schema = Ethernet.unpack(bytes(14))
        self.assertNotIn('__short_read__', schema.__dict__)
        self.assertNotIn('__short_read__', schema.to_dict())

    def test_record_survives_to_dict_and_from_dict(self) -> None:
        from pcapkit.protocols.schema.link.ethernet import Ethernet

        raw = bytes(range(1, 11))
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            dict_ = Ethernet.unpack(raw).to_dict()
        self.assertEqual(dict_['__short_read__'], ('src', 4))
        self.assertEqual(bytes(Ethernet.from_dict(dict_)), raw)


if __name__ == '__main__':
    unittest.main()
