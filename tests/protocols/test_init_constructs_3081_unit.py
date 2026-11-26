# -*- coding: utf-8 -*-
"""Calling a protocol class parses a file, and constructs from keywords alone (GitHub issue #3081).

The owner took option (A) on #3081: ``Proto(file, ...)`` parses as #2840 left it,
``Proto(**fields)`` constructs as ``build`` does, and ``parse`` is the
explicit form of the first. This module pins each branch:

* :class:`ParseShapeTests` -- a field beside a file is refused by name, through the
  base ``__init__``, the overrides and the versioned family bases, which parse
  without it;
* :class:`ConstructShapeTests` -- keywords alone build what ``build`` builds,
  through the base and every override; a stop given no file is refused unless the
  class takes a field of that name, as IPv4, PPP and IP_Pseudo take ``protocol``,
  where a file makes it the stop again; :obj:`None` for the file is refused;
* :class:`VersionedFamilyTests` -- a versioned family's base gives the member
  ``version`` names, built or parsed, and a member checks ``version`` either way;
* :class:`ParseMethodTests` -- ``parse`` gives what the class call gives, takes the
  class's own parse keywords, and refuses a field;
* :class:`FrameCountTests` -- ``parse`` costs the class call one frame at most, the
  same for a short frame and a deep one, and each ``__init__`` calls
  ``__post_init__`` itself, or through ``_parse`` where it says so (#1610);
  ``test_init_frames_3081_unit`` pins the frames per layer.

This module is unit tier: it builds its own octets and reads no capture.

"""
from __future__ import annotations

import inspect
import struct
import sys
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

if TYPE_CHECKING:
    from typing import Any, Callable

#: Test tier (#1958): exercises signature machinery, which differs by interpreter.
__tier__ = 'ALL'

#: A TCP segment carrying a payload no port of its dispatches.
SEGMENT = wire.tcp(b'payload', seq=1)

#: IPv4, then IPv6, carrying :data:`SEGMENT`.
PACKET = wire.ipv4(SEGMENT, proto=6)
PACKET6 = wire.ipv6(SEGMENT, nxt=6)

#: Ethernet, then :data:`PACKET`.
FRAME = wire.ethernet(PACKET, 0x0800)

#: A TCP header spelled as ``TCP.make`` declares it.
TCP_FIELDS = {'srcport': 50000, 'dstport': 80, 'seq_no': 1, 'syn': True, 'window': 8192}

#: Little-endian PCAP global header: v2.4, snaplen 65535, Ethernet.
GLOBAL = bytes.fromhex('d4c3b2a1' '0200' '0400' '00000000' '00000000' 'ffff0000' '01000000')


def record(data: bytes) -> bytes:
    """A PCAP record of ``data``, captured whole."""
    return struct.pack('<IIII', 1_500_000_000, 0, len(data), len(data)) + data


def ipv4_in_ipv4(count: int) -> bytes:
    """An Ethernet frame of ``count`` IPv4 headers, then :data:`SEGMENT`."""
    data, proto = SEGMENT, 6
    for _ in range(count):
        data, proto = wire.ipv4(data, proto=proto), 4
    return wire.ethernet(data, 0x0800)


def depth(func: 'Callable[[], object]') -> int:
    """How many Python frames deeper than its caller ``func()`` goes, as #1610's test counts."""
    state = {'now': 0, 'most': 0}

    def profile(frame: object, event: str, arg: object) -> None:  # pylint: disable=unused-argument
        if event == 'call':
            state['now'] += 1
            state['most'] = max(state['most'], state['now'])
        elif event == 'return':
            state['now'] -= 1

    sys.setprofile(profile)
    try:
        func()
    finally:
        sys.setprofile(None)
    return state['most']


class ParseShapeTests(unittest.TestCase):
    """Given a file, the class call parses, and a field beside it is refused by name."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def parses(self) -> 'list[tuple[str, Callable[..., object], dict[str, Any]]]':
        """A parse through the base, each kind of override and each family base, as
        the name of the class refusing, the call, and its parse keywords."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.application.dns.protocol import DNS
        from pcapkit.protocols.application.http.protocol import HTTP
        from pcapkit.protocols.internet.hopopt.protocol import HOPOPT
        from pcapkit.protocols.internet.icmp.protocol import ICMP
        from pcapkit.protocols.internet.igmp.protocol import IGMP
        from pcapkit.protocols.internet.ip.protocol import IP
        from pcapkit.protocols.link.l2tp.protocol import L2TP
        from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL
        from pcapkit.protocols.link.loopback.protocol import Loopback
        from pcapkit.protocols.link.netlink.protocol import Netlink
        from pcapkit.protocols.misc.pcap.frame.protocol import Frame
        from pcapkit.protocols.misc.pcap.header.protocol import Header
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG
        from pcapkit.protocols.transport.tcp.protocol import TCP

        header = Header(GLOBAL).info
        block = PCAPNG.build(num=0, sct=1, ctx=None, type=BlockType.Section_Header_Block, block={}).data
        return [
            ('TCP', lambda **kw: TCP(SEGMENT, **kw), {}),
            ('IPv4', lambda **kw: IP(PACKET, **kw), {}),
            ('ICMPv4', lambda **kw: ICMP(b'\x08\x00' + bytes(6), **kw), {'version': 4}),
            ('IGMPv1', lambda **kw: IGMP(bytes([0x11, 0]) + bytes(6), **kw), {}),
            ('LinuxSLL1', lambda **kw: LinuxSLL(bytes(14) + b'\x08\x00' + PACKET, **kw), {'version': 1}),
            ('L2TPv2', lambda **kw: L2TP(b'\x00\x02' + bytes(4), **kw), {}),
            ('HTTPv1', lambda **kw: HTTP(b'GET / HTTP/1.1\r\n\r\n', **kw), {}),
            ('Frame', lambda **kw: Frame(record(FRAME), **kw), {'num': 1, 'header': header}),
            ('PCAPNG', lambda **kw: PCAPNG(block, **kw), {'num': 0, 'sct': 1, 'ctx': None}),
            ('HOPOPT', lambda **kw: HOPOPT(bytes([6, 0, 1, 4, 0, 0, 0, 0]) + SEGMENT, **kw), {}),
            ('DNS', lambda **kw: DNS(bytes(12), **kw), {}),
            ('Loopback', lambda **kw: Loopback(b'\x02\x00\x00\x00' + PACKET, **kw), {}),
            ('Netlink', lambda **kw: Netlink(bytes(16), **kw), {'byteorder': 'little'}),
        ]

    def test_a_field_beside_a_file_is_refused_by_name(self) -> None:
        """One stray keyword is named alone, and several in sorted order; the parse keywords alone parse."""
        for name, parse, keywords in self.parses():
            with self.subTest(cls=name):
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    self.assertEqual(type(parse(**keywords)).__name__, name)
                with self.assertRaisesRegex(TypeError, rf"^{name}: unexpected keyword argument 'src' for a parse$"):
                    parse(**keywords, src='192.0.2.1')
                with self.assertRaisesRegex(
                        TypeError, rf"^{name}: unexpected keyword arguments 'dst', 'src' for a parse$"):
                    parse(**keywords, src='192.0.2.1', dst='192.0.2.2')


class ConstructShapeTests(unittest.TestCase):
    """Given no file, the class call constructs as ``build`` does, and takes no stop."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def assertConstructsAsBuild(self, cls: 'Any', **fields: 'Any') -> 'Any':  # pylint: disable=invalid-name
        """Build ``cls`` both ways from ``fields``, and check they agree."""
        built = cls(**fields)
        expected = cls.build(**fields)
        self.assertIs(type(built), type(expected))
        self.assertEqual(built.data, expected.data)
        self.assertEqual(built.info.to_dict(), expected.info.to_dict())
        self.assertIsNone(built._exlayer)  # pylint: disable=protected-access
        self.assertIsNone(built._exproto)  # pylint: disable=protected-access
        return built

    def test_the_base_and_every_override_construct_as_build_does(self) -> None:
        """An override's own parse keyword is a field where it is given, and left out where not."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.application.dns.protocol import DNS
        from pcapkit.protocols.internet.hopopt.protocol import HOPOPT
        from pcapkit.protocols.link.ethernet.protocol import Ethernet
        from pcapkit.protocols.link.loopback.protocol import Loopback
        from pcapkit.protocols.link.netlink.protocol import Netlink
        from pcapkit.protocols.misc.pcap.frame.protocol import Frame
        from pcapkit.protocols.misc.pcap.header.protocol import Header
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG
        from pcapkit.protocols.transport.tcp.protocol import TCP

        header = Header(GLOBAL).info
        cases = (
            (TCP, TCP_FIELDS),
            (Ethernet, {}),
            (Frame, {'num': 1, 'header': header, 'ts_sec': 1, 'ts_usec': 2, 'packet': b'abcd'}),
            (PCAPNG, {'num': 0, 'sct': 1, 'ctx': None, 'type': BlockType.Section_Header_Block, 'block': {}}),
            (HOPOPT, {}),
            (HOPOPT, {'extension': True}),
            (DNS, {}),
            (DNS, {'framed': True}),
            (Loopback, {}),
            (Loopback, {'byteorder': 'big', 'family': 2}),
            (Netlink, {'payload': b'\x01\x02'}),
            (Netlink, {'byteorder': 'little', 'payload': b'\x01\x02'}),
        )
        for cls, fields in cases:
            with self.subTest(cls=cls.__name__, fields=sorted(fields)):
                self.assertConstructsAsBuild(cls, **fields)
        # NOTE: The keyword reaches ``make``: big-endian AF_INET, and the TCP length field.
        self.assertEqual(Loopback(byteorder='big', family=2).data, b'\x00\x00\x00\x02')
        self.assertEqual(DNS(framed=True).data[:2], b'\x00\x0c')

    def test_a_stop_or_a_length_given_no_file_is_refused_by_name(self) -> None:
        """Construction takes no stop (#2840, ruling 7), and a length bounds only a parse."""
        from pcapkit.corekit.sentinels import NO_VALUE
        from pcapkit.protocols.application.dns.protocol import DNS
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.transport.tcp.protocol import TCP

        calls = (
            (lambda: TCP(layer='Link', **TCP_FIELDS), "^TCP: no file to parse, so no 'layer'$"),
            (lambda: TCP(protocol='TCP', **TCP_FIELDS), "^TCP: no file to parse, so no 'protocol'$"),
            (lambda: TCP(NO_VALUE, 64, **TCP_FIELDS), "^TCP: no file to parse, so no 'length'$"),
            (lambda: TCP(NO_VALUE, 64, layer='Link', protocol='TCP'),
             "^TCP: no file to parse, so no 'length', 'layer', 'protocol'$"),
            (lambda: DNS(layer='Link', framed=True), "^DNS: no file to parse, so no 'layer'$"),
            (lambda: IPv4(layer='Link', protocol=6), "^IPv4: no file to parse, so no 'layer'$"),
        )
        for call, message in calls:
            with self.subTest(message=message), self.assertRaisesRegex(TypeError, message):
                call()

    def test_protocol_is_a_field_without_a_file_and_the_stop_with_one(self) -> None:
        """IPv4, PPP and IP_Pseudo hand ``protocol`` to ``make`` and set no stop, or parse to it."""
        from pcapkit.const.ppp.protocol import Protocol as Enum_Protocol
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.link.ppp.protocol import PPP
        from pcapkit.protocols.misc.checksum.ip_pseudo.protocol import IP_Pseudo
        from pcapkit.protocols.misc.raw.protocol import Raw

        ppp = b'\xff\x03\x00\x21' + PACKET
        pseudo = bytes([192, 0, 2, 1, 192, 0, 2, 2, 0, 6, 0, 20])
        cases = (
            (IPv4, TransType.TCP, {'src': '192.0.2.1', 'dst': '192.0.2.2'}, PACKET, 'IPv4'),
            (PPP, Enum_Protocol.Internet_Protocol_version_4, {}, ppp, 'PPP'),
            (IP_Pseudo, TransType.UDP, {'src': '192.0.2.1', 'dst': '192.0.2.2', 'upper_length': 8}, pseudo, 'TCP'),
        )
        for cls, field, fields, octets, stop in cases:
            with self.subTest(cls=cls.__name__):
                built = self.assertConstructsAsBuild(cls, protocol=field, **fields)
                self.assertEqual(built.info.protocol, field)
                parsed = cls(octets, protocol=stop)
                self.assertEqual(parsed._exproto, stop)  # pylint: disable=protected-access
                self.assertEqual(parsed.info.protocol, cls(octets).info.protocol)
        self.assertIs(type(IPv4(PACKET, protocol='IPv4').payload), Raw)
        self.assertIs(type(PPP(ppp, protocol='PPP').payload), Raw)

    def test_a_file_or_length_keyword_no_field_takes_is_unexpected(self) -> None:
        """It is a field, never the positional of its name, so it is refused as any unknown field is,
        with a hint to pass the octets positionally to parse (#3081)."""
        from pcapkit.protocols.internet.ip.protocol import IP
        from pcapkit.protocols.link.ethernet.protocol import Ethernet
        from pcapkit.utilities.exceptions import ProtocolError, UnexpectedKeyword

        hint = '; to parse, pass the file and its length positionally$'
        calls = (
            (lambda: Ethernet(length=3), "^Ethernet: unexpected keyword\\(s\\): 'length'"),
            (lambda: Ethernet(file=FRAME), "^Ethernet: unexpected keyword\\(s\\): 'file'"),
            (lambda: Ethernet.build(length=3), "^Ethernet: unexpected keyword\\(s\\): 'length'"),
            (lambda: IP(version=4, file=PACKET, length=20), "^IPv4: unexpected keyword\\(s\\): 'file', 'length'"),
        )
        for call, message in calls:
            with self.subTest(message=message), self.assertRaisesRegex(UnexpectedKeyword, message + '.*' + hint):
                call()
        # NOTE: A versioned base's ``__new__`` takes it as a field too, so it reads no octets.
        with self.assertRaisesRegex(ProtocolError, '^IP: no version to build with'):
            IP(file=PACKET)

    def test_a_versioned_base_takes_file_or_length_as_a_field(self) -> None:
        """Each family's ``__new__`` takes them positionally alone, so a keyword is a field there too."""
        from pcapkit.protocols.application.http.protocol import HTTP
        from pcapkit.protocols.internet.icmp.protocol import ICMP
        from pcapkit.protocols.internet.igmp.protocol import IGMP
        from pcapkit.protocols.internet.ip.protocol import IP
        from pcapkit.protocols.link.l2tp.protocol import L2TP
        from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL
        from pcapkit.utilities.exceptions import ProtocolError, UnexpectedKeyword

        hint = '; to parse, pass the file and its length positionally$'
        families = (
            (IP, 4, 'IPv4', PACKET),
            (ICMP, 4, 'ICMPv4', b'\x08\x00' + bytes(6)),
            (IGMP, 1, 'IGMPv1', bytes([0x11, 0]) + bytes(6)),
            (L2TP, 2, 'L2TPv2', b'\x00\x02' + bytes(4)),
            (LinuxSLL, 1, 'LinuxSLL1', bytes(14) + b'\x08\x00' + PACKET),
            (HTTP, 1, 'HTTPv1', b'GET / HTTP/1.1\r\n\r\n'),
        )
        for base, version, member, octets in families:
            for keywords in ({'file': octets}, {'length': len(octets)}):
                with self.subTest(base=base.__name__, keyword=next(iter(keywords))), self.assertRaisesRegex(
                        ProtocolError, f'^{base.__name__}: no version to build with'):
                    base(**keywords)
            with self.subTest(base=base.__name__, version=version), self.assertRaisesRegex(
                    UnexpectedKeyword, f"^{member}: unexpected keyword\\(s\\): 'file'.*{hint}"):
                base(version=version, file=octets)

    def test_a_file_or_length_keyword_beside_a_file_is_a_stray_field(self) -> None:
        """A parse refuses it as a field, rather than taking it for the length."""
        from pcapkit.protocols.link.ethernet.protocol import Ethernet

        with self.assertRaisesRegex(TypeError, "^Ethernet: unexpected keyword argument 'length' for a parse$"):
            Ethernet(FRAME, length=3)
        with self.assertRaisesRegex(TypeError, "^Ethernet: unexpected keyword arguments 'file', 'length' for a parse$"):
            Ethernet.parse(FRAME, file=FRAME, length=3)

    def test_a_field_named_file_or_length_is_that_field(self) -> None:
        """A keyword always wins over the positional of its name, so a field may be called either (#3081)."""
        from pcapkit.protocols.misc.raw.protocol import Raw

        class Sized(Raw):
            """A protocol whose ``make`` takes a ``length`` field."""

            def make(self, *, length: 'Any' = None, packet: bytes = b'', **kwargs: 'Any') -> 'Any':  # type: ignore[override]
                return super().make(packet=packet if length is None else bytes(length), **kwargs)

        class Filed(Raw):
            """A protocol whose ``make`` takes a ``file`` field."""

            def make(self, *, file: 'Any' = None, packet: bytes = b'', **kwargs: 'Any') -> 'Any':  # type: ignore[override]
                return super().make(packet=packet if file is None else file, **kwargs)

        builds = (
            ('Sized(length=3)', lambda: Sized(length=3), bytes(3)),
            ('Sized.build(length=3)', lambda: Sized.build(length=3), bytes(3)),
            ('Sized.from_data(..., length=2)', lambda: Sized.from_data(Sized(length=3).info, length=2), bytes(2)),
            ("Filed(file=b'x')", lambda: Filed(file=b'x'), b'x'),
            ("Filed.build(file=b'x')", lambda: Filed.build(file=b'x'), b'x'),
        )
        for name, build, data in builds:
            with self.subTest(build=name):
                built = build()
                self.assertEqual(built.data, data)
                self.assertIsNone(built.__named_fields__)
        # NOTE: The positional still parses, the field unread.
        self.assertEqual(Sized(b'abc').data, b'abc')

    def test_a_frame_field_named_length_is_that_field(self) -> None:
        """``Frame.pack`` makes its header itself, so it takes the field over as the base's does."""
        from pcapkit.protocols.misc.pcap.frame.data import Frame as Data_Frame
        from pcapkit.protocols.misc.pcap.frame.protocol import Frame
        from pcapkit.protocols.misc.pcap.frame.schema import Frame as Schema_Frame
        from pcapkit.protocols.misc.pcap.header.protocol import Header

        class SizedFrame(Frame, schema=Schema_Frame, data=Data_Frame):  # type: ignore[misc]
            """A PCAP frame whose ``make`` takes a ``length`` field."""

            def make(self, *, length: 'Any' = None, packet: bytes = b'', **kwargs: 'Any') -> 'Any':  # type: ignore[override]
                return super().make(packet=packet if length is None else bytes(length), **kwargs)

        header = Header(GLOBAL).info
        built = SizedFrame(num=1, header=header, ts_sec=1, ts_usec=2, length=4)
        self.assertEqual(built.data, Frame(num=1, header=header, ts_sec=1, ts_usec=2, packet=bytes(4)).data)
        self.assertIsNone(built.__named_fields__)

    def test_none_for_the_file_is_refused_rather_than_constructing(self) -> None:
        """An explicit :obj:`None` is a parse given no octets, fields beside it or not."""
        from pcapkit.protocols.internet.ip.protocol import IP
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.transport.tcp.protocol import TCP

        for call, name in ((lambda: TCP(None, **TCP_FIELDS), 'TCP'),  # type: ignore[call-overload]
                           (lambda: IPv4(None, src='192.0.2.1'), 'IPv4'),  # type: ignore[call-overload]
                           (lambda: IP(None, version=4), 'IP')):  # type: ignore[call-overload]
            with self.subTest(cls=name), self.assertRaisesRegex(
                    TypeError, rf'^{name}: nothing to parse; build one with {name}\.build\(\)$'):
                call()

    def test_the_context_and_the_field_check_are_those_of_build(self) -> None:
        """``context`` is adopted, and an undeclared field raises as ``build`` raises it."""
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.transport.tcp.protocol import TCP
        from pcapkit.utilities.exceptions import UnexpectedKeyword

        registry = ContextRegistry()
        self.assertIs(TCP(**TCP_FIELDS, context=registry)._exctx, registry)  # pylint: disable=protected-access
        with self.assertRaises(UnexpectedKeyword) as called, warnings.catch_warnings():
            warnings.simplefilter('ignore')
            TCP(seq=1)
        with self.assertRaises(UnexpectedKeyword) as built:
            TCP.build(seq=1)
        self.assertEqual(str(called.exception), str(built.exception))


class VersionedFamilyTests(unittest.TestCase):
    """A versioned family's base gives a member on both paths (#2544, #2574)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_the_base_builds_the_member_version_names(self) -> None:
        from pcapkit.const.igmp.type import Type as Enum_Type
        from pcapkit.protocols.application.http.protocol import HTTP
        from pcapkit.protocols.internet.icmp.protocol import ICMP
        from pcapkit.protocols.internet.igmp.protocol import IGMP
        from pcapkit.protocols.internet.ip.protocol import IP
        from pcapkit.protocols.link.l2tp.protocol import L2TP
        from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL

        cases = (
            (IP, 4, 'IPv4', {'src': '192.0.2.1'}),
            (IP, 6, 'IPv6', {}),
            (ICMP, 4, 'ICMPv4', {}),
            (ICMP, 6, 'ICMPv6', {}),
            (IGMP, 1, 'IGMPv1', {}),
            (IGMP, 2, 'IGMPv2', {'type': Enum_Type.IGMPv2_Membership_Report}),
            (IGMP, 3, 'IGMPv3', {}),
            (LinuxSLL, 1, 'LinuxSLL1', {}),
            (LinuxSLL, 2, 'LinuxSLL2', {}),
            (L2TP, 2, 'L2TPv2', {}),
            (HTTP, 1, 'HTTPv1', {'method': 'GET', 'uri': '/'}),
            (HTTP, 2, 'HTTPv2', {}),
        )
        for base, version, member, fields in cases:
            with self.subTest(base=base.__name__, version=version):
                built = base(version=version, **fields)
                self.assertEqual(type(built).__name__, member)
                self.assertEqual(built.data, base.build(version=version, **fields).data)
                # NOTE: The member it gives builds the same, checking ``version`` as its own.
                self.assertEqual(type(built)(version=version, **fields).data, built.data)
                self.assertEqual(type(built)(**fields).data, built.data)

    def test_the_base_refuses_fields_without_a_version(self) -> None:
        from pcapkit.protocols.internet.icmp.protocol import ICMP
        from pcapkit.protocols.internet.ip.protocol import IP
        from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL
        from pcapkit.utilities.exceptions import ProtocolError

        for base in (IP, ICMP, LinuxSLL):
            with self.subTest(base=base.__name__), self.assertRaisesRegex(
                    ProtocolError, f'^{base.__name__}: no version to build with'):
                base(ttl=1)

    def test_a_member_refuses_another_s_version_either_way(self) -> None:
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaisesRegex(ProtocolError, '^IPv4: version=6 names another member$'):
            IPv4(version=6)
        with self.assertRaisesRegex(ProtocolError, '^IPv4: version=6 names another member$'):
            IPv4(PACKET, version=6)

    def test_the_base_parses_to_the_member_its_octets_name(self) -> None:
        """Through the class call and through ``parse`` alike."""
        from pcapkit.protocols.internet.ip.protocol import IP

        for octets, member in ((PACKET, 'IPv4'), (PACKET6, 'IPv6')):
            for parse in (IP, IP.parse):
                with self.subTest(member=member, parse=getattr(parse, '__name__', parse)):
                    self.assertEqual(type(parse(octets)).__name__, member)


class ParseMethodTests(unittest.TestCase):
    """``parse`` is the explicit form of the class call given a file."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_the_signature_is_the_parse_one_with_the_class_s_keywords(self) -> None:
        from pcapkit.protocols.protocol import ProtocolBase

        params = inspect.signature(ProtocolBase.parse).parameters
        self.assertEqual([(name, param.kind, param.default) for name, param in params.items()], [
            ('file', inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.empty),
            ('length', inspect.Parameter.POSITIONAL_ONLY, None),
            ('layer', inspect.Parameter.KEYWORD_ONLY, None),
            ('protocol', inspect.Parameter.KEYWORD_ONLY, None),
            ('context', inspect.Parameter.KEYWORD_ONLY, None),
            ('keywords', inspect.Parameter.VAR_KEYWORD, inspect.Parameter.empty),
        ])

    def test_parse_gives_what_the_class_call_gives(self) -> None:
        """The same class, octets and data, with the stops, the length and the class's own keywords."""
        from pcapkit.protocols.application.dns.protocol import DNS
        from pcapkit.protocols.internet.ip.protocol import IP
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.link.ethernet.protocol import Ethernet
        from pcapkit.protocols.link.loopback.protocol import Loopback
        from pcapkit.protocols.misc.pcap.frame.protocol import Frame
        from pcapkit.protocols.misc.pcap.header.protocol import Header

        header = Header(GLOBAL).info
        cases = (
            (Ethernet, (FRAME,), {}),
            (Ethernet, (FRAME, len(FRAME)), {'layer': 'Internet'}),
            (Ethernet, (FRAME,), {'protocol': 'IPv4'}),
            (IP, (PACKET,), {}),
            (IP, (PACKET6,), {'version': 6}),
            (IPv6, (PACKET6,), {}),
            (Frame, (record(FRAME),), {'num': 1, 'header': header}),
            (DNS, (bytes(12),), {'framed': False}),
            (Loopback, (b'\x02\x00\x00\x00' + PACKET,), {'byteorder': 'little'}),
        )
        for cls, args, keywords in cases:
            with self.subTest(cls=cls.__name__, keywords=sorted(keywords)), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                called, parsed = cls(*args, **keywords), cls.parse(*args, **keywords)
                self.assertIs(type(parsed), type(called))
                self.assertEqual(parsed.data, called.data)
                self.assertEqual(parsed.info.to_dict(), called.info.to_dict())
                self.assertEqual(str(parsed.protochain), str(called.protochain))

    def test_parse_refuses_a_field(self) -> None:
        """``protocol`` is the stop even where the class takes a field of that name."""
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.link.ethernet.protocol import Ethernet
        from pcapkit.utilities.exceptions import RegistryError

        with self.assertRaisesRegex(TypeError, "^Ethernet: unexpected keyword argument 'src' for a parse$"):
            Ethernet.parse(FRAME, src='aa:bb:cc:dd:ee:ff')
        with self.assertRaisesRegex(TypeError, "^IPv4: unexpected keyword argument 'ttl' for a parse$"):
            IPv4.parse(PACKET, ttl=1)
        self.assertEqual(IPv4.parse(PACKET, protocol='IPv4')._exproto, 'IPv4')  # pylint: disable=protected-access
        with self.assertRaises(RegistryError):
            IPv4.parse(PACKET, protocol=6)

    def test_parse_of_no_octets_is_refused(self) -> None:
        from pcapkit.protocols.internet.ip.protocol import IP
        from pcapkit.protocols.link.ethernet.protocol import Ethernet

        for cls in (Ethernet, IP):
            with self.subTest(cls=cls.__name__), self.assertRaisesRegex(
                    TypeError, rf'^{cls.__name__}: nothing to parse; build one with {cls.__name__}\.build\(\)$'):
                cls.parse(None)  # type: ignore[arg-type]


def post_init_caller(call: 'Callable[[], object]') -> 'Any':
    """The code that calls the first ``__post_init__`` ``call()`` enters, the outermost layer's."""
    callers = []  # type: list[Any]

    def profile(frame: 'Any', event: str, arg: object) -> None:  # pylint: disable=unused-argument
        if event == 'call' and not callers and frame.f_code.co_name == '__post_init__':
            callers.append(frame.f_back.f_code)

    sys.setprofile(profile)
    try:
        call()
    finally:
        sys.setprofile(None)
    return callers[0] if callers else None


class FrameCountTests(unittest.TestCase):
    """``parse`` adds no frame per layer to the class call (#1610)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_each_init_calls_post_init_as_it_says(self) -> None:
        """The base ``__init__`` and the overrides inlining its steps call ``__post_init__``
        themselves; the versioned bases that take ``version`` call it through ``_parse``."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.application.dns.protocol import DNS
        from pcapkit.protocols.application.http.protocol import HTTP
        from pcapkit.protocols.internet.hopopt.protocol import HOPOPT
        from pcapkit.protocols.internet.icmp.protocol import ICMP
        from pcapkit.protocols.internet.igmp.protocol import IGMP
        from pcapkit.protocols.internet.ip.protocol import IP
        from pcapkit.protocols.internet.ipv6_ext.protocol import IPv6_Ext
        from pcapkit.protocols.link.l2tp.protocol import L2TP
        from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL
        from pcapkit.protocols.link.loopback.protocol import Loopback
        from pcapkit.protocols.link.netlink.protocol import Netlink
        from pcapkit.protocols.misc.pcap.frame.protocol import Frame
        from pcapkit.protocols.misc.pcap.header.protocol import Header
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG
        from pcapkit.protocols.protocol import ProtocolBase
        from pcapkit.protocols.transport.tcp.protocol import TCP

        header = Header(GLOBAL).info
        block = PCAPNG.build(num=0, sct=1, ctx=None, type=BlockType.Section_Header_Block, block={}).data
        parse = vars(ProtocolBase)['_parse'].__code__
        cases = (
            ('TCP', lambda: TCP(SEGMENT), vars(ProtocolBase)['__init__'].__code__),
            ('TCP.parse', lambda: TCP.parse(SEGMENT), vars(ProtocolBase)['__init__'].__code__),
            ('Frame', lambda: Frame(record(FRAME), num=1, header=header), vars(Frame)['__init__'].__code__),
            ('PCAPNG', lambda: PCAPNG(block, num=0, sct=1, ctx=None), vars(PCAPNG)['__init__'].__code__),
            ('HOPOPT', lambda: HOPOPT(bytes([6, 0, 1, 4, 0, 0, 0, 0]) + SEGMENT), vars(IPv6_Ext)['__init__'].__code__),
            ('DNS', lambda: DNS(bytes(12)), vars(DNS)['__init__'].__code__),
            ('Loopback', lambda: Loopback(b'\x02\x00\x00\x00' + PACKET), vars(Loopback)['__init__'].__code__),
            ('Netlink', lambda: Netlink(bytes(16), byteorder='little'), vars(Netlink)['__init__'].__code__),
            ('L2TP', lambda: L2TP(b'\x00\x02' + bytes(4)), vars(L2TP)['__init__'].__code__),
            ('IP', lambda: IP(PACKET), parse),
            ('ICMP', lambda: ICMP(b'\x08\x00' + bytes(6), version=4), parse),
            ('IGMP', lambda: IGMP(bytes([0x11, 0]) + bytes(6)), parse),
            ('LinuxSLL', lambda: LinuxSLL(bytes(14) + b'\x08\x00' + PACKET, version=1), parse),
            ('HTTP', lambda: HTTP(b'GET / HTTP/1.1\r\n\r\n'), parse),
        )
        for name, call, caller in cases:
            with self.subTest(cls=name), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                self.assertIs(post_init_caller(call), caller)

    def test_parse_costs_the_class_call_one_frame_at_most_whatever_the_depth(self) -> None:
        from pcapkit.protocols.link.ethernet.protocol import Ethernet

        costs = {}
        for count in (1, 20):
            data = ipv4_in_ipv4(count)
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                Ethernet(data)
                Ethernet.parse(data)
                costs[count] = depth(lambda: Ethernet.parse(data)) - depth(lambda: Ethernet(data))  # pylint: disable=cell-var-from-loop
        self.assertEqual(costs[1], costs[20], costs)
        self.assertIn(costs[1], (0, 1), costs)


if __name__ == '__main__':
    unittest.main()
