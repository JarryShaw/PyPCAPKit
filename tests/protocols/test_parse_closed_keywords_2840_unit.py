# -*- coding: utf-8 -*-
"""A parse refuses what its signature does not take (GitHub issue #2840).

``Proto(file, length=None, /, *, layer=None, protocol=None, context=None)`` parses,
taking no field (#3081), so:

* :class:`UnknownKeywordTests` -- a misspelt stop, the old prefixed stops,
  ``__context__``, ``packet`` and ``__packet__`` are a :exc:`TypeError` naming
  them, and so is ``None`` for octets, where a misspelling used to parse in full;
* :class:`StopTests` -- ``layer`` is one of the four layer names or :obj:`None`,
  else :exc:`~pcapkit.utilities.exceptions.FormatError`, and ``protocol`` a name,
  class or instance or :obj:`None`, else
  :exc:`~pcapkit.utilities.exceptions.RegistryError`, on ``analyze`` as on
  ``__init__``;
* :class:`MemberVersionTests` -- a member given another member's ``version``
  refuses it, as construction does (decision 5).

This module is unit tier: it builds its own octets and reads no capture.

"""
from __future__ import annotations

import unittest

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

#: Test tier (#1958): exercises signature machinery, which differs by interpreter.
__tier__ = 'ALL'

#: A TCP segment carrying a payload no port of its dispatches.
SEGMENT = wire.tcp(b'payload', seq=1)

#: Ethernet, then IPv4, then :data:`SEGMENT`.
FRAME = wire.ethernet(wire.ipv4(SEGMENT, proto=6), 0x0800)


class UnknownKeywordTests(unittest.TestCase):
    """A parse refuses a keyword its signature does not declare."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_a_misspelt_stop_is_refused(self) -> None:
        """Where it parsed the whole frame, unread."""
        from pcapkit.protocols.link.ethernet.protocol import Ethernet
        from pcapkit.protocols.misc.raw.protocol import Raw

        with self.assertRaisesRegex(TypeError, "unexpected keyword argument 'layr'"):
            Ethernet(FRAME, len(FRAME), layr='Link')
        self.assertIs(type(Ethernet(FRAME, len(FRAME), layer='Link').payload), Raw)

    def test_the_old_spellings_and_the_state_are_refused(self) -> None:
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.ip.protocol import IP
        from pcapkit.protocols.link.ethernet.protocol import Ethernet

        for key, value in (('_layer', 'Link'), ('_protocol', 'TCP'), ('__context__', ContextRegistry()),
                           ('packet', {}), ('__packet__', {}), ('alias', 1)):
            for cls, octets in ((Ethernet, FRAME), (IP, FRAME[14:])):
                with self.subTest(key=key, cls=cls.__name__), \
                        self.assertRaisesRegex(TypeError, f"unexpected keyword argument '{key}'"):
                    cls(octets, len(octets), **{key: value})

    def test_no_octets_is_refused(self) -> None:
        """``Proto(None)`` points at ``from_fields``, rather than constructing."""
        from pcapkit.protocols.application.http.protocol import HTTP
        from pcapkit.protocols.internet.icmp.protocol import ICMP
        from pcapkit.protocols.internet.igmp.protocol import IGMP
        from pcapkit.protocols.internet.ip.protocol import IP
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.link.ethernet.protocol import Ethernet
        from pcapkit.protocols.link.l2tp.protocol import L2TP
        from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL

        for cls in (Ethernet, IP, IPv4, ICMP, IGMP, LinuxSLL, HTTP, L2TP):
            with self.subTest(cls=cls.__name__), self.assertRaisesRegex(
                    TypeError, rf'^{cls.__name__}: nothing to parse; build one with {cls.__name__}\.from_fields\(\)$'):
                cls(None)  # type: ignore[arg-type]

    def test_analyze_refuses_any_other_keyword(self) -> None:
        from pcapkit.const.reg.apptype import AppType, TransportProtocol
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.transport.tcp.protocol import TCP

        ports = tuple(AppType.get(port, proto=TransportProtocol.tcp) for port in (50000, 9))
        for call in (lambda: IPv4.analyze(6, SEGMENT, __context__=None),
                     lambda: IPv4.analyze(6, SEGMENT, _layer='Link'),
                     lambda: IPv4.analyze(6, SEGMENT, alias=6),
                     lambda: TCP.analyze(ports, b'payload', version=4)):
            with self.subTest(), self.assertRaisesRegex(TypeError, 'unexpected keyword argument'):
                call()


class StopTests(unittest.TestCase):
    """``None`` is the only no stop, and a stop of no known kind is refused."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_layer_names_one_of_the_four_layers(self) -> None:
        from pcapkit.protocols.link.ethernet.protocol import Ethernet
        from pcapkit.utilities.exceptions import FormatError

        for layer in ('Bogus', 'none', 'NONE', 3, Ethernet):
            with self.subTest(layer=layer), self.assertRaisesRegex(
                    FormatError, r"^unknown layer: .*; expected one of 'link', 'internet', 'transport', 'application'$"):
                Ethernet(FRAME, len(FRAME), layer=layer)  # type: ignore[arg-type]
        for layer in ('link', 'INTERNET', 'Transport'):
            with self.subTest(layer=layer):
                self.assertEqual(Ethernet(FRAME, len(FRAME), layer=layer)._exlayer, layer)  # pylint: disable=protected-access

    def test_protocol_is_a_name_class_or_instance(self) -> None:
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.link.ethernet.protocol import Ethernet
        from pcapkit.utilities.exceptions import RegistryError

        for protocol in (1.5, 6, b'TCP', object()):
            with self.subTest(protocol=protocol), self.assertRaisesRegex(RegistryError, 'unknown protocol'):
                Ethernet(FRAME, len(FRAME), protocol=protocol)  # type: ignore[arg-type]

        instance = IPv4(FRAME[14:], len(FRAME) - 14)
        for protocol in ('IPv4', 'HTTP/2', 'null', IPv4, instance):
            with self.subTest(protocol=protocol):
                parsed = Ethernet(FRAME, len(FRAME), protocol=protocol)
                self.assertIs(parsed._exproto, protocol)  # pylint: disable=protected-access

    def test_analyze_checks_its_stops_first(self) -> None:
        from pcapkit.const.reg.apptype import AppType, TransportProtocol
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.transport.tcp.protocol import TCP
        from pcapkit.utilities.exceptions import FormatError, RegistryError

        ports = tuple(AppType.get(port, proto=TransportProtocol.tcp) for port in (50000, 9))
        for call, error in ((lambda: IPv4.analyze(6, SEGMENT, layer='Bogus'), FormatError),
                            (lambda: IPv4.analyze(6, b'', layer='Bogus'), FormatError),
                            (lambda: IPv4.analyze(6, SEGMENT, protocol=1.5), RegistryError),
                            (lambda: TCP.analyze(ports, b'payload', layer='none'), FormatError),
                            (lambda: TCP.analyze(ports, b'payload', protocol=1.5), RegistryError)):
            with self.subTest(error=error.__name__), self.assertRaises(error):
                call()


class MemberVersionTests(unittest.TestCase):
    """A member's ``version`` is its own while parsing, as while constructing (decision 5)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_a_member_refuses_another_s_version(self) -> None:
        from pcapkit.protocols.application.httpv1.protocol import HTTPv1
        from pcapkit.protocols.internet.icmpv4.protocol import ICMPv4
        from pcapkit.protocols.internet.igmpv2.protocol import IGMPv2
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.link.l2tpv2.protocol import L2TPv2
        from pcapkit.protocols.link.linux_sll1.protocol import LinuxSLL1
        from pcapkit.utilities.exceptions import ProtocolError

        cases = (
            (IPv4, FRAME[14:], 4, 6, 'IPv4: version=6 names another member'),
            (ICMPv4, ICMPv4.from_fields().data, 4, 6, 'ICMPv4: version=6 names another member'),
            (IGMPv2, IGMPv2.from_fields(max_resp_time=100).data, 2, 3, 'IGMPv2: version=3 names another member'),
            (LinuxSLL1, LinuxSLL1.from_fields().data, 1, 2, 'LinuxSLL1: version=2 names another member'),
            (HTTPv1, b'GET / HTTP/1.1\r\n\r\n', 1, 2, 'HTTPv1: version=2 names another member'),
            (L2TPv2, L2TPv2.from_fields().data, 2, 3, 'L2TP: invalid version: 3'),
        )
        for cls, octets, own, other, message in cases:
            with self.subTest(cls=cls.__name__):
                self.assertEqual(cls(octets, len(octets), version=own).info, cls(octets, len(octets)).info)
                with self.assertRaisesRegex(ProtocolError, message):
                    cls(octets, len(octets), version=other)

    def test_a_subclass_outside_the_members_has_no_version(self) -> None:
        """As for ``from_fields``, a parse of one names no member with ``version``."""
        from pcapkit.protocols.link.l2tp.protocol import L2TP
        from pcapkit.protocols.link.l2tpv2.protocol import L2TPv2
        from pcapkit.utilities.exceptions import ProtocolError

        class Outside(L2TP):  # type: ignore[type-arg]
            """A concrete subclass of the base that is no member."""

            name = length = None  # type: ignore[assignment]

            def read(self, length: 'object' = None, **kwargs: 'object') -> 'object':
                raise NotImplementedError

            def make(self, **kwargs: 'object') -> 'object':
                raise NotImplementedError

        octets = L2TPv2.from_fields().data
        with self.assertRaisesRegex(ProtocolError, '^Outside: no version of its own to match version=2$'):
            Outside(octets, len(octets), version=2)

    def test_the_version_reaches_no_hook(self) -> None:
        """The member selector is consumed by the dispatcher; the hooks get the channel's alone."""
        from unittest import mock

        from pcapkit.protocols.internet.icmp.protocol import ICMP
        from pcapkit.protocols.internet.icmpv4.protocol import ICMPv4

        octets = ICMPv4.from_fields().data
        seen = []
        original = ICMPv4.read

        def read(self, length=None, **kwargs):  # type: ignore[no-untyped-def]
            seen.append(kwargs)
            return original(self, length, **kwargs)

        with mock.patch.object(ICMPv4, 'read', read):
            parsed = ICMP(octets, len(octets), version=4)
        self.assertIs(type(parsed), ICMPv4)
        self.assertNotIn('version', seen[0])



class OverrideTests(unittest.TestCase):
    """A third-party ``__init__`` override with a keyword of its own parses through ``_parse``."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_parse_hands_on_its_keywords_under_the_channel(self) -> None:
        from pcapkit.protocols.misc.raw.protocol import Raw

        seen = []

        class Marked(Raw):
            def __init__(self, file, length=None, /, *, extension=False,  # type: ignore[no-untyped-def]
                         layer=None, protocol=None, context=None, **fields):
                self._parse(file, length, fields, layer=layer, protocol=protocol, context=context,
                            extension=extension)

            def read(self, length=None, **kwargs):  # type: ignore[no-untyped-def]
                seen.append(kwargs)
                return super().read(length, **kwargs)

        parsed = Marked(b'octets', 6, extension=True, layer='Link')
        self.assertEqual((seen[-1]['extension'], parsed._exlayer), (True, 'Link'))  # pylint: disable=protected-access
        self.assertEqual(parsed.info.packet, b'octets')
        # NOTE: The state the enclosing layer hands on wins over the override's default.
        Marked._from_parent(b'octets', 6, extension=True)  # pylint: disable=protected-access
        self.assertIs(seen[-1]['extension'], True)
        with self.assertRaisesRegex(TypeError, r'^Marked: nothing to parse'):
            Marked(None)  # type: ignore[arg-type]
        # NOTE: ``_parse`` refuses the fields an override hands it beside a file (#3081).
        with self.assertRaisesRegex(TypeError, r"^Marked: unexpected keyword argument 'src' for a parse$"):
            Marked(b'octets', 6, src=1)

    def test_analyze_takes_next_layer_state_alone_privately(self) -> None:
        """``_analyze_from_parent`` refuses a key that is no next-layer state, as ``_from_parent`` does."""
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.utilities.exceptions import UnsupportedCall

        with self.assertRaisesRegex(UnsupportedCall, "IPv4: unknown next-layer state: 'bogus'"):
            IPv4._analyze_from_parent(6, SEGMENT, bogus=1)  # pylint: disable=protected-access


if __name__ == '__main__':
    unittest.main()
