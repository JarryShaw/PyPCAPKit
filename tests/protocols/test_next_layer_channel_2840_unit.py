# -*- coding: utf-8 -*-
"""A next layer gets the state its parent hands on through one private channel (#2840).

``_parse_next_layer``, ``beholder`` and ``analyze``'s fallback build a layer with
``ProtocolBase._from_parent``. Its public ``__init__`` gets the stops and the context
alone, and each key of ``_NEXT_LAYER_KEYWORDS`` reaches the hook that reads it, from
``__post_init__`` on, checked on the path that hands it on: ``framed`` and ``chained``
included, and the ``EXTENSION_HEADER_LIMIT`` error.

Every packet is built in memory; no sample capture is read.

"""
from __future__ import annotations

import contextlib
import importlib.util
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

if TYPE_CHECKING:
    from typing import Any, Iterator

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: The keywords ``_from_parent`` gives ``__init__``: the stops and the context.
INIT_KEYWORDS = {'layer', 'protocol', '__context__'}

#: A TCP segment with a payload no port of its dispatches.
SEGMENT = wire.tcp(b'payload', seq=1)

#: A TLS 1.2 application-data record of four octets.
TLS_RECORD = bytes([23, 3, 3, 0, 4]) + b'abcd'

#: A whole SSLv2 CLIENT-HELLO, which TLS's SSLv2 trial parses (as in ``test_sslv2_unit``).
CLIENT_HELLO = bytes.fromhex('801c' '01' '0002' '0003' '0000' '0010' '010080') + bytes(16)


def options(nxt: int) -> bytes:
    """An 8-octet Destination Options header: Hdr Ext Len 0 and one PadN."""
    return bytes([nxt, 0, 1, 4, 0, 0, 0, 0])


@contextlib.contextmanager
def spy(cls: type, name: str) -> 'Iterator[list[tuple[str, dict[str, Any]]]]':
    """Record the class and the keywords of every call of ``cls.<name>``, which still runs."""
    calls = []  # type: list[tuple[str, dict[str, Any]]]
    original = getattr(cls, name)

    def wrapper(self: 'Any', *args: 'Any', **kwargs: 'Any') -> 'Any':
        calls.append((type(self).__name__, dict(kwargs)))
        return original(self, *args, **kwargs)

    with mock.patch.object(cls, name, wrapper):
        yield calls


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class NextLayerChannelTests(unittest.TestCase):
    """The stops and context reach ``__init__``; the state reaches the hooks alone."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def assertStopsAlone(self, calls: 'list[tuple[str, dict[str, Any]]]') -> None:
        """Every recorded ``__init__`` call got the stops and the context, and nothing else."""
        self.assertTrue(calls)
        for name, kwargs in calls:
            with self.subTest(init=name):
                self.assertEqual(set(kwargs), INIT_KEYWORDS)

    def test_init_gets_the_stops_and_context_and_read_the_state(self) -> None:
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.protocols.protocol import ProtocolBase

        context, packet = ContextRegistry(), {'outer': 1}
        with spy(Raw, '__init__') as init, spy(Raw, 'read') as read:
            raw = ProtocolBase._parse_next_layer(Raw, b'four', 4, layer='Link', protocol='TCP',
                                                 context=context, alias=7, packet=packet)

        self.assertEqual(init, [('Raw', {'layer': 'Link', 'protocol': 'TCP', '__context__': context})])
        self.assertEqual(read[0][1]['alias'], 7)
        self.assertIs(read[0][1]['packet'], packet)
        self.assertEqual(read[0][1]['__packet__']['outer'], 1)
        self.assertIsNot(read[0][1]['__packet__'], packet)
        self.assertEqual((raw._exlayer, raw._exproto), ('Link', 'TCP'))
        self.assertIs(raw._exctx, context)
        self.assertEqual(raw.info.protocol, 7)

    def test_a_frame_hands_each_layer_its_state_past_init(self) -> None:
        """TCP inside IPv4 still gets ``alias``, ``packet``, ``version`` and ``extension``."""
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.link.ethernet.protocol import Ethernet
        from pcapkit.protocols.transport.tcp.protocol import TCP

        frame = wire.ethernet(wire.ipv4(SEGMENT, proto=6), 0x0800)
        with spy(TCP, '__init__') as init, spy(TCP, 'read') as read:
            parsed = Ethernet(frame, len(frame), layer='Transport')

        self.assertStopsAlone(init)
        self.assertEqual(init[0][1]['layer'], 'Transport')
        state = read[0][1]
        self.assertEqual(state['alias'], TransType.TCP)
        self.assertEqual((state['version'], state['extension']), (4, False))
        self.assertIsInstance(state['packet'], dict)
        self.assertEqual(str(parsed.protochain), 'Ethernet:IPv4:TCP:Raw')

    def test_framed_reaches_the_next_dns_message(self) -> None:
        from pcapkit.protocols.application.dns.protocol import DNS

        octets = DNS.from_fields(id=1, framed=True).data + DNS.from_fields(id=2, framed=True).data
        with spy(DNS, '__init__') as init, spy(DNS, '__post_init__') as post:
            parsed = DNS(octets, len(octets))

        self.assertNotIn('framed', post[0][1])
        self.assertIs(post[1][1]['framed'], True)
        self.assertStopsAlone(init[1:])
        self.assertEqual((parsed.info.id, parsed.payload.info.id), (1, 2))

    def test_chained_reaches_the_next_tls_record(self) -> None:
        from pcapkit.protocols.application.tls.protocol import TLS

        octets = TLS_RECORD * 2
        with spy(TLS, '__init__') as init, spy(TLS, 'unpack') as unpack:
            parsed = TLS(octets, len(octets))

        self.assertNotIn('chained', unpack[0][1])
        self.assertIs(unpack[1][1]['chained'], True)
        self.assertStopsAlone(init[1:])
        self.assertEqual(str(parsed.protochain), 'TLS 1.2:TLS 1.2')

    def test_the_sslv2_trial_shares_the_tls_parse_s_packet(self) -> None:
        """A re-dispatch of the same octets hands on the copy of ``packet`` its schema writes."""
        from pcapkit.protocols.application.sslv2.protocol import SSLv2
        from pcapkit.protocols.application.tls.protocol import TLS

        with spy(TLS, 'unpack') as unpack, spy(SSLv2, '__init__') as init, \
                spy(SSLv2, 'read') as read:
            parsed = TLS._from_parent(CLIENT_HELLO, len(CLIENT_HELLO), alias=443, packet={'outer': 1})

        self.assertStopsAlone(init)
        self.assertIs(read[0][1]['__packet__'], unpack[0][1]['__packet__'])
        self.assertEqual((read[0][1]['alias'], read[0][1]['packet']), (443, {'outer': 1}))
        self.assertEqual(parsed.alias, 'SSLv2')

    def test_the_extension_header_limit_error_and_depth_reach_their_readers(self) -> None:
        from pcapkit.protocols.internet.ipv6_opts.protocol import IPv6_Opts
        from pcapkit.protocols.link.ethernet.protocol import Ethernet
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.utilities import config
        from pcapkit.utilities.warnings import ProtocolWarning

        frame = wire.ethernet(wire.ipv4(options(60) + options(6) + SEGMENT, proto=60), 0x0800)
        with mock.patch.object(config, 'EXTENSION_HEADER_LIMIT', 1), \
                warnings.catch_warnings(record=True) as caught, \
                spy(IPv6_Opts, '__init__') as opts_init, spy(Raw, '__init__') as raw_init, \
                spy(Raw, 'read') as read:
            warnings.simplefilter('always')
            parsed = Ethernet(frame, len(frame))

        messages = [str(item.message) for item in caught if issubclass(item.category, ProtocolWarning)]
        self.assertEqual(len(messages), 1)
        self.assertIn('limit of 1 headers', messages[0])
        self.assertEqual(read[0][1]['error'], messages[0])
        self.assertStopsAlone(opts_init)
        self.assertStopsAlone(raw_init)
        self.assertEqual(parsed.payload.payload._exthdr_depth, 1)
        self.assertEqual(parsed.payload.payload.payload.info.error, messages[0])

    def test_beholder_hands_its_raw_the_error_and_the_code(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.misc.raw.protocol import Raw

        # NOTE: A Data Offset of 1 word, which TCP refuses.
        packet = wire.ipv4(SEGMENT[:12] + b'\x10' + SEGMENT[13:], proto=6)
        with spy(Raw, '__init__') as init, spy(Raw, 'read') as read:
            parsed = IPv4(packet, len(packet))

        self.assertStopsAlone(init)
        self.assertEqual(read[0][1]['alias'], TransType.TCP)
        self.assertTrue(read[0][1]['error'])
        self.assertIsInstance(parsed.payload, Raw)
        self.assertEqual(parsed.payload.info.error, read[0][1]['error'])

    def test_a_raw_kept_by_parse_next_layer_gets_the_state(self) -> None:
        """The frame-limit ``Raw`` and the ``Raw`` kept for a header cut short."""
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.link.ethernet.protocol import Ethernet
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.protocols.protocol import ProtocolBase
        from pcapkit.utilities import config

        frame = wire.ethernet(wire.ipv4(SEGMENT, proto=6), 0x0800)
        with mock.patch.object(config, 'FRAME_LAYER_LIMIT', 1), warnings.catch_warnings(), \
                spy(Raw, '__init__') as init, spy(Raw, 'read') as read:
            warnings.simplefilter('ignore')
            parsed = Ethernet(frame, len(frame))

        self.assertStopsAlone(init)
        self.assertEqual((read[0][1]['alias'], read[0][1]['version']), (TransType.TCP, 4))
        self.assertIn('limit of 1 layers', read[0][1]['error'])
        self.assertTrue(parsed.payload.payload._past_layer_limit)

        # NOTE: Ten octets of an Ethernet header parse zero-filled, so the parse is replaced.
        with warnings.catch_warnings(), spy(Raw, '__init__') as init, spy(Raw, 'read') as read:
            warnings.simplefilter('ignore')
            short = ProtocolBase._parse_next_layer(Ethernet, bytes(10), 10, alias=1, version=4)

        # NOTE: The last ``Raw`` is the one kept, after any the trial parse made.
        self.assertStopsAlone(init)
        self.assertEqual((read[-1][1]['alias'], read[-1][1]['version']), (1, 4))
        self.assertIsInstance(short, Raw)
        self.assertEqual(short.info.protocol, 1)

    def test_analyze_keeps_its_fallback_s_stops_context_and_state(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.misc.no_payload.protocol import NoPayload
        from pcapkit.protocols.misc.raw.protocol import Raw

        context = ContextRegistry()
        refused = SEGMENT[:12] + b'\x10' + SEGMENT[13:]
        for label, payload, kept in (('refused', refused, Raw), ('empty', b'', NoPayload)):
            with self.subTest(label), spy(kept, '__init__') as init, \
                    spy(kept, '__post_init__') as post:
                result = IPv4.analyze(6, payload, _layer='Link', protocol='TCP',
                                      __context__=context, packet={'outer': 1}, unread=True)

                self.assertIsInstance(result, kept)
                self.assertEqual(init, [(kept.__name__, {'layer': 'Link', 'protocol': 'TCP',
                                                         '__context__': context})])
                self.assertEqual(post[0][1]['alias'], TransType.TCP)
                self.assertEqual(post[0][1]['packet'], {'outer': 1})
                self.assertNotIn('unread', post[0][1])
                self.assertIs(result._exctx, context)

    def test_analyze_s_trial_gets_the_stops_and_context_alone(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.transport.tcp.protocol import TCP

        context = ContextRegistry()
        with spy(TCP, '__init__') as init, spy(TCP, 'read') as read:
            result = IPv4.analyze(6, SEGMENT, _layer='Transport', __context__=context,
                                  packet={'outer': 1}, version=4)

        self.assertIsInstance(result, TCP)
        self.assertEqual(init, [('TCP', {'layer': 'Transport', 'protocol': None, '__context__': context})])
        self.assertEqual(read[0][1]['alias'], TransType.TCP)
        self.assertEqual((read[0][1]['packet'], read[0][1]['version']), ({'outer': 1}, 4))
        self.assertIs(result._exctx, context)

        # NOTE: A keyword neither a stop nor state is the caller's, for the public constructor.
        with spy(TCP, '__init__') as init:
            IPv4.analyze(6, SEGMENT, unread=True)
        self.assertEqual(init, [('TCP', {'unread': True, 'alias': TransType.TCP})])

    def test_stops_named_none_and_null_are_no_stop(self) -> None:
        """As ``Extractor`` spells an omitted stop, which ``__init__`` still reads as none."""
        from pcapkit.protocols.link.ethernet.protocol import Ethernet

        frame = wire.ethernet(wire.ipv4(SEGMENT, proto=6), 0x0800)
        parsed = Ethernet._from_parent(frame, len(frame), layer='none', protocol='null')
        self.assertEqual((parsed._exlayer, parsed._exproto), (None, None))
        self.assertEqual(str(parsed.protochain), 'Ethernet:IPv4:TCP:Raw')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class FromParentTests(unittest.TestCase):
    """``_from_parent`` runs ``__new__`` and ``__init__`` as calling the class does."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_unknown_state_is_refused(self) -> None:
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.protocols.protocol import ProtocolBase
        from pcapkit.utilities.exceptions import UnsupportedCall

        with self.assertRaisesRegex(UnsupportedCall, "Raw: unknown next-layer state: 'bogus'"):
            Raw._from_parent(b'', 0, bogus=1)
        # NOTE: The constructor's spelling of the context is no state.
        with self.assertRaisesRegex(UnsupportedCall, "'__context__'"):
            ProtocolBase._parse_next_layer(Raw, b'x', 1, __context__=None)

    def test_the_channel_is_cleared(self) -> None:
        from pcapkit.protocols.link.ethernet.protocol import Ethernet
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.protocols.protocol import ProtocolBase

        self.assertIsNone(ProtocolBase.__next_layer__)
        frame = wire.ethernet(wire.ipv4(SEGMENT, proto=6), 0x0800)
        layer = Ethernet(frame, len(frame))
        while not isinstance(layer, Raw):
            with self.subTest(layer=type(layer).__name__):
                self.assertNotIn('__next_layer__', vars(layer))
            layer = layer.payload

        made = []

        class Skips(Raw):
            def __init__(self, *args: 'Any', **kwargs: 'Any') -> None:  # pylint: disable=super-init-not-called
                made.append(vars(self).get('__next_layer__'))

        class Raises(Raw):
            def __init__(self, *args: 'Any', **kwargs: 'Any') -> None:  # pylint: disable=super-init-not-called
                made.append(self)
                raise ValueError('stand-in')

        skipped = Skips._from_parent(b'', 0, alias=1)
        self.assertEqual(made.pop(), {'alias': 1})
        self.assertNotIn('__next_layer__', vars(skipped))
        with self.assertRaises(ValueError):
            Raises._from_parent(b'', 0, alias=1)
        self.assertNotIn('__next_layer__', vars(made.pop()))

    def test_a_family_base_picks_the_member_a_call_picks(self) -> None:
        from pcapkit.protocols.application.http.protocol import HTTP
        from pcapkit.protocols.internet.icmp.protocol import ICMP
        from pcapkit.protocols.internet.igmp.protocol import IGMP
        from pcapkit.protocols.internet.ip.protocol import IP
        from pcapkit.protocols.link.l2tp.protocol import L2TP
        from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL

        cases = {
            'IP, version 4': (IP, wire.ipv4(SEGMENT, proto=6)),
            'IP, version 6': (IP, wire.ipv6(SEGMENT, nxt=6)),
            'IGMP': (IGMP, bytes([0x11, 100, 0, 0, 0, 0, 0, 0])),
            'HTTP': (HTTP, b'GET / HTTP/1.1\r\n\r\n'),
            'L2TP': (L2TP, bytes.fromhex('000200010001')),
            'ICMP': (ICMP, bytes([8, 0, 0, 0, 0, 1, 0, 1])),
            'LinuxSLL': (LinuxSLL, bytes(16)),
        }
        for label, (base, octets) in cases.items():
            with self.subTest(label), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                self.assertEqual(self.outcome(base._from_parent, octets),
                                 self.outcome(base, octets))

    def test_the_ip_version_never_picks_a_member(self) -> None:
        from pcapkit.protocols.internet.icmp.protocol import ICMP
        from pcapkit.protocols.internet.ip.protocol import IP
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.utilities.exceptions import ProtocolError

        octets = wire.ipv6(SEGMENT, nxt=6)
        self.assertIsInstance(IP._from_parent(octets, len(octets), version=4), IPv6)
        with self.assertRaises(ProtocolError):
            ICMP._from_parent(bytes(8), 8, version=4)

    def test_a_new_giving_another_class_skips_init(self) -> None:
        from pcapkit.protocols.misc.raw.protocol import Raw

        class Elsewhere(Raw):
            def __new__(cls, *args: 'Any', **kwargs: 'Any') -> 'Any':
                return 'elsewhere'

        self.assertEqual(Elsewhere._from_parent(b'', 0, alias=1), 'elsewhere')

    @staticmethod
    def outcome(make: 'Any', octets: bytes) -> 'tuple[str, str]':
        """The class ``make`` gives for ``octets``, or the error it raises, by name and message."""
        try:
            return ('made', type(make(octets, len(octets))).__name__)
        except Exception as exc:  # pylint: disable=broad-except
            return (type(exc).__name__, str(exc))


if __name__ == '__main__':
    unittest.main()
