# -*- coding: utf-8 -*-
"""A frame is dissected to 64 layers, and no further.

GitHub issue #1610: each layer dissects the next one from inside its own parse,
so deep nesting of any protocol ran into Python's recursion limit, and
:func:`~pcapkit.utilities.decorators.beholder` caught the ``RecursionError`` and
left the rest raw, silently. From a script on Python 3.14, TCP was lost behind
108 IPv4 headers in IPv4, or behind 200 stacked 802.1Q tags. #1604 bounded one
chain of extension headers, but its count restarts at every tunnel.

Now every frame stops at
:data:`~pcapkit.protocols.protocol.FRAME_LAYER_LIMIT` layers, counted along its
protocol chain from the first layer its record carries, through tunnels, tags
and extension headers alike: what follows is kept as
:class:`~pcapkit.protocols.misc.raw.Raw`, with one
:exc:`~pcapkit.utilities.warnings.ProtocolWarning`.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import itertools
import logging
import struct
import sys
import time
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import close_extractor, reimport_once_per_class, scale_timeout, time_limit
from tests.foundation import _roundtrip as wire

if TYPE_CHECKING:
    from typing import Optional

#: Little-endian PCAP global header: v2.4, snaplen 65535, Ethernet.
GLOBAL = bytes.fromhex('d4c3b2a1' '0200' '0400' '00000000' '00000000' 'ffff0000' '01000000')

#: EtherType naming each layer, from Ethernet or an 802.1Q tag.
ETHERTYPE = {'ipv4': 0x0800, 'ipv6': 0x86DD, 'vlan': 0x8100}
#: Protocol number naming each layer, from IP or an extension header.
PROTO = {'ipv4': 4, 'ipv6': 41, 'opts': 60, 'tcp': 6}

#: Frames longer than the limit, in layers: by one, and by far.
PAST = (65, 1000)

#: Layer by layer, after Ethernet, and each ending in TCP: ``count`` layers in
#: all, Ethernet the first and TCP the last.
SHAPES = {
    'IPv4 in IPv4': lambda count: ['ipv4'] * (count - 2) + ['tcp'],
    'IPv6 in IPv6': lambda count: ['ipv6'] * (count - 2) + ['tcp'],
    '802.1Q tags': lambda count: ['vlan'] * (count - 3) + ['ipv4', 'tcp'],
    # Tags, then IPv4 and IPv6 in turn, with Destination Options between them:
    # dissected one by one after IPv4, walked by IPv6.
    'mixed': lambda count: (['vlan'] * 3 + list(itertools.islice(itertools.cycle(
        ['ipv4', 'opts', 'opts', 'ipv6', 'opts', 'opts', 'opts']), count - 5)) + ['tcp']),
}


#: A TCP header whose Data Offset claims 32 octets, all of them present: snap
#: four off and the parser rejects it, leaving it to the #1518 fall-back.
SNAPPABLE = (struct.pack('!HHIIBBHHH', 40000, 9, 1, 0, 8 << 4, 0x10, 65535, 0, 0)
             + bytes.fromhex('020405b4' '01030306' '01010402'))


def octets(layers: 'list[str]', sport: int = 40000, segment: 'Optional[bytes]' = None) -> bytes:
    """The octets of ``layers``, outermost first, the last of them TCP from
    ``sport``, or ``segment`` if given."""
    data, inner = b'', None
    for name in reversed(layers):
        if name == 'tcp':
            data = wire.tcp(b'payload', seq=1, sport=sport) if segment is None else segment
        elif name == 'ipv4':
            data = wire.ipv4(data, proto=PROTO[inner])
        elif name == 'ipv6':
            data = wire.ipv6(data, nxt=PROTO[inner])
        elif name == 'opts':  # Hdr Ext Len 0, one PadN
            data = bytes([PROTO[inner], 0, 1, 4, 0, 0, 0, 0]) + data
        else:  # an 802.1Q tag: TCI 0, then the inner EtherType
            data = bytes(2) + ETHERTYPE[inner].to_bytes(2, 'big') + data
        inner = name
    return data


def ethernet(layers: 'list[str]', sport: int = 40000, segment: 'Optional[bytes]' = None) -> bytes:
    """An Ethernet frame carrying ``layers``."""
    return wire.ethernet(octets(layers, sport, segment), ETHERTYPE[layers[0]])


def record(data: bytes, snapped: int = 0) -> bytes:
    """A PCAP record of ``data``, with its last ``snapped`` octets left uncaptured."""
    captured = data[:len(data) - snapped]
    return struct.pack('<IIII', 1_500_000_000, 0, len(captured), len(data)) + captured


def chains(carrier: 'str', count: 'int', times: 'int') -> 'list[str]':
    """``times`` tunnels of ``carrier``, each carrying ``count`` Destination Options headers."""
    return ([carrier] + ['opts'] * count) * times + ['tcp']


class _Logged(logging.Handler):
    """Collect what the ``pcapkit`` logger reports of a recursion error."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.messages = []  # type: list[str]

    def emit(self, entry: 'logging.LogRecord') -> None:
        message = entry.getMessage()
        if 'recursion' in message.lower():
            self.messages.append(message)

    def __enter__(self) -> '_Logged':
        logging.getLogger('pcapkit').addHandler(self)
        return self

    def __exit__(self, *exc: object) -> None:
        logging.getLogger('pcapkit').removeHandler(self)


def depth(func: 'object') -> int:
    """How many Python frames deeper than its caller ``func()`` goes."""
    state = {'now': 0, 'most': 0}

    def profile(frame: object, event: str, arg: object) -> None:  # pylint: disable=unused-argument
        if event == 'call':
            state['now'] += 1
            state['most'] = max(state['most'], state['now'])
        elif event == 'return':
            state['now'] -= 1

    sys.setprofile(profile)
    try:
        func()  # type: ignore[operator]
    finally:
        sys.setprofile(None)
    return state['most']


class FrameLayerLimitTests(unittest.TestCase):
    """C.f. #1610."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def frame(self, data: bytes, snapped: int = 0, **kwargs: object) -> 'tuple[object, list[str]]':
        """The PCAP frame of ``data``, and the messages of the ProtocolWarnings it gave."""
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header
        from pcapkit.utilities.warnings import ProtocolWarning

        header = Header(GLOBAL).info
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            parsed = Frame(io.BytesIO(record(data, snapped)), num=1, header=header, **kwargs)
        return parsed, [str(item.message) for item in caught if issubclass(item.category, ProtocolWarning)]

    def raw_of(self, parsed: object) -> object:
        """The first :class:`~pcapkit.protocols.misc.raw.Raw` layer of ``parsed``."""
        from pcapkit.protocols.misc.raw import Raw

        layer = parsed
        while not isinstance(layer, Raw):
            layer = layer.payload  # type: ignore[attr-defined]
        return layer

    def assert_cut(self, layers: 'list[str]', parsed: object, messages: 'list[str]') -> None:
        """``parsed`` is the frame of ``layers``, cut at the 65th, with one warning."""
        self.assertNotIn('TCP', parsed)
        self.assertEqual(len(parsed.protochain), 65)  # type: ignore[attr-defined]
        self.assertEqual(len(messages), 1, messages)
        self.assertIn('limit of 64 layers', messages[0])

        # the 65th layer is the 64th after Ethernet, and the rest is kept as captured
        layer = self.raw_of(parsed)
        self.assertEqual(bytes(layer.data), octets(layers[63:]))  # type: ignore[attr-defined]
        self.assertEqual(layer.info.error, messages[0])  # type: ignore[attr-defined]
        named = ETHERTYPE if layers[62] == 'vlan' else PROTO
        self.assertEqual(int(layer.info.protocol), named[layers[63]])  # type: ignore[attr-defined]

    def test_the_limit_is_64(self) -> None:
        from pcapkit.protocols.protocol import FRAME_LAYER_LIMIT

        self.assertEqual(FRAME_LAYER_LIMIT, 64)

    def test_a_frame_of_64_layers_is_dissected_to_the_tcp(self) -> None:
        # Guard: below the old recursion cut-off, so this held before #1610 too.
        for shape, build in SHAPES.items():
            with self.subTest(shape=shape):
                parsed, messages = self.frame(ethernet(build(64)))
                self.assertIn('TCP', parsed)
                # the 64 layers, and the TCP payload, left raw as before
                self.assertEqual(len(parsed.protochain), 65)  # type: ignore[attr-defined]
                self.assertEqual(messages, [])

    def test_a_frame_past_64_layers_stops_at_the_limit(self) -> None:
        for shape, build in SHAPES.items():
            for count in PAST:
                with self.subTest(shape=shape, count=count):
                    layers = build(count)
                    parsed, messages = self.frame(ethernet(layers))
                    self.assert_cut(layers, parsed, messages)

    def test_tunnels_between_extension_header_chains_do_not_restart_the_count(self) -> None:
        # Three chains of 30, each under the extension header limit of 32, and
        # each in a tunnel of its own: the third chain's first header is the 65th
        # layer.
        for carrier in ('ipv4', 'ipv6'):
            with self.subTest(carrier=carrier):
                layers = chains(carrier, 30, 3)
                parsed, messages = self.frame(ethernet(layers))
                self.assert_cut(layers, parsed, messages)
                names = str(parsed.protochain).split(':')  # type: ignore[attr-defined]
                self.assertEqual(names.count('IPv6-Opts'), 60)

    def test_what_a_walked_header_dissects_counts_after_every_header_walked(self) -> None:
        # IPv6 walks its extension headers in a loop, but ESP dissects its
        # decrypted payload itself, walked or not. Behind 30 headers walked,
        # ESP is the 33rd layer, so a TCP behind 31 IPv4 headers in it is the
        # 65th. ESP-NULL decrypts with no keys.
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.internet.esp import ESPContext, SecurityAssociation

        registry = ContextRegistry.make(ESPContext(SecurityAssociation(spi=7)))
        walked = b''.join(bytes([60 if index < 29 else 50, 0, 1, 4, 0, 0, 0, 0]) for index in range(30))
        for nested, cut in ((30, False), (31, True)):
            with self.subTest(nested=nested):
                inner = octets(['ipv4'] * nested + ['tcp'])
                pad = -(len(inner) + 2) % 4  # ESP-NULL: padding, its length, Next Header 4
                esp = struct.pack('!II', 7, 1) + inner + bytes(range(1, pad + 1)) + bytes([pad, 4])
                parsed, messages = self.frame(wire.ethernet(wire.ipv6(walked + esp, nxt=60), 0x86DD),
                                              __context__=registry)

                # walked as an extension header, ESP refuses ``payload`` and
                # ``protochain``, so what it dissected is read off ``_next``
                names, layer = [], parsed.payload.payload.extension_headers[ExtensionHeader.ESP]  # type: ignore[attr-defined]
                while layer._next.__class__.__name__ not in ('Raw', 'NoPayload'):  # pylint: disable=protected-access
                    layer = layer._next  # pylint: disable=protected-access
                    names.append(layer.__class__.__name__)
                self.assertEqual(names, ['IPv4'] * nested + ([] if cut else ['TCP']))
                self.assertEqual(layer._next._past_layer_limit, cut)  # pylint: disable=protected-access
                self.assertEqual(len(messages), int(cut), messages)

    def test_where_both_limits_fall_on_one_layer_it_warns_once(self) -> None:
        # Guard: the 33rd header in a row is also the 65th layer, and the
        # extension header limit, which held before #1610 too, is the one named.
        for carrier in ('ipv4', 'ipv6'):
            with self.subTest(carrier=carrier):
                layers = ['ipv4'] * 30 + [carrier] + ['opts'] * 40 + ['tcp']
                parsed, messages = self.frame(ethernet(layers))
                self.assertNotIn('TCP', parsed)
                self.assertEqual(len(messages), 1, messages)
                self.assertIn('limit of 32 headers', messages[0])
                self.assertEqual(len(parsed.protochain), 65)  # type: ignore[attr-defined]

    def test_the_count_is_per_frame(self) -> None:
        from pcapkit import extract

        # one TCP flow per frame, and so one datagram per frame dissected to its TCP
        lengths = (64, 65, 64, 1000, 64)
        data = GLOBAL + b''.join(record(ethernet(SHAPES['IPv4 in IPv4'](count), 40000 + number))
                                 for number, count in enumerate(lengths))
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=io.BytesIO(data), nofile=True, engine='default',
                                reassembly=True, tcp=True)
        close_extractor(extractor)
        self.assertEqual(['TCP' in frame for frame in extractor.frame], [True, False, True, False, True])
        self.assertEqual(sorted(datagram.index[0] for datagram in extractor.reassembly.tcp), [1, 3, 5])

    def test_a_tcp_segment_past_the_limit_is_not_read_back_out_of_the_raw(self) -> None:
        # The layer past the limit is kept raw with an ``error``, as a TCP header
        # the parser rejected is, and in every shape here the IP layer above it
        # carries TCP. ``tcp_segment`` reads the fixed header of a rejected one
        # (#1518), and read this one too, so the TCP 65th layer was reassembled.
        from pcapkit.toolkit.pcap import tcp_segment

        for shape, build in SHAPES.items():
            with self.subTest(shape=shape):
                parsed, _ = self.frame(ethernet(build(65)))
                self.assertIsNone(tcp_segment(parsed))
                whole, _ = self.frame(ethernet(build(64)))
                self.assertIsNotNone(tcp_segment(whole))

        # A header the parser rejected is still read below the limit, but not
        # past it.
        for count, read in ((3, True), (64, True), (65, False)):
            with self.subTest(rejected=count):
                parsed, _ = self.frame(ethernet(SHAPES['IPv4 in IPv4'](count), segment=SNAPPABLE), snapped=4)
                self.assertNotIn('TCP', parsed)
                segment = tcp_segment(parsed)
                self.assertEqual(segment is not None, read)
                if read:
                    self.assertEqual((segment.srcport, segment.dstport, len(segment.header)), (40000, 9, 28))

    def test_a_protocol_constructed_directly_counts_from_the_layer_below_it(self) -> None:
        from pcapkit.protocols.link.ethernet import Ethernet

        layers = SHAPES['IPv4 in IPv4'](66)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            whole = Ethernet(ethernet(layers[1:]))
            cut = Ethernet(ethernet(layers))
        self.assertIn('TCP', whole)
        self.assertNotIn('TCP', cut)
        self.assertEqual(len(caught), 1, [str(item.message) for item in caught])
        self.assertEqual(len(cut.protochain), 66)

    def test_no_recursion_error_at_any_depth_and_the_time_stays_bounded(self) -> None:
        from pcapkit.protocols.link.ethernet import Ethernet

        def best(data: bytes) -> float:
            times = []
            for _ in range(3):
                start = time.perf_counter()
                Ethernet(data)
                times.append(time.perf_counter() - start)
            return min(times)

        cases = {'IPv4 in IPv4': 3000, '802.1Q tags': 10000, 'IPv6 in IPv6': 1500, 'mixed': 3000}
        with time_limit(scale_timeout(60)), warnings.catch_warnings(), _Logged() as logged:
            warnings.simplefilter('ignore')
            for shape, count in cases.items():
                with self.subTest(shape=shape):
                    build = SHAPES[shape]
                    short, deep = best(ethernet(build(66))), best(ethernet(build(count)))
                    self.assertLess(deep, 4 * short + 0.05, (short, deep))
        self.assertEqual(logged.messages, [])

    def test_a_cut_frame_rebuilds_byte_exact(self) -> None:
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header

        header = Header(GLOBAL).info
        shapes = dict(SHAPES, chains=lambda count: chains('ipv4', 30, count // 31 + 1))
        with warnings.catch_warnings(), _Logged() as logged:
            warnings.simplefilter('ignore')
            for shape, build in shapes.items():
                for count in PAST:
                    with self.subTest(shape=shape, count=count):
                        data = ethernet(build(count))
                        parsed, _ = self.frame(data)
                        self.assertEqual(parsed.data, record(data))  # type: ignore[attr-defined]
                        rebuilt = Frame.from_data(parsed.info.to_dict(), num=1, header=header)  # type: ignore[attr-defined]
                        self.assertEqual(rebuilt.data, record(data))
                        self.assertEqual(str(rebuilt.protochain), str(parsed.protochain))  # type: ignore[attr-defined]

                        packet = Ethernet(data)
                        self.assertEqual(Ethernet.from_data(packet.info.to_dict()).data, data)
        self.assertEqual(logged.messages, [])

    def test_rebuilding_a_cut_frame_warns_once_as_parsing_it_does(self) -> None:
        # Each layer rebuilt parses its own octets again, and each such parse
        # reaches the limit, so the rebuild warned once a layer: 65 times.
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header
        from pcapkit.utilities.warnings import ProtocolWarning

        header = Header(GLOBAL).info
        for shape, build in SHAPES.items():
            for count in PAST:
                with self.subTest(shape=shape, count=count):
                    parsed, messages = self.frame(ethernet(build(count)))
                    self.assertEqual(len(messages), 1, messages)
                    for data in (parsed.info, parsed.info.to_dict()):  # type: ignore[attr-defined]
                        with warnings.catch_warnings(record=True) as caught:
                            warnings.simplefilter('always')
                            Frame.from_data(data, num=1, header=header)
                        self.assertEqual([str(item.message) for item in caught
                                          if issubclass(item.category, ProtocolWarning)], messages)

    def test_rebuilding_a_cut_frame_goes_no_deeper_than_parsing_it(self) -> None:
        # Each layer rebuilt parses its own octets again, so were it to count
        # from itself, the rebuild would go 64 layers below every layer of the
        # frame, nearly twice as deep as the parse, and past the recursion limit.
        # It may go a frame or two deeper than the parse, from ``from_data``
        # itself, but not a layer's worth.
        from pcapkit.protocols.link.ethernet import Ethernet

        for carrier in ('ipv4', 'ipv6'):
            with self.subTest(carrier=carrier), warnings.catch_warnings(), _Logged() as logged:
                warnings.simplefilter('ignore')
                data = ethernet(chains(carrier, 30, 33) if carrier == 'ipv4' else SHAPES['IPv6 in IPv6'](1000))
                info = Ethernet(data).info.to_dict()
                parsing = depth(lambda: Ethernet(data))  # pylint: disable=cell-var-from-loop
                rebuilding = depth(lambda: Ethernet.from_data(info))  # pylint: disable=cell-var-from-loop
                self.assertLess(rebuilding - parsing, 9, (parsing, rebuilding))
                self.assertEqual(logged.messages, [])


if __name__ == '__main__':
    unittest.main()
