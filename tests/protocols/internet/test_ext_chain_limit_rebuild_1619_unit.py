# -*- coding: utf-8 -*-
"""Rebuilding a frame cut at the extension header chain limit warns once.

GitHub issue #1619: #1604 bounded a chain of IPv6 extension headers at
:data:`~pcapkit.utilities.config.EXTENSION_HEADER_LIMIT` headers,
with one :exc:`~pcapkit.utilities.warnings.ProtocolWarning`, and parsing a cut
frame does warn once. But each layer :meth:`from_data
<pcapkit.protocols.protocol.ProtocolBase.from_data>` rebuilds parses its own
octets again, and each such parse counted its chain afresh, from ``0``: so every
one that reached the limit warned of it, twice for IPv6 and up to 33 times for
IPv4, and went up to 32 headers past where the parse had stopped.

Now a rebuilt payload takes its place in its chain from the layer it is the
payload of, as #1610 has it take its place in the frame, and only the layer
being rebuilt warns, once its own parse gets to the limit.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import struct
import sys
import unittest
import warnings

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

#: The TCP segment every chain ends in.
SEGMENT = wire.tcp(b'payload', seq=1)

#: Ethernet II EtherTypes of the two carriers.
ETHERTYPE = {'ipv4': 0x0800, 'ipv6': 0x86DD}

#: Protocol numbers of Hop-by-Hop Options and Destination Options.
HEADERS = {'HOPOPT': 0, 'IPv6-Opts': 60}

#: Chain lengths: at the limit, past it by one, and by far.
COUNTS = (32, 33, 100, 1000)

#: Little-endian PCAP global header: v2.4, snaplen 65535, Ethernet.
GLOBAL = bytes.fromhex('d4c3b2a1' '0200' '0400' '00000000' '00000000' 'ffff0000' '01000000')


def chain(count: int, code: int) -> bytes:
    """``count`` 8-octet headers of protocol ``code``, each one PadN, then :data:`SEGMENT`."""
    return b''.join(bytes([code if index < count - 1 else 6, 0, 1, 4, 0, 0, 0, 0])
                    for index in range(count)) + SEGMENT


def ip(carrier: str, payload: bytes, code: int) -> bytes:
    """An IPv4 or IPv6 packet of ``payload``, whose first header after its own is ``code``."""
    if carrier == 'ipv4':
        return wire.ipv4(payload, proto=code)
    return wire.ipv6(payload, nxt=code)


def frame(carrier: str, count: int, code: int) -> bytes:
    """An Ethernet frame of IPv4 or IPv6 whose payload is :func:`chain`."""
    return wire.ethernet(ip(carrier, chain(count, code), code), ETHERTYPE[carrier])


def tunnelled(carrier: str, tunnels: int, count: int) -> bytes:
    """An Ethernet frame of ``tunnels`` IPv4 headers in IPv4, then a ``carrier``
    packet of ``count`` Destination Options headers."""
    data = ip(carrier, chain(count, 60), 60)
    inner = 4 if carrier == 'ipv4' else 41
    for _ in range(tunnels):
        data, inner = wire.ipv4(data, proto=inner), 4
    return wire.ethernet(data, 0x0800)


def record(data: bytes) -> bytes:
    """A PCAP record of ``data``, captured whole."""
    return struct.pack('<IIII', 1_500_000_000, 0, len(data), len(data)) + data


def depth(func: 'object') -> int:
    """How many Python frames deeper than its caller ``func()`` goes."""
    state = {'now': 0, 'most': 0}

    def profile(frame_: object, event: str, arg: object) -> None:  # pylint: disable=unused-argument
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


class ExtensionHeaderChainRebuildTests(unittest.TestCase):
    """C.f. #1619."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def messages(self, func: 'object') -> 'tuple[object, list[str]]':
        """What ``func()`` returns, and the messages of the ProtocolWarnings it gave."""
        from pcapkit.utilities.warnings import ProtocolWarning

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            result = func()  # type: ignore[operator]
        return result, [str(item.message) for item in caught if issubclass(item.category, ProtocolWarning)]

    def assert_rebuilds_as_parsed(self, klass: type, data: bytes, warned: int, **kwargs: object) -> 'list[str]':
        """``klass`` parses ``data`` with ``warned`` warnings, and rebuilds it, from
        its info and from that info as a :obj:`dict`, byte-exact, to the same
        protocol chain and with the same warnings, which are returned."""
        parsed, messages = self.messages(lambda: klass(data, **kwargs))  # type: ignore[operator]
        self.assertEqual(len(messages), warned, messages)
        for info in (parsed.info, parsed.info.to_dict()):  # type: ignore[attr-defined]
            with self.subTest(info=type(info).__name__):
                rebuilt, again = self.messages(lambda: klass.from_data(info, **kwargs))  # type: ignore[attr-defined] # pylint: disable=cell-var-from-loop
                self.assertEqual(again, messages)
                self.assertEqual(rebuilt.data, data)  # type: ignore[attr-defined]
                self.assertEqual(str(rebuilt.protochain), str(parsed.protochain))  # type: ignore[attr-defined]
        return messages

    def test_rebuilding_a_cut_frame_warns_as_often_as_parsing_it(self) -> None:
        # Rebuilt, IPv6 and the Ethernet around it both warned, and over IPv4
        # so did each header rebuilt whose own count got to the chain limit
        # before the frame limit: 33 times.
        from pcapkit.protocols.link.ethernet import Ethernet

        for carrier in ETHERTYPE:
            for name, code in HEADERS.items():
                for count in COUNTS:
                    with self.subTest(carrier=carrier, header=name, count=count):
                        self.assert_rebuilds_as_parsed(Ethernet, frame(carrier, count, code), int(count > 32))

    def test_a_layer_rebuilt_on_its_own_counts_as_one_parsed_on_its_own(self) -> None:
        # A protocol constructed from its own octets is in no chain, and counts
        # the next header as the first; so is one rebuilt on its own, rather
        # than one past the layer it was the payload of.
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.internet.ipv6 import IPv6

        for klass, carrier in ((IPv4, 'ipv4'), (IPv6, 'ipv6')):
            for count in COUNTS:
                with self.subTest(carrier=carrier, count=count):
                    self.assert_rebuilds_as_parsed(klass, ip(carrier, chain(count, 0), 0), int(count > 32))

        # The HOPOPT parsed on its own is followed by 32 headers, then 33.
        for count, warned in ((33, 0), (34, 1), (1000, 1)):
            with self.subTest(count=count):
                self.assert_rebuilds_as_parsed(HOPOPT, chain(count, 0), warned)

    def test_where_both_limits_fall_on_one_layer_rebuilding_warns_once(self) -> None:
        # The 33rd header in a row is also the 65th layer: rebuilt, every IP
        # layer around the chain warned of it once more, 33 times in all.
        # Ethernet constructed on its own is not counted, so it takes 31
        # tunnels, and 30 in a frame.
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header

        header = Header(GLOBAL).info
        for carrier in ETHERTYPE:
            for count in (40, 1000):
                with self.subTest(carrier=carrier, count=count):
                    for messages in (self.assert_rebuilds_as_parsed(Ethernet, tunnelled(carrier, 31, count), 1),
                                     self.assert_rebuilds_as_parsed(Frame, record(tunnelled(carrier, 30, count)),
                                                                    1, num=1, header=header)):
                        self.assertIn('limit of 32 headers', messages[0])

                    # and both do fall there: one tunnel more, and the frame
                    # limit falls first
                    messages = self.assert_rebuilds_as_parsed(Ethernet, tunnelled(carrier, 32, count), 1)
                    self.assertIn('limit of 64 layers', messages[0])

    def test_where_the_frame_limit_falls_first_rebuilding_warns_once(self) -> None:
        # Guard: 40 tunnels put the 65th layer at the chain's 24th header, short
        # of the chain limit; the rebuild warned once before #1619 too.
        from pcapkit.protocols.link.ethernet import Ethernet

        for carrier in ETHERTYPE:
            with self.subTest(carrier=carrier):
                messages = self.assert_rebuilds_as_parsed(Ethernet, tunnelled(carrier, 40, 40), 1)
                self.assertIn('limit of 64 layers', messages[0])

    def test_rebuilding_a_cut_frame_goes_no_deeper_than_parsing_it(self) -> None:
        # Each header rebuilt over IPv4 counted the chain from itself, so its
        # parse went up to 32 headers past the cut: 123 frames deeper than the
        # parse, at 1000 headers. It may go a frame or two deeper, from
        # ``from_data`` itself, but not a header's worth.
        from pcapkit.protocols.link.ethernet import Ethernet

        for carrier in ETHERTYPE:
            for count in (33, 1000):
                with self.subTest(carrier=carrier, count=count), warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    data = frame(carrier, count, 0)
                    info = Ethernet(data).info.to_dict()
                    parsing = depth(lambda: Ethernet(data))  # pylint: disable=cell-var-from-loop
                    rebuilding = depth(lambda: Ethernet.from_data(info))  # pylint: disable=cell-var-from-loop
                    self.assertLess(rebuilding - parsing, 9, (parsing, rebuilding))


if __name__ == '__main__':
    unittest.main()
