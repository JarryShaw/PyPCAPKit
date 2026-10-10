# -*- coding: utf-8 -*-
"""A chain of IPv6 extension headers is dissected to 32 headers, and no further.

GitHub issue #1604: inside IPv4, each IPv6 extension header dissects the next
one itself, so a long chain ran into Python's recursion limit, and
:func:`~pcapkit.utilities.decorators.beholder` caught the ``RecursionError``
and left the rest raw, silently. Where that happened depended on the
interpreter and the stack -- after 79 headers on Python 3.11, and between 85
and 90 on 3.14, from a script at the default limit -- and IPv6, which walks its
chain in a loop, went on to any depth.

Now both stop at :data:`~pcapkit.protocols.internet.internet.EXTENSION_HEADER_LIMIT`
headers in a row: what follows is kept as
:class:`~pcapkit.protocols.misc.raw.Raw`, with one
:exc:`~pcapkit.utilities.warnings.ProtocolWarning`, however long the chain and
whatever the recursion limit.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import sys
import unittest
import warnings

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

#: The TCP segment every chain ends in.
SEGMENT = wire.tcp(b'payload', seq=1)

#: Ethernet II EtherTypes of the two carriers.
ETHERTYPE = {'ipv4': 0x0800, 'ipv6': 0x86DD}


def options(nxt: int) -> bytes:
    """An 8-octet Destination Options header: Hdr Ext Len 0 and one PadN."""
    return bytes([nxt, 0, 1, 4, 0, 0, 0, 0])


def ah(nxt: int) -> bytes:
    """A 12-octet Authentication Header, its fixed part only (Payload Length 1)."""
    return bytes([nxt, 1, 0, 0]) + bytes.fromhex('0000100000000001')


def chain(count: int, *, mixed: bool = False, last: int = 6) -> bytes:
    """``count`` extension headers, then :data:`SEGMENT`.

    Destination Options headers only, or alternately Destination Options and AH
    when ``mixed``, the first and the last always Destination Options. Each
    names the next, and the last names ``last``.

    """
    kinds = [ah if mixed and index % 2 and index < count - 1 else options for index in range(count)]
    codes = [51 if kind is ah else 60 for kind in kinds]
    return b''.join(kind(nxt) for kind, nxt in zip(kinds, codes[1:] + [last])) + SEGMENT


def ip(carrier: str, payload: bytes) -> bytes:
    """An IPv4 or IPv6 packet whose first header after its own is Destination Options."""
    if carrier == 'ipv4':
        return wire.ipv4(payload, proto=60)
    return wire.ipv6(payload, nxt=60)


def frame(carrier: str, count: int, *, mixed: bool = False) -> bytes:
    """An Ethernet frame of IPv4 or IPv6 whose payload is :func:`chain`."""
    return wire.ethernet(ip(carrier, chain(count, mixed=mixed)), ETHERTYPE[carrier])


def raw_of(parsed: object) -> object:
    """The first :class:`~pcapkit.protocols.misc.raw.Raw` layer of ``parsed``, if any."""
    from pcapkit.protocols.misc.null import NoPayload
    from pcapkit.protocols.misc.raw import Raw

    layer = parsed
    while not isinstance(layer, (Raw, NoPayload)):
        layer = layer.payload  # type: ignore[attr-defined]
    return layer if isinstance(layer, Raw) else None


class _Depth:
    """Lower the recursion limit to ``margin`` frames above the caller's."""

    def __init__(self, margin: int) -> None:
        self.margin = margin

    def __enter__(self) -> '_Depth':
        depth, frame_ = 0, sys._getframe()  # pylint: disable=protected-access
        while frame_ is not None:
            depth, frame_ = depth + 1, frame_.f_back
        self.saved = sys.getrecursionlimit()
        sys.setrecursionlimit(depth + self.margin)
        return self

    def __exit__(self, *exc: object) -> None:
        sys.setrecursionlimit(self.saved)


class ExtensionHeaderChainLimitTests(unittest.TestCase):
    """C.f. #1604."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def dissect(self, data: bytes) -> 'tuple[object, list[str]]':
        """The frame ``data`` parses to, and the messages of the ProtocolWarnings it gave."""
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.utilities.warnings import ProtocolWarning

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            parsed = Ethernet(data)
        return parsed, [str(item.message) for item in caught if issubclass(item.category, ProtocolWarning)]

    def summary(self, data: bytes) -> 'tuple[object, ...]':
        """What a cut chain comes to: its layers, the raw remainder and the warnings."""
        parsed, messages = self.dissect(data)
        layer = raw_of(parsed)
        if layer is None:
            return (str(parsed.protochain), None, None, tuple(messages))
        return (str(parsed.protochain), layer.info.protocol, len(layer.data), tuple(messages))

    def test_the_limit_is_32(self) -> None:
        from pcapkit.protocols.internet.internet import EXTENSION_HEADER_LIMIT

        self.assertEqual(EXTENSION_HEADER_LIMIT, 32)

    def test_a_chain_of_32_is_dissected_to_the_tcp(self) -> None:
        for carrier in ETHERTYPE:
            for mixed in (False, True):
                with self.subTest(carrier=carrier, mixed=mixed):
                    parsed, messages = self.dissect(frame(carrier, 32, mixed=mixed))
                    self.assertIn('TCP', parsed)
                    names = str(parsed.protochain).split(':')
                    self.assertEqual(names.count('IPv6-Opts') + names.count('AH'), 32, names)
                    self.assertEqual(messages, [])

    def test_a_chain_of_33_stops_at_the_limit(self) -> None:
        from pcapkit.const.reg.transtype import TransType

        for carrier in ETHERTYPE:
            for mixed in (False, True):
                with self.subTest(carrier=carrier, mixed=mixed):
                    payload = chain(33, mixed=mixed)
                    parsed, messages = self.dissect(frame(carrier, 33, mixed=mixed))
                    self.assertNotIn('TCP', parsed)
                    names = str(parsed.protochain).split(':')
                    self.assertEqual(names.count('IPv6-Opts') + names.count('AH'), 32, names)

                    layer = raw_of(parsed)
                    # the 33rd header on, kept as it was captured
                    cut = len(payload) - len(SEGMENT) - len(options(6))
                    self.assertEqual(bytes(layer.data), payload[cut:])
                    self.assertEqual(layer.info.protocol, TransType.IPv6_Opts)

                    self.assertEqual(len(messages), 1, messages)
                    self.assertIn('limit of 32 headers', messages[0])
                    self.assertEqual(layer.info.error, messages[0])

    def test_where_a_chain_stops_depends_on_neither_its_length_nor_the_recursion_limit(self) -> None:
        for carrier in ETHERTYPE:
            with self.subTest(carrier=carrier):
                want = self.summary(frame(carrier, 33))
                for count in (33, 34, 100, 1000):
                    for margin in (None, 550):
                        with self.subTest(count=count, margin=margin):
                            data = frame(carrier, count)
                            if margin is None:
                                got = self.summary(data)
                            else:
                                with _Depth(margin):
                                    got = self.summary(data)
                            # the remainder is longer by the headers past the 33rd
                            self.assertEqual(got[:2] + got[3:], want[:2] + want[3:])
                            self.assertEqual((got[2] or 0) - (want[2] or 0), (count - 33) * len(options(6)))

    def test_a_chain_of_32_fits_a_lowered_recursion_limit(self) -> None:
        for carrier in ETHERTYPE:
            with self.subTest(carrier=carrier), _Depth(550):
                parsed, messages = self.dissect(frame(carrier, 32))
                self.assertIn('TCP', parsed)
                self.assertEqual(messages, [])

    def test_layers_between_two_chains_start_a_new_count(self) -> None:
        # Two chains of 20, with IP-in-IP between them: 40 headers in all, but
        # never more than 20 in a row.
        for carrier, tunnel in (('ipv4', 4), ('ipv6', 41)):
            with self.subTest(carrier=carrier):
                outer = chain(20, last=tunnel)[:-len(SEGMENT)]
                data = wire.ethernet(ip(carrier, outer + ip(carrier, chain(20))), ETHERTYPE[carrier])
                parsed, messages = self.dissect(data)
                self.assertIn('TCP', parsed)
                self.assertEqual(str(parsed.protochain).split(':').count('IPv6-Opts'), 40)
                self.assertEqual(messages, [])

    def test_a_cut_frame_rebuilds_byte_exact(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.link.ethernet import Ethernet

        for carrier, klass in (('ipv4', IPv4), ('ipv6', IPv6)):
            for count in (32, 33, 1000):
                with self.subTest(carrier=carrier, count=count), warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    data = frame(carrier, count)
                    parsed = Ethernet(data)
                    self.assertEqual(parsed.data, data)
                    self.assertEqual(Ethernet.from_data(parsed.info.to_dict()).data, data)
                    packet = klass(data[14:])
                    self.assertEqual(klass.from_data(packet.info.to_dict()).data, data[14:])


if __name__ == '__main__':
    unittest.main()
