# -*- coding: utf-8 -*-
"""A later IPv6 fragment's data is raw, not an upper-layer header.

GitHub issue #1545: :class:`~pcapkit.protocols.internet.ipv6.IPv6` handed the
octets after a Fragment header with a non-zero offset to the upper-layer
dispatch on the Fragment header's Next Header, so a slice from the middle of a
UDP or TCP datagram read as a UDP or TCP header of its own -- ports and lengths
taken from payload octets.

:rfc:`8200#section-4.5` puts the upper-layer header in the first fragment only.
A later one carries a slice of the Fragmentable Part from its offset on, and
that slice starts with no header, so it is now a
:class:`~pcapkit.protocols.misc.raw.Raw` leaf. A first fragment, and an atomic
one (offset zero, M clear), are still dissected as before.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import unittest

from tests._support import reimport_once_per_class

#: Source and destination addresses.
ADDRS = (bytes.fromhex('20010db8000000000000000000000001')
         + bytes.fromhex('20010db8000000000000000000000002'))

#: Upper layers by name: the Next Header code, the protocol's alias, and a
#: header with payload that dissects as that protocol when it is one.
UPPER = {
    'UDP': (17, 'UDP', bytes.fromhex('c822138900280000') + bytes(range(0x40, 0x60))),
    'TCP': (6, 'TCP', bytes.fromhex('9c40000900000001000000005000ffff0000000078')),
}

#: Fragment Offsets of a later fragment, in 8-octet units: the smallest, and
#: the three of ``examples/captures/ipv6.pcap``'s frames 14 to 16.
LATER_OFFSETS = (1, 181, 362, 543)


def datagram(code: int, payload: bytes) -> bytes:
    """An IPv6 datagram with Next Header ``code`` and ``payload``."""
    return (bytes.fromhex('60000000') + len(payload).to_bytes(2, 'big')
            + bytes((code, 64)) + ADDRS + payload)


def fragment(code: int, offset: int, more: bool) -> bytes:
    """A Fragment header: Next Header ``code``, at ``offset`` 8-octet units."""
    return bytes((code, 0)) + (offset * 8 + more).to_bytes(2, 'big') + (110308).to_bytes(4, 'big')


class TestIPv6LaterFragmentRaw(unittest.TestCase):
    """Pin a later fragment's data as raw, and a first one's as dissected."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _parse(self, data: bytes) -> 'object':
        from pcapkit.protocols.internet.ipv6 import IPv6

        ipv6 = IPv6(data)
        self.assertEqual(ipv6.data, data)
        return ipv6

    def assert_rebuilds(self, ipv6: 'object') -> None:
        """``ipv6`` rebuilds byte for byte from its info and its info as a dict."""
        from pcapkit.protocols.internet.ipv6 import IPv6

        self.assertEqual(IPv6.from_data(ipv6.info).data, ipv6.data)
        self.assertEqual(IPv6.from_data(ipv6.info.to_dict()).data, ipv6.data)

    def test_later_fragment_data_is_raw(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag
        from pcapkit.protocols.misc.raw import Raw

        for name, (code, alias, upper) in UPPER.items():
            for offset in LATER_OFFSETS:
                for more in (True, False):
                    with self.subTest(upper=name, offset=offset, more=more):
                        ipv6 = self._parse(datagram(44, fragment(code, offset, more) + upper))
                        self.assertNotIn(alias, ipv6)
                        self.assertEqual(str(ipv6.protochain), 'IPv6:IPv6-Frag:Raw')
                        self.assertIs(type(ipv6.payload), Raw)
                        self.assertIsNone(ipv6.payload.info.protocol)
                        self.assertEqual(ipv6.payload.data, upper)

                        # the Next Header still names the first fragment's upper
                        # layer, and reassembly's split is untouched
                        self.assertEqual(ipv6.info.protocol, TransType(code))
                        self.assertEqual([type(ext) for ext in ipv6.extension_headers.values()],
                                         [IPv6_Frag])
                        self.assertEqual(ipv6.info.hdr_len, 48)
                        self.assertEqual(ipv6.info.raw_len, len(upper))
                        self.assertEqual(ipv6.info.fragment.payload, upper)
                        self.assert_rebuilds(ipv6)

    def test_first_and_atomic_fragments_are_dissected(self) -> None:
        # offset zero with M set is a first fragment; with M clear, an atomic
        # one (:rfc:`6946`), which is the whole datagram
        for name, (code, alias, upper) in UPPER.items():
            direct = self._parse(datagram(code, upper))
            for more in (True, False):
                with self.subTest(upper=name, more=more):
                    ipv6 = self._parse(datagram(44, fragment(code, 0, more) + upper))
                    self.assertIn(alias, ipv6)
                    self.assertEqual(str(ipv6.protochain), f'IPv6:IPv6-Frag:{alias}:Raw')
                    self.assertEqual(type(ipv6.payload), type(direct.payload))
                    self.assertEqual(ipv6.payload.info, direct.payload.info)
                    self.assertEqual(ipv6.info.fragment.payload, upper)
                    self.assert_rebuilds(ipv6)

    def test_made_later_fragment_parses_as_raw(self) -> None:
        # make -> parse: a later fragment built with an upper-layer header's
        # octets in it reads back as raw, and rebuilds to the octets made
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport.udp import UDP

        upper = UDP(srcport=51234, dstport=5001, payload=bytes(range(0x40, 0x60))).data
        header = IPv6_Frag(next=17, offset=181, mf=True, id=110308).data
        made = IPv6(next=44, src='2001:db8::1', dst='2001:db8::2', payload=header + upper)

        ipv6 = self._parse(made.data)
        self.assertNotIn('UDP', ipv6)
        self.assertIs(type(ipv6.payload), Raw)
        self.assertEqual(ipv6.payload.data, upper)
        self.assert_rebuilds(ipv6)


if __name__ == '__main__':
    unittest.main()
