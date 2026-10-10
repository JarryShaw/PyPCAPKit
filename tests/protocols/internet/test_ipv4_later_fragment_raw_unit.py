# -*- coding: utf-8 -*-
"""A later IPv4 fragment's data is raw, not an upper-layer header.

GitHub issue #1553: :class:`~pcapkit.protocols.internet.ipv4.IPv4` handed the
payload of a datagram with a non-zero Fragment Offset to the upper-layer
dispatch on its Protocol field, so a slice from the middle of a UDP or TCP
datagram read as a UDP or TCP header of its own -- ports and lengths taken from
payload octets. It is the IPv4 counterpart of #1545.

:rfc:`791#section-3.2` puts the upper-layer header in the first fragment only.
A later one carries a slice of the datagram's data from its offset on, and that
slice starts with no header, so it is now a
:class:`~pcapkit.protocols.misc.raw.Raw` leaf, as Wireshark shows it (``data``,
under ``-o ip.defragment:FALSE``). A first fragment (offset zero, MF set) and
an unfragmented datagram are still dissected as before.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import unittest

from tests._support import reimport_once_per_class

#: Source and destination addresses.
ADDRS = bytes((1, 1, 1, 1, 2, 2, 2, 2))

#: Upper layers by name: the Protocol code, the protocol's alias, and a header
#: with payload that dissects as that protocol when it is one.
UPPER = {
    'UDP': (17, 'UDP', bytes.fromhex('c822138900280000') + bytes(range(0x40, 0x60))),
    'TCP': (6, 'TCP', bytes.fromhex('9c40000900000001000000005000ffff0000000078')),
}

#: Fragment Offsets of a later fragment, in 8-octet units: the smallest, the
#: issue's 185 (1480 octets, one Ethernet MTU's worth), and the largest.
LATER_OFFSETS = (1, 185, 0x1fff)

#: IPv4 options, padded to a 4-octet boundary: none, and NOP NOP NOP EOOL.
OPTIONS = (b'', bytes((1, 1, 1, 0)))


def datagram(code: int, payload: bytes, *, offset: int = 0, more: bool = False,
             options: bytes = b'') -> bytes:
    """An IPv4 datagram with Protocol ``code``, at ``offset`` 8-octet units."""
    ihl = 5 + len(options) // 4
    return (bytes((0x40 | ihl, 0)) + (ihl * 4 + len(payload)).to_bytes(2, 'big')
            + (0x1234).to_bytes(2, 'big') + ((more << 13) | offset).to_bytes(2, 'big')
            + bytes((64, code)) + b'\x00\x00' + ADDRS + options + payload)


class TestIPv4LaterFragmentRaw(unittest.TestCase):
    """Pin a later fragment's data as raw, and a first one's as dissected."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _parse(self, data: bytes) -> 'object':
        from pcapkit.protocols.internet.ipv4 import IPv4

        ipv4 = IPv4(data)
        self.assertEqual(ipv4.data, data)
        return ipv4

    def assert_rebuilds(self, ipv4: 'object') -> None:
        """``ipv4`` rebuilds byte for byte from its info and its info as a dict."""
        from pcapkit.protocols.internet.ipv4 import IPv4

        self.assertEqual(IPv4.from_data(ipv4.info).data, ipv4.data)
        self.assertEqual(IPv4.from_data(ipv4.info.to_dict()).data, ipv4.data)

    def test_later_fragment_data_is_raw(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.misc.raw import Raw

        for name, (code, alias, upper) in UPPER.items():
            for options in OPTIONS:
                for offset in LATER_OFFSETS:
                    for more in (True, False):
                        with self.subTest(upper=name, options=options.hex(), offset=offset, more=more):
                            ipv4 = self._parse(datagram(code, upper, offset=offset, more=more,
                                                        options=options))
                            self.assertNotIn(alias, ipv4)
                            self.assertEqual(str(ipv4.protochain), 'IPv4:Raw')
                            self.assertIs(type(ipv4.payload), Raw)
                            self.assertIsNone(ipv4.payload.info.protocol)
                            self.assertEqual(ipv4.payload.data, upper)

                            # the Protocol field still names the first fragment's
                            # upper layer, and what reassembly reads is untouched
                            self.assertEqual(ipv4.info.protocol, TransType(code))
                            self.assertEqual(ipv4.info.offset, offset * 8)
                            self.assertEqual(ipv4.info.flags.mf, more)
                            self.assertEqual(ipv4.info.hdr_len, 20 + len(options))
                            self.assertEqual(ipv4.info.len, 20 + len(options) + len(upper))
                            self.assertEqual(bytes(ipv4.packet.payload), upper)
                            self.assert_rebuilds(ipv4)

    def test_first_and_unfragmented_datagrams_are_dissected(self) -> None:
        # offset zero with MF set is a first fragment; with MF clear, the whole
        # datagram
        for name, (code, alias, upper) in UPPER.items():
            for options in OPTIONS:
                for more in (True, False):
                    with self.subTest(upper=name, options=options.hex(), more=more):
                        ipv4 = self._parse(datagram(code, upper, more=more, options=options))
                        self.assertIn(alias, ipv4)
                        self.assertEqual(str(ipv4.protochain), f'IPv4:{alias}:Raw')
                        self.assertEqual(ipv4.payload.data, upper)
                        self.assertEqual(ipv4.info.protocol, code)
                        self.assert_rebuilds(ipv4)

    def test_issue_repro_later_fragment_in_a_frame(self) -> None:
        # the issue's reproduction, carried in an Ethernet frame as a capture
        # would carry it: ``'UDP' in frame`` no longer holds
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.protocols.misc.raw import Raw

        made = IPv4(protocol='UDP', offset=185, payload=Raw(bytes(range(40))),
                    src='1.1.1.1', dst='2.2.2.2')
        ipv4 = self._parse(made.data)
        self.assertEqual(ipv4.info.offset, 1480)
        self.assertEqual(str(ipv4.protochain), 'IPv4:Raw')
        self.assertEqual(ipv4.payload.data, bytes(range(40)))
        self.assert_rebuilds(ipv4)

        wire = bytes.fromhex('020000000002' '020000000001' '0800') + made.data
        frame = Ethernet(wire)
        self.assertEqual(frame.data, wire)
        self.assertNotIn('UDP', frame)
        self.assertEqual(str(frame.protochain), 'Ethernet:IPv4:Raw')
        self.assertEqual(Ethernet.from_data(frame.info.to_dict()).data, wire)

    def test_made_later_fragment_parses_as_raw(self) -> None:
        # make -> parse: a later fragment built with a UDP object as its payload
        # writes the UDP octets, reads back as raw (as IPv6 does since #1545),
        # and rebuilds to the octets made
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport.udp import UDP

        upper = UDP(srcport=51234, dstport=5001, payload=bytes(range(0x40, 0x60)))
        for options in (None, [bytes((1, 1, 1, 0))]):
            with self.subTest(options=options):
                kwargs = {} if options is None else {'options': options}
                made = IPv4(protocol='UDP', offset=185, mf=True, payload=upper,
                            src='1.1.1.1', dst='2.2.2.2', **kwargs)
                self.assertEqual(made.data[made.info.hdr_len:], upper.data)
                self.assertNotIn('UDP', made)
                self.assertIs(type(made.payload), Raw)

                ipv4 = self._parse(made.data)
                self.assertNotIn('UDP', ipv4)
                self.assertIs(type(ipv4.payload), Raw)
                self.assertEqual(ipv4.payload.data, upper.data)
                self.assert_rebuilds(ipv4)


if __name__ == '__main__':
    unittest.main()
