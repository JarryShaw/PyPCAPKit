# -*- coding: utf-8 -*-
"""An IPv6 extension header rebuilds byte for byte from its own info.

GitHub issue #1446: :class:`~pcapkit.protocols.internet.ipv6.IPv6` hands each
extension header the rest of the datagram, with ``extension=True``. The header
parses only itself -- its info holds no payload -- but its ``data`` kept every
octet after it, so ``type(ex).from_data(ex.info).data`` came back short: 8 of
the 28 octets of an 8-octet header followed by a UDP datagram.

``data`` now holds the header alone, which is also what the parent's
``from_data`` concatenates, so the parent rebuild is pinned alongside.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import importlib
import unittest

from tests._support import reimport_once_per_class

#: Module, class and IPv6 Next Header code of each extension header.
EXTENSIONS = (
    ('hopopt', 'HOPOPT', 0),
    ('ipv6_route', 'IPv6_Route', 43),
    ('ipv6_frag', 'IPv6_Frag', 44),
    ('ipv6_opts', 'IPv6_Opts', 60),
    ('mh', 'MH', 135),
    ('ah', 'AH', 51),
    ('hip', 'HIP', 139),
)


class TestIPv6ExtHeaderRebuild(unittest.TestCase):
    """Pin ``from_data(info).data == data`` for extension-mode headers."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _parse(self, mod: str, cls: str, code: int, upper: bytes) -> 'tuple[bytes, object, object]':
        from pcapkit.protocols.internet.ipv6 import IPv6

        klass = getattr(importlib.import_module(f'pcapkit.protocols.internet.{mod}'), cls)
        header = klass(next=17, payload=b'').data
        ipv6 = IPv6(IPv6(next=code, src='2001:db8::1', dst='2001:db8::2',
                         payload=header + upper).data)
        ext = next(iter(ipv6.extension_headers.values()))
        self.assertIs(type(ext), klass)
        return header, ext, ipv6

    def test_extension_header_rebuilds_from_info(self) -> None:
        from pcapkit.protocols.transport.udp import UDP

        upper = UDP(srcport=1, dstport=2, payload=b'hello world!').data
        for mod, cls, code in EXTENSIONS:
            with self.subTest(header=cls):
                header, ext, _ = self._parse(mod, cls, code, upper)
                self.assertEqual(ext.data, header)
                self.assertEqual(len(ext), ext.length)
                self.assertEqual(type(ext).from_data(ext.info).data, ext.data)

    def test_parent_ipv6_still_rebuilds(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.transport.udp import UDP

        upper = UDP(srcport=1, dstport=2, payload=b'hello world!').data
        for mod, cls, code in EXTENSIONS:
            with self.subTest(header=cls):
                _, _, ipv6 = self._parse(mod, cls, code, upper)
                self.assertEqual(IPv6.from_data(ipv6.info).data, ipv6.data)

    def test_fragment_keeps_header_only(self) -> None:
        # a non-first fragment, as in ``examples/captures/ipv6.pcap``: the
        # remainder is fragment data, not a decodable upper layer
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag

        header = IPv6_Frag(next=17, offset=181, id=0x1234).data
        ipv6 = IPv6(IPv6(next=44, src='2001:db8::1', dst='2001:db8::2',
                         payload=header + bytes(range(256)) * 2).data)
        ext = ipv6.extension_headers.get(44)
        self.assertEqual(ext.data, header)
        self.assertEqual(IPv6_Frag.from_data(ext.info).data, header)
        self.assertEqual(IPv6.from_data(ipv6.info).data, ipv6.data)

    def test_standalone_parse_keeps_payload(self) -> None:
        # without ``extension=True`` the header still owns what follows it
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.transport.udp import UDP

        upper = UDP(srcport=1, dstport=2, payload=b'hello world!').data
        packet = HOPOPT(next=17, payload=upper).data
        hop = HOPOPT(packet)
        self.assertEqual(hop.data, packet)
        self.assertEqual(HOPOPT.from_data(hop.info).data, packet)


if __name__ == '__main__':
    unittest.main()
