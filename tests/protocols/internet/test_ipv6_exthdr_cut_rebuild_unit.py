# -*- coding: utf-8 -*-
"""A cut IPv6 extension header chain rebuilds byte-exact, from info and dict.

GitHub issue #1471: an upper layer cut short after an extension header fell
back to :class:`~pcapkit.protocols.misc.raw.Raw` over the *whole* IPv6 payload,
since :func:`~pcapkit.utilities.decorators.beholder` ignored the ``payload`` it
was handed, so the rebuild wrote the extension headers twice -- Destination
Options, TCP cut at 57 octets rebuilt 65.

GitHub issue #1473: a header whose dedicated parser raised is parsed by
:class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext` and written under its
``ext`` key, but the ``to_dict`` rebuild chose the dedicated class from the
``next`` code, which then missed fields only it parses -- ``AttributeError:
'HOPOPT' object has no attribute 'options'``.

Every case builds its own octets and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import struct
import unittest
import warnings

from tests._support import reimport_once_per_class

HOP, TCP, DST, AH, NONXT, HIP = 0, 6, 60, 51, 59, 139

#: A TCP header and one octet of data.
SEGMENT = struct.pack('!HHIIBBHHH', 1, 2, 0, 0, 0x50, 2, 0, 0, 0) + b'x'


def opts(nxt: int) -> bytes:
    """An 8-octet Hop-by-Hop or Destination Options header: one PadN."""
    return bytes([nxt, 0, 1, 4, 0, 0, 0, 0])


def auth(nxt: int) -> bytes:
    """A 24-octet Authentication Header with a 12-octet ICV."""
    return bytes([nxt, 4, 0, 0]) + bytes(20)


def hip(nxt: int) -> bytes:
    """A 40-octet HIPv2 header with no parameters."""
    return bytes([nxt, 4, 1, 0x21, 0, 0, 0, 0]) + bytes(32)


#: First next-header code and IPv6 payload of each chain.
CHAINS = {
    'dst-tcp': (DST, opts(TCP) + SEGMENT),
    'hop-tcp': (HOP, opts(TCP) + SEGMENT),
    'hop-dst-tcp': (HOP, opts(DST) + opts(TCP) + SEGMENT),
    'dst-ah-tcp': (DST, opts(AH) + auth(TCP) + SEGMENT),
    'hop-nonxt': (HOP, bytes([NONXT, 1, 1, 12]) + bytes(12)),
    'hip': (HIP, hip(NONXT)),
    'dst-hip': (DST, opts(HIP) + hip(NONXT)),
}


def packet(name: str) -> bytes:
    """The whole IPv6 packet of ``CHAINS[name]``."""
    code, body = CHAINS[name]
    return struct.pack('!IHBB', 6 << 28, len(body), code, 64) + bytes(32) + body


class TestIPv6ExtensionHeaderCutRebuild(unittest.TestCase):
    """Pin the rebuild of an extension header chain cut at every octet."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        quiet = warnings.catch_warnings()
        quiet.__enter__()  # pylint: disable=unnecessary-dunder-call
        self.addCleanup(quiet.__exit__, None, None, None)
        warnings.simplefilter('ignore')

    def test_every_cut_rebuilds_from_info_and_dict(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.link.ethernet import Ethernet

        for name in CHAINS:
            full = packet(name)
            for cut in range(40, len(full) + 1):
                for cls, data in ((IPv6, full[:cut]), (Ethernet, bytes(12) + b'\x86\xdd' + full[:cut])):
                    proto = cls(data, len(data))
                    with self.subTest(chain=name, cut=cut, layer=cls.__name__, form='parse'):
                        self.assertEqual(proto.data, data)
                    with self.subTest(chain=name, cut=cut, layer=cls.__name__, form='info'):
                        self.assertEqual(cls.from_data(proto.info).data, data)
                    with self.subTest(chain=name, cut=cut, layer=cls.__name__, form='dict'):
                        self.assertEqual(cls.from_data(proto.info.to_dict()).data, data)

    def test_raw_upper_layer_starts_past_the_extension_headers(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.misc.raw import Raw

        data = packet('dst-tcp')[:57]
        ip6 = IPv6(data, len(data))
        self.assertIsInstance(ip6.payload, Raw)
        self.assertEqual(ip6.payload.data, data[48:])
        self.assertEqual(len(IPv6.from_data(ip6.info).data), 57)

    def test_dict_rebuild_keeps_the_generic_parser(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext

        for cut in (48, 50, 52, 55):
            data = packet('hop-nonxt')[:cut]
            with self.subTest(cut=cut):
                ip6 = IPv6(data, len(data))
                self.assertIs(type(ip6._exthdr[ExtensionHeader.HOPOPT]), IPv6_Ext)
                _, chain = IPv6._lookup_exthdr(ip6.info.to_dict())
                self.assertEqual([parser for parser, _ in chain], [IPv6_Ext])
                self.assertEqual(IPv6.from_data(ip6.info.to_dict()).data, data)


if __name__ == '__main__':
    unittest.main()
