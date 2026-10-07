# -*- coding: utf-8 -*-
"""IPv6 core headers rebuild byte for byte.

* GitHub issue #1230: :class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext`
  dropped the header body on rebuild, and wrote an overrun's ``Hdr Ext Len``
  as ``0xff``.
* GitHub issue #1231: next-header codes 253 and 254 were recorded as an
  extension header *and* decoded as the upper layer, so the payload was
  emitted twice.
* GitHub issue #1236: ``IPv6_Route.make(data=<bytes>)`` raised for every
  routing type.
* GitHub issue #1235 (part): the IPv6-Frag ``Res`` bits and the RPL routing
  header's 20 reserved bits were written back as zero.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import unittest
import warnings

from tests._support import reimport_once_per_class


def ipv6(nxt: int, payload: bytes) -> bytes:
    """Return an IPv6 header with next header ``nxt``, followed by ``payload``."""
    return (bytes.fromhex('60000000') + len(payload).to_bytes(2, 'big') + bytes([nxt, 64])
            + bytes(15) + b'\x01' + bytes(15) + b'\x02' + payload)


class TestIPv6CoreRoundTrip(unittest.TestCase):
    """Pin the byte-exact rebuild of the IPv6 core headers."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_ipv6_ext_rebuilds_body(self) -> None:
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext

        cases = {
            'len0': bytes.fromhex('3b00010203040506'),
            'len1': bytes.fromhex('3b01') + bytes(range(14)),
            'overrun': bytes.fromhex('3b00'),
        }
        for name, octets in cases.items():
            with self.subTest(case=name), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                parsed = IPv6_Ext(io.BytesIO(octets), len(octets), extension=True, alias=140)
                self.assertEqual(IPv6_Ext.from_data(parsed.info).data, octets)
        self.assertIsNone(parsed.info.next)

    def test_ipv6_ext_rebuilds_through_ipv6(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6

        frame = ipv6(140, bytes.fromhex('3b00010203040506'))
        self.assertEqual(IPv6.from_data(IPv6(frame).info).data, frame)

    def test_private_codes_are_not_extension_headers(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6

        for code in (253, 254):
            with self.subTest(code=code):
                frame = ipv6(code, bytes.fromhex('3b00010203040506'))
                parsed = IPv6(frame)
                self.assertEqual(parsed.info.__exthdr__, ())
                self.assertEqual(len(parsed.protochain), 2)
                self.assertEqual(IPv6.from_data(parsed.info).data, frame)

    def test_route_make_accepts_bytes_data(self) -> None:
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route

        for type_ in (0, 2, 3, 4, 5):
            with self.subTest(type=type_):
                built = IPv6_Route(next=59, type=type_, data=b'\x00' * 20)
                octets = built.data
                self.assertEqual(octets, bytes([59, 2, type_, 0]) + bytes(20))
                parsed = IPv6_Route(io.BytesIO(octets), len(octets), extension=True)
                self.assertEqual(IPv6_Route.from_data(parsed.info).data, octets)

    def test_route_make_rejects_bytes_that_do_not_parse(self) -> None:
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route
        from pcapkit.utilities.exceptions import ProtocolError

        # An RPL header whose Pad (15) exceeds the octets that follow it.
        with self.assertRaises(ProtocolError), warnings.catch_warnings():
            warnings.simplefilter('ignore')
            IPv6_Route(next=59, type=3, data=b'\x00\xf0\x00\x00')

    def test_frag_keeps_reserved_bits(self) -> None:
        from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag

        octets = bytes.fromhex('3b00000712345678')
        parsed = IPv6_Frag(io.BytesIO(octets), len(octets), extension=True)
        self.assertEqual(parsed.info.reserved, 3)
        self.assertEqual(IPv6_Frag.from_data(parsed.info).data, octets)

    def test_rpl_route_keeps_reserved_bits(self) -> None:
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route

        octets = bytes.fromhex('3b020301000abcde') + bytes(16)
        parsed = IPv6_Route(io.BytesIO(octets), len(octets), extension=True)
        self.assertEqual(parsed.info.reserved, 0xabcde)
        self.assertEqual(IPv6_Route.from_data(parsed.info).data, octets)


if __name__ == '__main__':
    unittest.main()
