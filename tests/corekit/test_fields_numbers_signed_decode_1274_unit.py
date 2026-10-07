# -*- coding: utf-8 -*-
"""A resolved signed number field decodes into its signed range.

GitHub issue #1274: :meth:`NumberField.post_process
<pcapkit.corekit.fields.numbers.NumberField.post_process>` masked the
decoded value with ``_bit_mask`` and returned it, so once ``__call__`` had set
that mask -- as it does for every field inside a :class:`Schema` -- a signed
field came back as its unsigned pattern: ``ffffffff`` read as ``4294967295``,
and the PCAP ``thiszone`` of ``-3600`` as ``4294963696``.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import unittest

from tests._support import reimport_once_per_class


class TestSignedNumberFieldDecode(unittest.TestCase):
    """Pin the decoded value and the rebuilt octets of signed fields."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_schema_int32_decodes_negative(self) -> None:
        from pcapkit.corekit.fields.numbers import Int32Field, UInt8Field
        from pcapkit.protocols.schema.schema import Schema

        class T(Schema):
            z: 'int' = Int32Field()
            u: 'int' = UInt8Field()

        # big-endian, the field's default byte order
        for raw, value in ((b'\xff\xff\xff\xff', -1), (b'\xff\xff\xf1\xf0', -3600),
                           (b'\x80\x00\x00\x00', -2**31), (b'\x7f\xff\xff\xff', 2**31 - 1)):
            with self.subTest(raw=raw.hex()):
                data = raw + b'\xff'
                schema = T.unpack(io.BytesIO(data), 5, {'__length__': 5})
                self.assertEqual(schema.z, value)
                self.assertEqual(schema.u, 255)
                self.assertEqual(T(z=schema.z, u=schema.u).pack({}), data)

    def test_pcap_thiszone_round_trips(self) -> None:
        from pcapkit.protocols.misc.pcap.header import Header

        data = bytes.fromhex('d4c3b2a1' '0200' '0400' 'f0f1ffff' '00000000' 'ffff0000' '01000000')
        header = Header(data)
        self.assertEqual(header.info.thiszone, -3600)
        self.assertEqual(Header.from_data(header.info).data, data)


if __name__ == '__main__':
    unittest.main()
