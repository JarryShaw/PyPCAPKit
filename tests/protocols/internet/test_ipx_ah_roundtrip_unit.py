# -*- coding: utf-8 -*-
"""IPX and AH headers rebuild byte for byte through ``from_data``.

GitHub issue #1315: :meth:`IPX._make_data
<pcapkit.protocols.internet.ipx.IPX._make_data>` handed the parsed
:class:`~pcapkit.protocols.data.internet.ipx.Address` objects to a schema that
packs 12 raw octets, so every rebuild raised :exc:`struct.error`; and
:meth:`IPX.make <pcapkit.protocols.internet.ipx.IPX.make>` recomputed the
packet length instead of keeping the parsed one.

GitHub issue #1327: the AH reserved field (:rfc:`4302#section-2.3`) was a
padding field, so a non-zero value was written back as zero.

Every case builds its own octets in memory and reads no capture.

Classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load, so that
they belong to the :mod:`pcapkit` import that is live when the test runs.

"""

import io
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Checksum, length, hop count, type, destination and source, then payload.
IPX_PACKETS = {
    'all-zero': bytes.fromhex('0000' '001e') + bytes(26),
    'addresses': (bytes.fromhex('ffff' '001e' '05' '11')
                  + bytes.fromhex('0a0b0c0d' '010203040506' '4004')
                  + bytes.fromhex('deadbeef' '112233445566' 'abcd')),
    'payload': bytes.fromhex('ffff' '0020' '05' '11') + bytes(24) + b'hi',
    'length-over-data': bytes.fromhex('ffff' '0040' '05' '11') + bytes(24) + b'hi',
    'length-under-header': bytes.fromhex('ffff' '0010' '05' '11') + bytes(24),
}

#: Next header, payload length, reserved, SPI, sequence number and ICV.
AH_HEADERS = {
    'reserved-nonzero': bytes.fromhex('0604' 'dead') + bytes(8) + bytes(range(12)),
    'reserved-zero': bytes.fromhex('3304' '0000' '00000100' '00000002') + bytes(range(12)),
}


class TestIPXRoundTrip(unittest.TestCase):
    """Pin the IPX rebuild of addresses and packet length."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_from_data_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.internet.ipx import IPX

        for name, packet in IPX_PACKETS.items():
            with self.subTest(packet=name), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                parsed = IPX(io.BytesIO(packet), len(packet), extension=True)
                self.assertEqual(IPX.from_data(parsed.info).data, packet)

    def test_make_computes_length_when_not_given(self) -> None:
        from pcapkit.protocols.internet.ipx import IPX

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            proto = IPX(payload=b'hi')
        self.assertEqual(proto.data[2:4], bytes.fromhex('0020'))


class TestAHRoundTrip(unittest.TestCase):
    """Pin the AH rebuild of the reserved field."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_from_data_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.internet.ah import AH

        for name, header in AH_HEADERS.items():
            with self.subTest(header=name), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                parsed = AH(io.BytesIO(header), len(header), extension=True)
                self.assertEqual(AH.from_data(parsed.info).data, header)

    def test_reserved_is_parsed(self) -> None:
        from pcapkit.protocols.internet.ah import AH

        header = AH_HEADERS['reserved-nonzero']
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = AH(io.BytesIO(header), len(header), extension=True)
        self.assertEqual(parsed.info.reserved, 0xdead)

    def test_make_reserved_defaults_to_zero(self) -> None:
        from pcapkit.protocols.internet.ah import AH

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            proto = AH(icv=bytes(12))
        self.assertEqual(proto.data[2:4], bytes(2))


if __name__ == '__main__':
    unittest.main()
