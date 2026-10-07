# -*- coding: utf-8 -*-
"""HIP writes Header Length 4 when it carries no parameters.

GitHub issue #1189: :meth:`HIP.make <pcapkit.protocols.internet.hip.HIP.make>`
wrote Header Length ``0`` for ``parameters=None``. RFC 7401 §5.1 counts the
field in 8-octet units excluding the first 8, so the two 16-octet HITs alone
make 4 the minimum. The header's own re-parse then computed a parameter length
of ``-32`` and raised ``ProtocolError``. :meth:`HIP.read
<pcapkit.protocols.internet.hip.HIP.read>` now rejects a wire Header Length
below 4 up front.

Every case builds its own octets in memory and reads no capture.

:class:`HIP` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load, so it
always belongs to the live :mod:`pcapkit` import.

"""

import unittest

from tests._support import reimport_once_per_class

#: Keyword arguments for a parameterless HIP header with no payload.
KWARGS = dict(next=59, packet=1, checksum=b'\x00\x00', controls_anonymous=False,
              shit=0, rhit=0, payload=b'')


class TestHIPParameterlessLength(unittest.TestCase):
    """Pin Header Length for a HIP header without parameters."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_make_without_parameters_writes_length_4(self) -> None:
        from pcapkit.protocols.internet.hip import HIP

        for version in (1, 2):
            with self.subTest(version=version):
                proto = HIP(parameters=None, version=version, **KWARGS)
                self.assertEqual(len(proto.data), 40)
                self.assertEqual(proto.data[1], 4)
                self.assertEqual(proto.info.length, 40)
                self.assertNotIn('parameters', proto.info)

    def test_parameterless_header_parses_back(self) -> None:
        from pcapkit.protocols.internet.hip import HIP

        for version in (1, 2):
            with self.subTest(version=version):
                data = HIP(parameters=None, version=version, **KWARGS).data
                parsed = HIP(data)
                self.assertEqual(parsed.info.length, 40)
                self.assertEqual(parsed.info.version, version)
                self.assertEqual(parsed.data, data)

    def test_read_rejects_header_length_below_4(self) -> None:
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.utilities.exceptions import ProtocolError

        for value in (0, 3):
            with self.subTest(len=value):
                # Next Header, Header Length, Packet Type 1, Version 2, then
                # checksum, controls and the two HITs, all zero.
                data = bytes([59, value, 0x01, 0x21]) + bytes(36)
                with self.assertRaisesRegex(ProtocolError, 'invalid header length'):
                    HIP(data)


if __name__ == '__main__':
    unittest.main()
