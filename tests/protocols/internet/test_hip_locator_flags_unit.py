# -*- coding: utf-8 -*-
"""HIP ``LOCATOR_SET`` keeps the seven reserved bits of each locator's flags octet.

GitHub issue #1365. :rfc:`8046#section-4` lays the fourth octet of a locator out
as ``Reserved`` (7 bits) followed by ``P`` (1 bit). ``Locator.flags`` declared only
``preferred: (7, 1)``, so the seven high-order bits were dropped on rebuild: flags
``0xfe`` parsed and rebuilt through ``from_data`` as ``0x00``. The fix names them
``reserved: (0, 7)``, per the #654 per-site policy, and carries them through
:class:`~pcapkit.protocols.data.internet.hip.Locator` and ``make()``.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.
"""

import unittest
import warnings

from tests._support import reimport_once_per_class

#: Header fields shared by every HIP packet built here.
HIP_BASE = {
    'next': 6, 'packet': 1, 'version': 2, 'checksum': b'\x00\x00',
    'controls_anonymous': False, 'shit': 0, 'rhit': 0, 'payload': b'',
}

#: Offset of the first locator's flags octet: the 40-octet HIP header, the
#: parameter's ``Type`` and ``Length``, then ``Traffic``, ``Type`` and ``Length``.
FLAGS_OFFSET = 40 + 4 + 3


class TestHIPLocatorFlags(unittest.TestCase):
    """Pin every bit of the locator flags octet across parse, rebuild and make."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _frame(self, flags: int) -> bytes:
        """Build a one-locator ``LOCATOR_SET`` packet whose flags octet is ``flags``."""
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        octets = bytearray(HIP(
            parameters=[(Parameter.LOCATOR_SET,
                         {'locator_set': [{'ip': '2001:db8::1'}]})],
            extension=True, **HIP_BASE).data)
        self.assertEqual(octets[FLAGS_OFFSET], 0)
        octets[FLAGS_OFFSET] = flags
        return bytes(octets)

    def _parse(self, frame: bytes):  # type: ignore[no-untyped-def]
        from pcapkit.protocols.internet.hip import HIP

        with warnings.catch_warnings():
            # Nested ``Locator`` schemas warn about their placeholder length;
            # that is pre-existing noise unrelated to the flags octet.
            warnings.simplefilter('ignore')
            return HIP(frame, len(frame), extension=True)

    def test_from_data_rebuilds_every_flags_bit(self) -> None:
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        for flags in (0x00, 0x01, 0xfe, 0xff, 0x80, 0x55):
            with self.subTest(flags=hex(flags)):
                frame = self._frame(flags)
                parsed = self._parse(frame)
                rebuilt = HIP.from_data(parsed.info)
                self.assertEqual(rebuilt.data[FLAGS_OFFSET], flags)
                self.assertEqual(rebuilt.data, frame)

                locator = parsed.info.parameters[Parameter.LOCATOR_SET].locator_set[0]
                self.assertEqual(locator.reserved, flags >> 1)
                self.assertEqual(locator.preferred, bool(flags & 1))

    def test_make_writes_reserved_from_keywords(self) -> None:
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        built = HIP(
            parameters=[(Parameter.LOCATOR_SET,
                         {'locator_set': [{'ip': '2001:db8::1', 'reserved': 0x7f,
                                           'preferred': False}]})],
            extension=True, **HIP_BASE)
        self.assertEqual(built.data[FLAGS_OFFSET], 0xfe)
        self.assertEqual(built.data, self._frame(0xfe))

    def test_make_defaults_reserved_to_zero(self) -> None:
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        built = HIP(
            parameters=[(Parameter.LOCATOR_SET,
                         {'locator_set': [{'ip': '2001:db8::1', 'preferred': True}]})],
            extension=True, **HIP_BASE)
        self.assertEqual(built.data[FLAGS_OFFSET], 0x01)


if __name__ == '__main__':
    unittest.main()
