# -*- coding: utf-8 -*-
"""HIP keeps the reserved bits of the ``Version`` octet and the route ``Flags``.

GitHub issue #1417. Three HIP ``BitField`` namespaces left bits unnamed, so those
bits were packed as zero on rebuild (start, length):

* ``HIP.ver``: (4, 3) -- the ``RES`` bits between ``Version`` and the fixed
  low-order ``1`` (:rfc:`7401#section-5.1`);
* ``RouteDstParameter.flags`` and ``RouteViaParameter.flags``: (2, 14) -- the
  reserved bits after ``S`` and ``M`` (:rfc:`6028#section-5`).

The fix names a ``reserved`` sub-field at each site, per the #654 per-site
policy, and carries it through the data model and ``make()``.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.
"""

import unittest

from tests._support import reimport_once_per_class

#: Header fields shared by every HIP packet built here.
HIP_BASE = {
    'next': 59, 'packet': 1, 'version': 2, 'checksum': b'\x00\x00',
    'controls_anonymous': False, 'shit': 0, 'rhit': 0, 'payload': b'',
}

#: Offset of the ``Version`` octet in the HIP header.
VER_OFFSET = 3

#: Offset of the first parameter's two-octet ``Flags``: the 40-octet HIP header,
#: then the parameter's ``Type`` and ``Length``.
FLAGS_OFFSET = 40 + 4


class TestHIPReservedBits(unittest.TestCase):
    """Pin the reserved bits of ``Version`` and route ``Flags`` across rebuilds."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _route_codes(self):  # type: ignore[no-untyped-def]
        from pcapkit.const.hip.parameter import Parameter

        return (Parameter.ROUTE_DST, Parameter.ROUTE_VIA)

    def _frame(self, code=None, *, ver=None, flags=None):  # type: ignore[no-untyped-def]
        """Build a HIP packet, then overwrite its ``Version`` or route ``Flags``."""
        from pcapkit.protocols.internet.hip import HIP

        params = None if code is None else [(code, {'hit': ['2001:db8::1']})]
        octets = bytearray(HIP(parameters=params, extension=True, **HIP_BASE).data)
        if ver is not None:
            self.assertEqual(octets[VER_OFFSET], 0x21)
            octets[VER_OFFSET] = ver
        if flags is not None:
            self.assertEqual(octets[FLAGS_OFFSET:FLAGS_OFFSET + 2], b'\x00\x00')
            octets[FLAGS_OFFSET:FLAGS_OFFSET + 2] = flags.to_bytes(2, 'big')
        return bytes(octets)

    def test_from_data_rebuilds_version_reserved(self) -> None:
        from pcapkit.protocols.internet.hip import HIP

        for ver in (0x21, 0x23, 0x2f, 0x2b, 0xff):
            with self.subTest(ver=hex(ver)):
                frame = self._frame(ver=ver)
                parsed = HIP(frame, len(frame), extension=True)
                self.assertEqual(parsed.info.version, ver >> 4)
                self.assertEqual(parsed.info.reserved, (ver >> 1) & 0b111)
                self.assertEqual(HIP.from_data(parsed.info).data, frame)

    def test_make_writes_version_reserved(self) -> None:
        from pcapkit.protocols.internet.hip import HIP

        built = HIP(version_reserved=0b101, extension=True, **HIP_BASE).data
        self.assertEqual(built[VER_OFFSET], 0x2b)
        parsed = HIP(built, len(built), extension=True)
        self.assertEqual(parsed.info.reserved, 0b101)
        self.assertEqual(HIP.from_data(parsed.info).data, built)

        default = HIP(extension=True, **HIP_BASE).data
        self.assertEqual(default[VER_OFFSET], 0x21)

    def test_from_data_rebuilds_route_flags_reserved(self) -> None:
        from pcapkit.protocols.internet.hip import HIP

        for code in self._route_codes():
            for flags in (0x0000, 0x3fff, 0x8001, 0x4000, 0xffff, 0x2aaa):
                with self.subTest(code=code.name, flags=hex(flags)):
                    frame = self._frame(code, flags=flags)
                    parsed = HIP(frame, len(frame), extension=True)
                    data = parsed.info.parameters[code].flags
                    self.assertEqual(data.symmetric, bool(flags & 0x8000))
                    self.assertEqual(data.must_follow, bool(flags & 0x4000))
                    self.assertEqual(data.reserved, flags & 0x3fff)
                    self.assertEqual(HIP.from_data(parsed.info).data, frame)

    def test_make_writes_route_flags_reserved(self) -> None:
        from pcapkit.protocols.internet.hip import HIP

        for code in self._route_codes():
            with self.subTest(code=code.name):
                built = HIP(parameters=[(code, {
                    'symmetric': True, 'flags_reserved': 0x1234, 'hit': ['2001:db8::1'],
                })], extension=True, **HIP_BASE).data
                self.assertEqual(built[FLAGS_OFFSET:FLAGS_OFFSET + 2], b'\x92\x34')
                parsed = HIP(built, len(built), extension=True)
                self.assertEqual(parsed.info.parameters[code].flags.reserved, 0x1234)
                self.assertEqual(HIP.from_data(parsed.info).data, built)

                default = HIP(parameters=[(code, {'hit': ['2001:db8::1']})],
                              extension=True, **HIP_BASE).data
                self.assertEqual(default[FLAGS_OFFSET:FLAGS_OFFSET + 2], b'\x00\x00')


if __name__ == '__main__':
    unittest.main()
