# -*- coding: utf-8 -*-
"""HOPOPT and IPv6-Opts read and rebuild the RPL option under type 0x23.

GitHub issue #1196: the ``__option__`` registries of :class:`HOPOPT` and
:class:`IPv6_Opts` mapped only ``RPL_Option_0x63`` to the RPL reader. Type
0x23, the RPL option code assigned by :rfc:`9008`, fell through to
``_read_opt_none``, which read ``schema.data`` off the RPL schema and raised
:exc:`AttributeError`.

Every case builds its own octets in memory and reads no capture. The protocol
classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, as in
:mod:`tests.protocols.link.test_ethernet_mac_roundtrip_unit`.

"""

import unittest

from tests._support import reimport_once_per_class

#: Extension headers carrying one RPL option [:rfc:`6553#section-3`], next
#: header 59: flags ``O``, ``R`` and ``F`` set, RPLInstanceID 0x2A, SenderRank
#: 0x0102. Type 0x63 is already routed to the RPL reader and is the control.
HEADERS = {
    0x23: bytes.fromhex('3b002304e02a0102'),
    0x63: bytes.fromhex('3b006304e02a0102'),
}


def _classes() -> 'dict[str, type]':
    from pcapkit.protocols.internet.hopopt import HOPOPT
    from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
    return {'HOPOPT': HOPOPT, 'IPv6_Opts': IPv6_Opts}


class TestRPLOption(unittest.TestCase):
    """Pin the RPL option for both of its option types."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_rpl_option_is_read_by_the_rpl_reader(self) -> None:
        for name, cls in _classes().items():
            for code, octets in HEADERS.items():
                with self.subTest(proto=name, type=hex(code)):
                    parsed = cls(octets, len(octets), extension=True)
                    opt = list(parsed.info.options.values())[0]
                    self.assertEqual(opt.type, code)
                    self.assertEqual(opt.length, 6)
                    self.assertEqual((opt.flags.down, opt.flags.rank_err, opt.flags.fwd_err),
                                     (True, True, True))
                    self.assertEqual(opt.id, 0x2A)
                    self.assertEqual(opt.rank, 0x0102)

    def test_rpl_option_rebuilds_byte_for_byte(self) -> None:
        for name, cls in _classes().items():
            for code, octets in HEADERS.items():
                with self.subTest(proto=name, type=hex(code)):
                    parsed = cls(octets, len(octets), extension=True)
                    self.assertEqual(cls.from_data(parsed.info).data, octets)

    def test_malformed_rpl_option_raises_protocol_error(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        # Opt Data Len 0, where the RPL option needs 4.
        octets = bytes.fromhex('3b00230001020000')
        for name, cls in _classes().items():
            with self.subTest(proto=name):
                with self.assertRaises(ProtocolError):
                    cls(octets, len(octets), extension=True)


if __name__ == '__main__':
    unittest.main()
