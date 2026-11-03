# -*- coding: utf-8 -*-
"""An IPv4, HOPOPT or IPv6-Opts option given as empty raw octets is refused.

GitHub issue #2723: each of ``_make_ipv4_options``, ``_make_hopopt_options``
and ``_make_ipv6_opts`` reads the type octet of a raw-octets option before it
checks that the octets hold one, so ``[b'']`` raised a bare ``IndexError``.
Empty octets raise ``ProtocolError``, as the other malformed items in those
branches do, wherever in the list they sit.

A raw option that holds its type octet builds as given, which the cases
below pin against the specifications: the IPv4 Router Alert option of
:rfc:`2113#section-2.1` after the 20-octet header, with IHL counting it; the
IPv6 Router Alert option of :rfc:`2711#section-2.1` and the Tunnel
Encapsulation Limit option of :rfc:`2473#section-5.1` after the two fixed
octets, padded with a PadN option of :rfc:`8200#section-4.2` to 8 octets.

Every case builds its own octets in memory and reads no capture. The protocol
classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""
# Deferring these is the design: each build runs after the per-class re-import.
# pylint: disable=import-outside-toplevel
from __future__ import annotations

import importlib
import unittest

from tests._support import reimport_once_per_class

#: Module and class name of each protocol whose option maker is covered.
PROTOCOLS = (
    ('pcapkit.protocols.internet.ipv4', 'IPv4'),
    ('pcapkit.protocols.internet.hopopt', 'HOPOPT'),
    ('pcapkit.protocols.internet.ipv6_opts', 'IPv6_Opts'),
)

#: A whole raw option for each protocol: Router Alert for IPv4 and HOPOPT,
#: Tunnel Encapsulation Limit for IPv6-Opts.
RAW = {
    'IPv4': b'\x94\x04\x00\x00',
    'HOPOPT': b'\x05\x02\x00\x00',
    'IPv6_Opts': b'\x04\x01\x05',
}


class TestEmptyRawOption(unittest.TestCase):
    """Empty raw octets raise ``ProtocolError``; a whole raw option builds."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_empty_octets_are_refused(self) -> None:
        """Raw octets with no type octet raise ``ProtocolError``, not ``IndexError``."""
        from pcapkit.utilities.exceptions import ProtocolError

        for module, name in PROTOCOLS:
            protocol = getattr(importlib.import_module(module), name)
            for options in ([b''], [RAW[name], b'']):
                with self.subTest(protocol=name, options=options):
                    with self.assertRaisesRegex(ProtocolError, r"invalid option: b'' holds no type octet"):
                        protocol(options=options)

    def test_ipv4_raw_option_builds_as_given(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4

        built = IPv4(options=[RAW['IPv4']]).data
        self.assertEqual(built[0] & 0x0F, 6)  # IHL: the 20-octet header and the option
        self.assertEqual(built[20:24], RAW['IPv4'])

    def test_ipv6_extension_raw_option_builds_as_given(self) -> None:
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        built = HOPOPT(options=[RAW['HOPOPT']]).data
        self.assertEqual(built[1:], b'\x00' + RAW['HOPOPT'] + b'\x01\x00')

        built = IPv6_Opts(options=[RAW['IPv6_Opts']]).data
        self.assertEqual(built[1:], b'\x00' + RAW['IPv6_Opts'] + b'\x01\x01\x00')


if __name__ == '__main__':
    unittest.main()
