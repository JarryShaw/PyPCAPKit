# -*- coding: utf-8 -*-
"""A DCCP option given as empty raw octets is refused.

GitHub issue #2723: ``_make_dccp_options`` appends a raw-octets option as it
is, and reads no type octet off it, so ``[b'']`` added no octets and built the
header an empty option list builds: the item was dropped. Empty octets raise
``ProtocolError``, as the other malformed items in that branch do, wherever in
the list they sit.

A raw option that holds its type octet builds as given, which the cases below
pin against :rfc:`4340`: the one-octet Slow Receiver option of
:rfc:`4340#section-11.6` follows the 20 octets of a DCCP-Request with 48-bit
sequence numbers, padded with Padding options to a 32-bit boundary, and Data
Offset counts it (:rfc:`4340#section-5.1`).

Every case builds its own octets in memory and reads no capture. :class:`DCCP`
is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""
# Deferring these is the design: each build runs after the per-class re-import.
# pylint: disable=import-outside-toplevel
from __future__ import annotations

import unittest

from tests._support import reimport_once_per_class

#: A Slow Receiver option.
SLOW_RECEIVER = b'\x02'


class TestDCCPEmptyRawOption(unittest.TestCase):
    """Empty raw octets raise ``ProtocolError``; a whole raw option builds."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_empty_octets_are_refused(self) -> None:
        from pcapkit.protocols.transport.dccp import DCCP
        from pcapkit.utilities.exceptions import ProtocolError

        for options in ([b''], [SLOW_RECEIVER, b''], [b'', SLOW_RECEIVER]):
            with self.subTest(options=options):
                with self.assertRaisesRegex(ProtocolError, r"invalid option: b'' holds no type octet"):
                    DCCP(options=options)

    def test_raw_option_builds_as_given(self) -> None:
        from pcapkit.protocols.transport.dccp import DCCP

        built = DCCP(options=[SLOW_RECEIVER]).data
        self.assertEqual(built[4], 6)  # Data Offset: the 20-octet header and one word of options
        self.assertEqual(built[20:], SLOW_RECEIVER + b'\x00\x00\x00')


if __name__ == '__main__':
    unittest.main()
