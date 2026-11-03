# -*- coding: utf-8 -*-
"""A HIP parameter given as empty raw octets is refused.

GitHub issue #2723: ``_make_hip_param`` pads a raw-octets parameter to a
multiple of 8 octets and reads no type off it, so ``[b'']`` padded to nothing
and built the header an empty parameter list builds: the item was dropped.
Empty octets raise ``ProtocolError``, as the other malformed items in that
branch do, wherever in the list they sit.

A raw parameter that holds its type builds as given, which the cases below pin
against :rfc:`7401`: an ``ECHO_REQUEST_SIGNED`` parameter of
:rfc:`7401#section-5.2.20` follows the 40-octet fixed header, padded to 8
octets as :rfc:`7401#section-5.2.1` requires, and Header Length counts it in
8-octet units past the first 8 (:rfc:`7401#section-5.1`).

Every case builds its own octets in memory and reads no capture. :class:`HIP`
is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""
# Deferring these is the design: each build runs after the per-class re-import.
# pylint: disable=import-outside-toplevel
from __future__ import annotations

import unittest

from tests._support import reimport_once_per_class

#: An ECHO_REQUEST_SIGNED parameter, type 897, carrying ``ab`` and no padding.
ECHO_REQUEST_SIGNED = b'\x03\x81\x00\x02ab'


class TestHIPEmptyRawParam(unittest.TestCase):
    """Empty raw octets raise ``ProtocolError``; a whole raw parameter builds."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_empty_octets_are_refused(self) -> None:
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.utilities.exceptions import ProtocolError

        for parameters in ([b''], [ECHO_REQUEST_SIGNED, b''], [b'', ECHO_REQUEST_SIGNED]):
            with self.subTest(parameters=parameters):
                with self.assertRaisesRegex(ProtocolError, r"invalid parameter: b'' holds no type field"):
                    HIP(parameters=parameters)

    def test_raw_parameter_builds_as_given(self) -> None:
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        built = HIP(parameters=[ECHO_REQUEST_SIGNED]).data
        self.assertEqual(built[1], 5)  # Header Length: (40 + 8 - 8) / 8
        self.assertEqual(built[40:], ECHO_REQUEST_SIGNED + b'\x00\x00')
        self.assertIn(Parameter.ECHO_REQUEST_SIGNED, HIP(built).info.parameters)


if __name__ == '__main__':
    unittest.main()
