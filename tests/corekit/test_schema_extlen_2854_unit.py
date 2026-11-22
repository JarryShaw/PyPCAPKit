# -*- coding: utf-8 -*-
"""``ext_len_to_octets`` and ``octets_to_ext_len`` convert an 8-octet-unit header length.

GitHub issue #2854 gathered ``(Hdr Ext Len + 1) * 8`` and its inverse, written
out across the IPv6 extension headers, MH, HIP, the jumbogram lookup and IPv6
reassembly, into :mod:`pcapkit.corekit.schema.extlen`.

The expected values never use the helpers' arithmetic: :func:`spec_octets` and
:func:`spec_ext_len` count 8-octet units one at a time, as RFC 6564, section 4
words the field, and the fixed cases are lengths the RFCs give. That every
call site goes through them is
:mod:`tests.project.test_ext_len_arithmetic_2854_unit`'s to check.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load.

"""

import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): pure-Python arithmetic on one-octet field values, which
#: does not differ by interpreter.
__tier__ = 'LATEST'


def spec_octets(ext_len: int) -> int:
    """Octets of a header whose length field is ``ext_len``: the first 8, then one unit per count."""
    octets = 8
    for _ in range(ext_len):
        octets += 8
    return octets


def spec_ext_len(length: int) -> int:
    """Whole 8-octet units in ``length`` octets past the first 8, counted one at a time."""
    units = 0
    while 8 * (units + 2) <= length:
        units += 1
    return units


class ExtLenTests(unittest.TestCase):
    """The two helpers themselves."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

        from pcapkit.corekit.schema.extlen import ext_len_to_octets, octets_to_ext_len

        self.to_octets = ext_len_to_octets
        self.to_ext_len = octets_to_ext_len

    def test_rfc_lengths(self) -> None:
        # RFC 8200, section 4.3: a Hdr Ext Len of 0 is the minimal 8-octet header.
        # RFC 7401, section 5.1: Header Length 4 covers the fixed 40 octets with both HITs.
        # A one-octet field tops out at 255.
        for ext_len, octets in ((0, 8), (1, 16), (4, 40), (255, 2048)):
            with self.subTest(ext_len=ext_len):
                self.assertEqual(self.to_octets(ext_len), octets)
                self.assertEqual(self.to_ext_len(octets), ext_len)

    def test_every_field_value(self) -> None:
        for ext_len in range(256):
            with self.subTest(ext_len=ext_len):
                self.assertEqual(self.to_octets(ext_len), spec_octets(ext_len))
                self.assertEqual(self.to_ext_len(self.to_octets(ext_len)), ext_len)

    def test_inverse_rounds_down(self) -> None:
        for length in range(8, 8 * 33):
            with self.subTest(length=length):
                self.assertEqual(self.to_ext_len(length), spec_ext_len(length))
                self.assertLessEqual(self.to_octets(self.to_ext_len(length)), length)


if __name__ == '__main__':
    unittest.main()
