# -*- coding: utf-8 -*-
"""The value helpers ``Protocol`` shares with its subclasses (GitHub issue #2514).

The TLS extension parser on PR #2595 brought module-level vector and integer-list
helpers, and the owner asked there for them to live on the base ``Protocol``
instead, so that any protocol can use them; PR #2607's 802.11 header brought the
``_make_uint`` check, and the owner asked for the same there. Each helper is
checked here on its own, apart from TLS:

* ``_read_vector`` and ``_read_whole_vector`` -- a length-prefixed vector, with
  prefix widths of one, two and three octets, refusing a truncated prefix, a
  length past the end of the buffer and, for the whole-buffer form, trailing
  octets;
* ``_read_uints`` -- a run of fixed-width unsigned integers, refusing a buffer
  that is not a whole number of them;
* ``_make_vector`` and ``_make_uints`` -- their inverses, refusing what does not
  fit the width;
* ``_make_uint`` -- the check that a value given for a field fits its width.

The errors the readers and ``_make_uint`` raise name the instance's ``alias``,
which is per instance -- a TLS record's is its tier, such as ``TLS 1.3`` -- so
that is pinned with an alias that differs from the class name.

"""

from __future__ import annotations

import enum
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Callable

    from pcapkit.protocols.misc.raw import Raw

#: Test tier (#1958): the per-helper cases of the protocol base, beside the
#: ``ALL``-tier smoke slice in ``test_protocol_base_unit``.
__tier__ = 'LATEST'

#: An alias that is not the class name, to tell ``self.alias`` from ``cls.__name__``.
ALIAS = 'Sample 1.0'


class _HelperTestCase(unittest.TestCase):
    """A fresh :mod:`pcapkit` per class, and a protocol instance to call the helpers on."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.protocols.misc.raw import Raw

        self.proto = Raw(b'')  # type: Raw

    def assertRefused(self, pattern: 'str', func: 'Callable[..., object]', *args: 'object',
                      **kwargs: 'object') -> None:
        """``func`` raises :exc:`ProtocolError` naming :data:`ALIAS` and matching ``pattern``."""
        from pcapkit.utilities.exceptions import ProtocolError

        with mock.patch.object(type(self.proto), 'alias', new_callable=mock.PropertyMock, return_value=ALIAS):
            with self.assertRaisesRegex(ProtocolError, f'^{ALIAS}: {pattern}'):
                func(*args, **kwargs)


class ReadVectorTests(_HelperTestCase):
    """``_read_vector`` returns the vector's octets and the offset just past them."""

    def test_each_prefix_width(self) -> None:
        for size, prefix in ((1, b'\x03'), (2, b'\x00\x03'), (3, b'\x00\x00\x03')):
            with self.subTest(size=size):
                data = b'\xee' + prefix + b'abc' + b'\xff'
                self.assertEqual(self.proto._read_vector(data, 1, size=size, what='v'), (b'abc', 1 + size + 3))

    def test_an_empty_vector_and_the_default_offset(self) -> None:
        self.assertEqual(self.proto._read_vector(b'\x00rest', what='v'), (b'', 1))

    def test_a_truncated_prefix_is_refused(self) -> None:
        for size in (1, 2, 3):
            with self.subTest(size=size):
                self.assertRefused('invalid format: v length runs past the end of the buffer',
                                   self.proto._read_vector, b'\x00' * size, 1, size=size, what='v')

    def test_a_length_past_the_end_is_refused(self) -> None:
        for size, prefix in ((1, b'\x04'), (2, b'\x00\x04'), (3, b'\x00\x00\x04')):
            with self.subTest(size=size):
                self.assertRefused('invalid format: v runs past the end of the buffer',
                                   self.proto._read_vector, prefix + b'abc', size=size, what='v')


class ReadWholeVectorTests(_HelperTestCase):
    """``_read_whole_vector`` reads the one vector a buffer holds, and nothing after it."""

    def test_each_prefix_width(self) -> None:
        for size, prefix in ((1, b'\x02'), (2, b'\x00\x02'), (3, b'\x00\x00\x02')):
            with self.subTest(size=size):
                self.assertEqual(self.proto._read_whole_vector(prefix + b'ab', size=size, what='v'), b'ab')

    def test_a_truncated_prefix_is_refused(self) -> None:
        for size in (2, 3):
            with self.subTest(size=size):
                self.assertRefused('invalid format: v length runs past the end of the buffer',
                                   self.proto._read_whole_vector, b'\x00' * (size - 1), size=size, what='v')

    def test_a_length_past_the_end_is_refused(self) -> None:
        for size, prefix in ((1, b'\x03'), (2, b'\x00\x03'), (3, b'\x00\x00\x03')):
            with self.subTest(size=size):
                self.assertRefused('invalid format: v runs past the end of the buffer',
                                   self.proto._read_whole_vector, prefix + b'ab', size=size, what='v')

    def test_trailing_octets_are_refused(self) -> None:
        for size, prefix in ((1, b'\x01'), (2, b'\x00\x01'), (3, b'\x00\x00\x01')):
            with self.subTest(size=size):
                self.assertRefused('invalid format: v carries excess octets',
                                   self.proto._read_whole_vector, prefix + b'ab', size=size, what='v')


class ReadUintsTests(_HelperTestCase):
    """``_read_uints`` reads a buffer as big-endian unsigned integers of one width."""

    def test_each_width(self) -> None:
        data = bytes(range(1, 7))
        for size, expected in ((1, (1, 2, 3, 4, 5, 6)), (2, (0x0102, 0x0304, 0x0506)),
                               (3, (0x010203, 0x040506))):
            with self.subTest(size=size):
                self.assertEqual(self.proto._read_uints(data, size=size, what='list'), expected)

    def test_an_empty_list(self) -> None:
        self.assertEqual(self.proto._read_uints(b'', size=2, what='list'), ())

    def test_a_length_that_is_not_a_whole_number_of_integers_is_refused(self) -> None:
        for size, data in ((2, b'\x00\x01\x02'), (3, b'\x00\x01\x02\x03')):
            with self.subTest(size=size):
                self.assertRefused(f'invalid format: list length {len(data)} is not a multiple of {size}$',
                                   self.proto._read_uints, data, size=size, what='list')


class MakeVectorTests(_HelperTestCase):
    """``_make_vector`` writes the prefix ``_read_vector`` reads."""

    def test_each_prefix_width(self) -> None:
        for size, prefix in ((1, b'\x03'), (2, b'\x00\x03'), (3, b'\x00\x00\x03')):
            with self.subTest(size=size):
                made = type(self.proto)._make_vector(b'abc', size=size)
                self.assertEqual(made, prefix + b'abc')
                self.assertEqual(self.proto._read_whole_vector(made, size=size, what='v'), b'abc')

    def test_a_vector_too_long_for_its_prefix_is_refused(self) -> None:
        from pcapkit.utilities.exceptions import StructError

        with self.assertRaisesRegex(StructError, '^Raw: pack failed$'):
            type(self.proto)._make_vector(bytes(256), size=1)


class MakeUintsTests(_HelperTestCase):
    """``_make_uints`` writes the integers ``_read_uints`` reads."""

    def test_each_width(self) -> None:
        class Code(enum.IntEnum):
            five = 5

        for size, expected in ((1, b'\x01\x05'), (2, b'\x00\x01\x00\x05'), (3, b'\x00\x00\x01\x00\x00\x05')):
            with self.subTest(size=size):
                made = type(self.proto)._make_uints((1, Code.five), size=size)
                self.assertEqual(made, expected)
                self.assertEqual(self.proto._read_uints(made, size=size, what='list'), (1, 5))

    def test_a_value_outside_the_width_is_refused(self) -> None:
        from pcapkit.utilities.exceptions import StructError

        for size, value in ((1, 256), (2, 0x10000), (3, 0x1000000), (2, -1)):
            with self.subTest(size=size, value=value), self.assertRaises(StructError):
                type(self.proto)._make_uints((value,), size=size)


class MakeUintTests(_HelperTestCase):
    """``_make_uint`` passes a value that fits its field, as a plain :class:`int`."""

    def test_a_value_that_fits_is_returned_as_an_int(self) -> None:
        for bits, value in ((1, 1), (2, 3), (4, 0), (16, 0xFFFF)):
            with self.subTest(bits=bits, value=value):
                self.assertEqual(self.proto._make_uint(value, bits=bits, name='field'), value)

    def test_a_bool_is_accepted_for_a_one_bit_field(self) -> None:
        for flag in (False, True):
            with self.subTest(flag=flag):
                made = self.proto._make_uint(flag, bits=1, name='flag')
                self.assertEqual(made, int(flag))
                self.assertIs(type(made), int)

    def test_a_bool_is_refused_for_a_wider_field(self) -> None:
        for bits in (2, 8):
            with self.subTest(bits=bits):
                self.assertRefused(r'invalid field: True$', self.proto._make_uint, True, bits=bits, name='field')

    def test_a_negative_value_is_refused(self) -> None:
        self.assertRefused(r'invalid field: -1$', self.proto._make_uint, -1, bits=4, name='field')

    def test_a_value_one_past_the_width_is_refused(self) -> None:
        for bits in (1, 4, 16):
            with self.subTest(bits=bits):
                self.assertRefused(rf'invalid field: {2 ** bits}$',
                                   self.proto._make_uint, 2 ** bits, bits=bits, name='field')

    def test_a_non_int_is_refused(self) -> None:
        for value, shown in (('1', "'1'"), (1.0, r'1\.0'), (None, 'None')):
            with self.subTest(value=value):
                self.assertRefused(f'invalid field: {shown}$', self.proto._make_uint, value, bits=4, name='field')


if __name__ == '__main__':
    unittest.main()
