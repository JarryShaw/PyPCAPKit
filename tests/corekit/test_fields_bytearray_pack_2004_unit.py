# -*- coding: utf-8 -*-
"""A :obj:`bytearray` packs into an ``s`` or ``p`` field on every interpreter.

GitHub issue #2004. CPython's :func:`struct.pack` takes a :obj:`bytearray` for
the ``s`` and ``p`` formats, but PyPy's takes :obj:`bytes` alone and raises
``TypeError: expected bytes, got bytearray object``, so a :obj:`bytearray` value
packed by :meth:`Field.pack <pcapkit.corekit.fields.field.Field.pack>` failed on
PyPy. The field now hands :func:`struct.pack` a :obj:`bytes` copy.

The PyPy behaviour is reproduced on any interpreter with a :mod:`struct`
stand-in that refuses a :obj:`bytearray`, as PyPy's does. The real
:func:`struct.pack` then pins that the output is unchanged and that a value
refused before -- a :obj:`memoryview`, a :obj:`bool`, a :obj:`str` -- still is.

"""

import struct
import unittest
from unittest import mock

from tests._support import reimport_once_per_class

#: Test tier (#1958): exercises integer, bytes and struct edge cases, whose limits
#: differ by interpreter.
__tier__ = 'ALL'

#: The octets every case packs.
OCTETS = b'\xaa\xbb\xcc\xdd'


class _ByteArray(bytearray):
    """A :obj:`bytearray` subclass, which PyPy's :func:`struct.pack` refuses as well."""


class _PyPyStruct:
    """A :mod:`struct` whose :func:`pack` refuses a :obj:`bytearray`, as PyPy's does.

    Everything else is the real :mod:`struct`, and every value :func:`pack` is
    handed is recorded in :attr:`packed`.

    """

    def __init__(self) -> None:
        self.packed = []  # type: list[object]

    def __getattr__(self, name: str) -> object:
        return getattr(struct, name)

    def pack(self, fmt: str, *values: object) -> bytes:
        self.packed.extend(values)
        for value in values:
            if isinstance(value, bytearray):
                raise TypeError(f'expected bytes, got {type(value).__name__} object')
        return struct.pack(fmt, *values)


class TestBytearrayPack(unittest.TestCase):
    """Pin how :meth:`Field.pack` hands a :obj:`bytearray` to :func:`struct.pack`."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _fields(self) -> 'dict[str, object]':
        from pcapkit.corekit.fields.strings import BytesField

        # A ``p`` template has no field class of its own, so a fixed-width bytes
        # field is given one; it packs through the same Field.pack path.
        pascal = BytesField(length=len(OCTETS) + 1)
        pascal._template = f'{len(OCTETS) + 1}p'
        return {
            'fixed s': BytesField(length=len(OCTETS)),
            'callable s': BytesField(length=lambda _: len(OCTETS))({}),
            'negative s': BytesField(length=-1),
            'p': pascal,
        }

    def test_bytearray_packs_under_a_struct_that_refuses_it(self) -> None:
        for label, field in self._fields().items():
            for value in (bytearray(OCTETS), _ByteArray(OCTETS)):
                with self.subTest(field=label, value=type(value).__name__):
                    stand_in = _PyPyStruct()
                    with mock.patch('pcapkit.corekit.fields.field.struct', stand_in):
                        packed = field.pack(value, {})  # type: ignore[attr-defined]
                    self.assertEqual(packed, struct.pack(field.template, OCTETS))  # type: ignore[attr-defined]
                    self.assertEqual([type(item) for item in stand_in.packed], [bytes])

    def test_bytearray_output_matches_bytes(self) -> None:
        for label, field in self._fields().items():
            with self.subTest(field=label):
                self.assertEqual(field.pack(bytearray(OCTETS), {}),  # type: ignore[attr-defined]
                                 field.pack(OCTETS, {}))  # type: ignore[attr-defined]

    def test_refused_values_stay_refused(self) -> None:
        # CPython raises struct.error for these and PyPy TypeError; neither may
        # start packing because a bytearray now does.
        for label, field in self._fields().items():
            for value in (memoryview(OCTETS), True, OCTETS.decode('latin-1'), list(OCTETS)):
                with self.subTest(field=label, value=type(value).__name__):
                    with self.assertRaises((struct.error, TypeError)):
                        field.pack(value, {})  # type: ignore[attr-defined]

    def test_bytearray_for_the_c_format_stays_refused(self) -> None:
        # CPython's ``c`` format refuses a bytearray as well, so converting one
        # there would accept what no interpreter accepted before.
        from pcapkit.corekit.fields.strings import BytesField

        char = BytesField(length=1)
        char._template = 'c'
        self.assertEqual(char.pack(b'a', {}), b'a')
        with self.assertRaises((struct.error, TypeError)):
            char.pack(bytearray(b'a'), {})


if __name__ == '__main__':
    unittest.main()
