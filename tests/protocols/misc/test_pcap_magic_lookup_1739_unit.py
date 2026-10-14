# -*- coding: utf-8 -*-
"""The PCAP magic number is looked up in its one home as it was compared before. C.f. #1739.

Moving the four magic numbers to
:data:`pcapkit.protocols.schema.misc.pcap.header.MAGIC_NUMBER` turned three
comparisons into lookups, which pins two behaviours the literals had:

* :meth:`Header._make_magic <pcapkit.protocols.misc.pcap.header.Header._make_magic>`
  raises :exc:`KeyError` for a nanosecond flag that is neither, not a
  :exc:`StopIteration` that a generator would turn into :exc:`RuntimeError`;
* :func:`~pcapkit.protocols.schema.misc.pcap.header.magic_number_callback` and
  :meth:`Header.read <pcapkit.protocols.misc.pcap.header.Header.read>` match a
  :obj:`bytearray` magic number, which compared equal to the literals, rather
  than reject it as unhashable.

Every value is built here, so the module is in the unit tier.

"""
from __future__ import annotations

import types
import unittest

#: Each magic number as the octets read, and the byte order and nanosecond flag
#: it declares.
MAGICS = (
    (b'\xa1\xb2\x3c\x4d', 'big', True),
    (b'\xa1\xb2\xc3\xd4', 'big', False),
    (b'\x4d\x3c\xb2\xa1', 'little', True),
    (b'\xd4\xc3\xb2\xa1', 'little', False),
)


def _header() -> 'object':
    """A :class:`~pcapkit.protocols.misc.pcap.header.Header` with no file behind it."""
    from pcapkit.protocols.misc.pcap.header import Header  # pylint: disable=import-outside-toplevel
    return Header.__new__(Header)


class TestMakeMagic(unittest.TestCase):
    """:meth:`Header._make_magic` looks the pair up."""

    def test_each_pair(self) -> 'None':
        for magic, byteorder, nanosecond in MAGICS:
            with self.subTest(byteorder=byteorder, nanosecond=nanosecond):
                self.assertEqual(_header()._make_magic(byteorder, nanosecond=nanosecond),  # type: ignore[attr-defined]
                                 (magic, byteorder == 'little'))

    def test_undeclared_flag_is_a_key_error(self) -> 'None':
        for nanosecond in (None, 2, 'x'):
            with self.subTest(nanosecond=nanosecond):
                with self.assertRaises(KeyError):
                    _header()._make_magic('big', nanosecond=nanosecond)  # type: ignore[attr-defined]

    def test_undeclared_flag_inside_a_generator(self) -> 'None':
        # NOTE: a ``StopIteration`` escaping a generator is re-raised as
        # ``RuntimeError`` (PEP 479); a ``KeyError`` stays itself.
        def magics() -> 'object':
            yield _header()._make_magic('little', nanosecond=None)  # type: ignore[attr-defined]
        with self.assertRaises(KeyError):
            list(magics())  # type: ignore[call-overload]


class TestBytearrayMagic(unittest.TestCase):
    """A :obj:`bytearray` magic number is matched, as it was compared."""

    def test_callback(self) -> 'None':
        from pcapkit.protocols.schema.misc.pcap.header import \
            magic_number_callback  # pylint: disable=import-outside-toplevel
        for magic, byteorder, _ in MAGICS:
            with self.subTest(magic=magic):
                field = types.SimpleNamespace()
                magic_number_callback(field, {'magic_number': bytearray(magic)})  # type: ignore[arg-type]
                self.assertEqual(field._byteorder, byteorder)  # pylint: disable=protected-access

    def test_callback_rejects_others(self) -> 'None':
        from pcapkit.protocols.schema.misc.pcap.header import \
            magic_number_callback  # pylint: disable=import-outside-toplevel
        from pcapkit.utilities.exceptions import ProtocolError  # pylint: disable=import-outside-toplevel
        for magic in (bytearray(b'\x00\x00\x00\x00'), 0xA1B2C3D4, None):
            with self.subTest(magic=magic):
                with self.assertRaises(ProtocolError):
                    magic_number_callback(types.SimpleNamespace(), {'magic_number': magic})  # type: ignore[arg-type]

    def test_read(self) -> 'None':
        for magic, byteorder, nanosecond in MAGICS:
            with self.subTest(magic=magic):
                header = _header()
                header.__header__ = types.SimpleNamespace(  # type: ignore[attr-defined]
                    magic_number=bytearray(magic), version_major=2, version_minor=4,
                    thiszone=0, sigfigs=0, snaplen=0x40000, network=1,
                )
                data = header.read()  # type: ignore[attr-defined]
                self.assertEqual(data.magic_number.byteorder, byteorder)
                self.assertEqual(data.magic_number.nanosecond, nanosecond)
                self.assertEqual(data.magic_number.data, magic)


if __name__ == '__main__':
    unittest.main()
