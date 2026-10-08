# -*- coding: utf-8 -*-
"""Constructing a CALIPSO option validates its data length and its pad.

GitHub issue #1408: ``Opt Data Len`` is one octet, but ``make()`` wrote it
unchecked, so a bitmap plus pad over 255 octets produced a corrupt length
octet. A pad that was not :obj:`bytes`, or a bitmap that was neither
bytes-like nor an iterable of octets, surfaced as a raw :exc:`struct.error`, :exc:`TypeError` or
:exc:`ValueError`. All of these now raise
:exc:`~pcapkit.utilities.exceptions.ProtocolError`. ``make()`` also built an
odd ``Cmpt Length``, which RFC 5570 permits, but the reader rejected it; the
reader now accepts it.

The classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, so that they belong to the
:mod:`pcapkit` import that is live when the test runs.

"""

import importlib
import io
import unittest

from tests._support import reimport_once_per_class

#: The protocol classes sharing the option code, by module and class name.
PROTOCOLS = (
    ('pcapkit.protocols.internet.hopopt', 'HOPOPT'),
    ('pcapkit.protocols.internet.ipv6_opts', 'IPv6_Opts'),
)


class TestCALIPSOMakeValidation(unittest.TestCase):
    """Pin the CALIPSO ``make()`` length and pad checks."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _protocols(self) -> 'list[type]':
        return [getattr(importlib.import_module(mod), name) for mod, name in PROTOCOLS]

    def _make(self, cls: 'type', **fields: 'object') -> 'object':
        from pcapkit.const.ipv6.option import Option

        return cls(next=59, options=[(Option.CALIPSO, dict(domain=1, level=5, **fields))])

    def test_overlong_option_data_raises(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        cases = {
            'pad 248': {'pad': b'\x00' * 248},
            'pad 1000': {'pad': b'\x00' * 1000},
            'bitmap 248': {'bitmap': b'\x00' * 248},
            'bitmap 240 + pad 8': {'bitmap': b'\x00' * 240, 'pad': b'\x00' * 8},
        }
        for cls in self._protocols():
            for label, fields in cases.items():
                with self.subTest(protocol=cls.__name__, case=label):
                    with self.assertRaisesRegex(ProtocolError, 'too long CALIPSO option data'):
                        self._make(cls, **fields)

    def test_largest_option_data_round_trips(self) -> None:
        from pcapkit.const.ipv6.option import Option

        for cls in self._protocols():
            for label, fields in {
                'pad 247': {'pad': b'\xaa' * 247},
                'bitmap 240 + pad 7': {'bitmap': b'\x11' * 240, 'pad': b'\xaa' * 7},
            }.items():
                with self.subTest(protocol=cls.__name__, case=label):
                    made = self._make(cls, **fields)
                    data = made.data  # type: ignore[attr-defined]
                    self.assertEqual(data[2:4], b'\x07\xff')
                    parsed = cls(io.BytesIO(data), len(data), extension=True)
                    self.assertEqual(parsed.info.options[Option.CALIPSO].pad, fields['pad'])  # type: ignore[attr-defined]
                    self.assertEqual(cls.from_data(parsed.info).data, data)

    def test_non_bytes_pad_raises(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        for cls in self._protocols():
            for pad in ('abcd', [0, 0, 0, 0], None, 4):
                with self.subTest(protocol=cls.__name__, pad=pad):
                    with self.assertRaisesRegex(ProtocolError, 'invalid CALIPSO pad type'):
                        self._make(cls, pad=pad)

    def test_bad_bitmap_raises(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        cases = {
            'element over 255': ((256, 0, 0, 0), 'invalid CALIPSO bitmap octet'),
            'negative element': ((-1, 0, 0, 0), 'invalid CALIPSO bitmap octet'),
            'str element': (('a', 0, 0, 0), 'invalid CALIPSO bitmap octet'),
            'bool element': ((True, 0, 0, 0), 'invalid CALIPSO bitmap octet'),
            'str bitmap': ('abcd', 'invalid CALIPSO bitmap type'),
            'int bitmap': (4, 'invalid CALIPSO bitmap type'),
            'bool bitmap': (True, 'invalid CALIPSO bitmap type'),
            'non-iterable bitmap': (4.0, 'invalid CALIPSO bitmap type'),
        }
        for cls in self._protocols():
            for label, (bitmap, message) in cases.items():
                with self.subTest(protocol=cls.__name__, case=label):
                    with self.assertRaisesRegex(ProtocolError, message):
                        self._make(cls, bitmap=bitmap)

    def test_odd_cmpt_length_round_trips(self) -> None:
        # RFC 5570, section 5.2: the bitmap is sized in 32-bit words, so an
        # odd ``Cmpt Length`` (here 1 and 3) is valid and has to re-parse
        from pcapkit.const.ipv6.option import Option

        for cls in self._protocols():
            for words in (1, 3):
                bitmap = bytes(range(1, 4 * words + 1))
                with self.subTest(protocol=cls.__name__, cmpt_len=words):
                    data = self._make(cls, bitmap=bitmap).data  # type: ignore[attr-defined]
                    self.assertEqual(data[4 + 4], words)
                    parsed = cls(io.BytesIO(data), len(data), extension=True)
                    calipso = parsed.info.options[Option.CALIPSO]  # type: ignore[attr-defined]
                    self.assertEqual(calipso.cmpt_len, 4 * words)
                    self.assertEqual(bytes(calipso.cmpt_bitmap), bitmap)
                    self.assertEqual(cls.from_data(parsed.info).data, data)

    def test_bitmap_sequences_match_bytes(self) -> None:
        for cls in self._protocols():
            expected = self._make(cls, bitmap=b'\x01\x02\x03\x04\x05\x06\x07\x08').data  # type: ignore[attr-defined]
            for bitmap in (bytearray(range(1, 9)), memoryview(bytes(range(1, 9))),
                           tuple(range(1, 9)), list(range(1, 9)), range(1, 9),
                           (octet for octet in range(1, 9))):
                with self.subTest(protocol=cls.__name__, bitmap=type(bitmap).__name__):
                    self.assertEqual(self._make(cls, bitmap=bitmap).data, expected)  # type: ignore[attr-defined]
            with self.subTest(protocol=cls.__name__, bitmap='memoryview zeros'):
                self.assertEqual(self._make(cls, bitmap=memoryview(bytes(8))).data,  # type: ignore[attr-defined]
                                 self._make(cls, bitmap=b'\x00' * 8).data)  # type: ignore[attr-defined]

    def test_bytearray_pad_matches_bytes(self) -> None:
        for cls in self._protocols():
            with self.subTest(protocol=cls.__name__):
                self.assertEqual(self._make(cls, pad=bytearray(b'\xaa\xbb\xcc\xdd')).data,  # type: ignore[attr-defined]
                                 self._make(cls, pad=b'\xaa\xbb\xcc\xdd').data)  # type: ignore[attr-defined]


if __name__ == '__main__':
    unittest.main()
