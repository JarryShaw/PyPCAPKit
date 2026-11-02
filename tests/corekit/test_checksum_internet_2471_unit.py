# -*- coding: utf-8 -*-
"""The one's-complement Internet checksum the IP family's checksums share.

GitHub issue #2471 settled the policy: verification is opt-in and computation
opt-out, each a ``PCAPKIT_*`` flag; a wrong checksum warns rather than raises;
and the outcome is recorded as a
:class:`~pcapkit.corekit.checksum.internet.ChecksumStatus`. These tests pin
:mod:`pcapkit.corekit.checksum.internet` against :rfc:`1071`, cross-checked
with the hand-written sum of ``tests/foundation/_roundtrip.py``.

"""
from __future__ import annotations

import enum
import random
import unittest
import warnings

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

#: Test tier (#1958): exercises bytes and struct edge cases, odd lengths and folding.
__tier__ = 'ALL'


class InternetChecksumTests(unittest.TestCase):
    """:func:`internet_checksum` and :func:`compute_checksum`."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.corekit.checksum import internet as checksum

        self.checksum = checksum

    def test_rfc_1071_example(self) -> None:
        # RFC 1071 section 3: the words sum to 0xddf2.
        self.assertEqual(self.checksum.internet_checksum(bytes.fromhex('0001f203f4f5f6f7')), ~0xDDF2 & 0xFFFF)

    def test_odd_length_is_padded(self) -> None:
        self.assertEqual(self.checksum.internet_checksum(b'\x01'), ~0x0100 & 0xFFFF)
        self.assertEqual(self.checksum.internet_checksum(b''), 0xFFFF)

    def test_agrees_with_an_independent_sum(self) -> None:
        rng = random.Random(2471)
        for size in (1, 2, 3, 20, 41, 1500, 65535):
            data = bytes(rng.randrange(256) for _ in range(size))
            with self.subTest(size=size):
                self.assertEqual(self.checksum.internet_checksum(data), wire.checksum(data))
                self.assertEqual(self.checksum.compute_checksum(data[2:], prefix=data[:2]),
                                 wire.checksum(data).to_bytes(2, 'big'))

    def test_a_computed_zero(self) -> None:
        self.assertEqual(self.checksum.compute_checksum(b'\xff\xff'), b'\x00\x00')
        self.assertEqual(self.checksum.compute_checksum(b'\xff\xff', nonzero=True), b'\xff\xff')

    def test_the_partial_checksum_is_the_uncomplemented_sum(self) -> None:
        prefix = bytes.fromhex('c0000201' 'c6336402' '00' '06' '0014')
        self.assertEqual(self.checksum.partial_checksum(prefix), (~wire.checksum(prefix) & 0xFFFF).to_bytes(2, 'big'))


class VerifyChecksumTests(unittest.TestCase):
    """:func:`verify_checksum` returns each :class:`ChecksumStatus` it can."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.corekit.checksum import internet as checksum
        from pcapkit.utilities.warnings import ChecksumWarning, ProtocolWarning

        self.checksum = checksum
        self.Status = checksum.ChecksumStatus
        self.ProtocolWarning = ProtocolWarning
        self.ChecksumWarning = ChecksumWarning
        body = b'\x45\x00\x00\x1c\x12\x34\x00\x00\x40\x11\x00\x00\xc0\x00\x02\x01\xc6\x33\x64\x02'
        self.field = wire.checksum(body).to_bytes(2, 'big')
        self.data = body[:10] + self.field + body[12:]

    def verify(self, data: bytes, field: bytes, **kwargs: object) -> 'tuple[object, list[tuple[type, str]]]':
        """The status of ``data``, and its ProtocolWarnings as ``(category, message)``."""
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            status = self.checksum.verify_checksum('TEST', data, field, **kwargs)
        return status, [(item.category, str(item.message))
                        for item in caught if issubclass(item.category, self.ProtocolWarning)]

    def corrupt(self, field: bytes) -> bytes:
        """``self.data`` with ``field`` in place of its checksum."""
        return self.data[:10] + field + self.data[12:]

    def test_valid(self) -> None:
        self.assertEqual(self.verify(self.data, self.field), (self.Status.VALID, []))

    def test_invalid_warns_with_the_expected_value(self) -> None:
        status, messages = self.verify(self.corrupt(b'\xbe\xef'), b'\xbe\xef')
        self.assertIs(status, self.Status.INVALID)
        self.assertEqual(messages, [(self.ChecksumWarning,
                                     f'TEST: checksum 0xbeef is wrong; 0x{self.field.hex()} expected')])

    def test_both_zeros_verify(self) -> None:
        # RFC 1071: a receiver sums the field in, so 0x0000 and 0xffff are both zero.
        data = b'\xff\xff\x00\x00'
        self.assertEqual(self.verify(data, b'\x00\x00'), (self.Status.VALID, []))
        self.assertEqual(self.verify(b'\xff\xff\xff\xff', b'\xff\xff'), (self.Status.VALID, []))

    def test_truncated(self) -> None:
        self.assertEqual(self.verify(self.data, self.field, length=len(self.data) + 1),
                         (self.Status.TRUNCATED, []))
        self.assertEqual(self.verify(self.data + b'junk', self.field, length=len(self.data)),
                         (self.Status.VALID, []))

    def test_absent_is_checked_first(self) -> None:
        data = self.corrupt(b'\x00\x00')
        self.assertEqual(self.verify(data, b'\x00\x00', absent=b'\x00\x00'), (self.Status.NOT_COMPUTED, []))

    def test_offload_only_once_wrong(self) -> None:
        self.assertEqual(self.verify(self.corrupt(b'\x12\x34'), b'\x12\x34', offload=(b'\x12\x34',)),
                         (self.Status.NOT_COMPUTED, []))
        self.assertEqual(self.verify(self.data, self.field, offload=(self.field,)), (self.Status.VALID, []))

    def test_the_status_is_shaped_like_esp_status(self) -> None:
        from pcapkit.corekit.enum import EnumLookup

        self.assertEqual(self.Status.__bases__, (EnumLookup, enum.IntEnum))
        self.assertEqual([member.name for member in self.Status],
                         ['VALID', 'INVALID', 'NOT_COMPUTED', 'TRUNCATED', 'NO_PSEUDO_HEADER'])
        self.assertIs(self.Status.get('NOT_COMPUTED'), self.Status.NOT_COMPUTED)


if __name__ == '__main__':
    unittest.main()
