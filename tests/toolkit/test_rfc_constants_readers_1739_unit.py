# -*- coding: utf-8 -*-
"""Toolkit readers of the RFC-fixed constants behave at the constants' edges. C.f. #1739.

The constants moved to their homes in :mod:`pcapkit.protocols`; these pin the
behaviour of the toolkit code that reads them, at exactly the value each one
gives:

* :func:`pcapkit.toolkit.pypcapfile._walk_extension_headers` steps over an AH of
  exactly :data:`~pcapkit.protocols.schema.internet.ah.AH_HEADER_LEN` octets -- one
  carrying no Integrity Check Value -- and rejects a shorter one;
* :class:`pcapkit.toolkit.dpkt.Timestamp` defaults to microseconds and
  :class:`~pcapkit.toolkit.dpkt.DecimalTimestamp` to nanoseconds, the two
  resolutions of
  :data:`~pcapkit.protocols.schema.misc.pcap.header.RESOLUTION`.

Every value is built here and neither PyPCAPFile nor DPKT is imported, so the
module is in the unit tier.

"""
from __future__ import annotations

import decimal
import unittest

#: IP protocol numbers of AH and TCP.
AH, TCP = 51, 6


def _ah(payload_length: 'int', next_header: 'int' = TCP) -> 'bytes':
    """An AH whose Payload Length is ``payload_length``, zero-filled."""
    return bytes([next_header, payload_length]) + bytes((payload_length + 2) * 4 - 2)


class TestWalkAH(unittest.TestCase):
    """An AH is stepped over from :data:`AH_HEADER_LEN` octets up."""

    def test_shortest_ah_is_stepped_over(self) -> 'None':
        from pcapkit.toolkit.pypcapfile import \
            _walk_extension_headers  # pylint: disable=import-outside-toplevel
        segment = b'TCP header octets...'
        ah = _ah(1)
        self.assertEqual(len(ah), 12)
        self.assertEqual(_walk_extension_headers(AH, ah + segment), (TCP, segment, 1))

    def test_longer_ah_is_stepped_over(self) -> 'None':
        from pcapkit.toolkit.pypcapfile import \
            _walk_extension_headers  # pylint: disable=import-outside-toplevel
        segment = b'TCP header octets...'
        self.assertEqual(_walk_extension_headers(AH, _ah(4) + segment), (TCP, segment, 1))

    def test_shorter_ah_is_rejected(self) -> 'None':
        from pcapkit.toolkit.pypcapfile import \
            _walk_extension_headers  # pylint: disable=import-outside-toplevel
        # a Payload Length of 0 declares 8 octets, fewer than the fixed part
        self.assertIsNone(_walk_extension_headers(AH, bytes([TCP, 0]) + bytes(30)))
        # fewer octets than the fixed part at all
        self.assertIsNone(_walk_extension_headers(AH, bytes([TCP, 1]) + bytes(9)))


class TestTimestampDefaults(unittest.TestCase):
    """DPKT timestamps default to the resolution of their type."""

    def test_float_timestamp_is_microseconds(self) -> 'None':
        from pcapkit.toolkit.dpkt import Timestamp  # pylint: disable=import-outside-toplevel
        self.assertEqual(Timestamp(1.5).resolution, 1_000_000)
        self.assertEqual(Timestamp().resolution, 1_000_000)

    def test_decimal_timestamp_is_nanoseconds(self) -> 'None':
        from pcapkit.toolkit.dpkt import DecimalTimestamp  # pylint: disable=import-outside-toplevel
        self.assertEqual(DecimalTimestamp(decimal.Decimal('1.5')).resolution, 1_000_000_000)
        self.assertEqual(DecimalTimestamp().resolution, 1_000_000_000)


if __name__ == '__main__':
    unittest.main()
