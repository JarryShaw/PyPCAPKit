# -*- coding: utf-8 -*-
"""A wrong checksum warns with a category of its own.

GitHub issue #2470 ruled that a checksum mismatch warns with
:exc:`~pcapkit.utilities.warnings.ChecksumWarning`, a
:exc:`~pcapkit.utilities.warnings.ProtocolWarning`, so that a filter can silence
mismatches alone. Each protocol's checksum tests pin that its mismatch warns with
it; these pin the class and what the filters do with it.

"""
from __future__ import annotations

import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire


def chain(count: int) -> bytes:
    """``count`` Destination Options headers, then a TCP segment."""
    return b''.join(bytes([60 if index < count - 1 else 6, 0, 1, 4, 0, 0, 0, 0])
                    for index in range(count)) + wire.tcp(b'x', seq=1)


def with_wrong_checksum(packet: bytes) -> bytes:
    """``packet`` with the low bit of its IPv4 header checksum flipped."""
    return packet[:11] + bytes([packet[11] ^ 1]) + packet[12:]


#: IPv4 with a wrong header checksum, carrying more Destination Options headers
#: than an extension-header limit of 2: a ChecksumWarning and a ProtocolWarning.
PACKET = with_wrong_checksum(wire.ipv4(chain(4), proto=60))


class ChecksumWarningTests(unittest.TestCase):
    """:exc:`ChecksumWarning` under the warning filters."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.utilities import config
        from pcapkit.utilities import warnings as module

        self.IPv4 = IPv4
        self.config = config
        self.module = module
        self.ChecksumWarning = module.ChecksumWarning
        self.ProtocolWarning = module.ProtocolWarning

    def parse(self, *filters: 'tuple[str, type]') -> 'list[tuple[type, str]]':
        """The ProtocolWarnings of :data:`PACKET` under ``filters``, as ``(category, message)``."""
        with mock.patch.object(self.config, 'CHECKSUM_VERIFY', True), \
                mock.patch.object(self.config, 'EXTENSION_HEADER_LIMIT', 2), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            for action, category in filters:
                warnings.filterwarnings(action, category=category)
            self.IPv4(PACKET)
        return [(item.category, str(item.message))
                for item in caught if issubclass(item.category, self.ProtocolWarning)]

    def test_a_protocol_warning(self) -> None:
        self.assertTrue(issubclass(self.ChecksumWarning, self.ProtocolWarning))
        self.assertIn('ChecksumWarning', self.module.__all__)

    def categories(self, *filters: 'tuple[str, type]') -> 'list[str]':
        """The categories :meth:`parse` gives, by name and sorted."""
        return sorted(category.__name__ for category, _ in self.parse(*filters))

    def test_the_packet_gives_both(self) -> None:
        self.assertEqual(self.categories(), ['ChecksumWarning', 'ProtocolWarning'])

    def test_a_protocol_warning_filter_still_catches_a_mismatch(self) -> None:
        self.assertEqual(self.parse(('ignore', self.ProtocolWarning)), [])
        self.assertEqual(self.categories(('ignore', Warning), ('always', self.ProtocolWarning)),
                         ['ChecksumWarning', 'ProtocolWarning'])
        with self.assertRaisesRegex(self.ChecksumWarning, r'^IPv4: checksum 0x\w+ is wrong'):
            self.parse(('error', self.ProtocolWarning))

    def test_ignoring_checksum_warnings_keeps_the_others(self) -> None:
        records = self.parse(('ignore', self.ChecksumWarning))
        self.assertEqual([category for category, _ in records], [self.ProtocolWarning])
        self.assertIn('reached the limit of 2 headers', records[0][1])


if __name__ == '__main__':
    unittest.main()
