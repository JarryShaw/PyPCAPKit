# -*- coding: utf-8 -*-
"""A GRE header the data ends inside reads ``TRUNCATED``, not ``INVALID``.

GitHub issue #2689: built directly on octets that end inside its header, a
:class:`~pcapkit.protocols.link.gre.protocol.GRE` layer reads the fields the data never held as
zeros, and verifying that zero-filled checksum would read ``INVALID`` with a
``ChecksumWarning``. The checksum covers the whole message (:rfc:`2784#section-2.5`),
so a header cut anywhere, in the Checksum or after it, leaves part of what it covers
uncaptured, and :meth:`GRE.read <pcapkit.protocols.link.gre.protocol.GRE.read>` reads the
schema's own ``__short_read__`` record as ``TRUNCATED``. A whole header is verified.

The messages are built here; this module is unit-tier and reads no capture file.

"""
from __future__ import annotations

import struct
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): hand-picked parse -> rebuild round trips.
__tier__ = 'ALL'

#: The payload every message carries, of EtherType ``0x88B5``, local experimental,
#: which no layer is registered for.
PAYLOAD = b'twenty-octet-payload'


def gre(flags: int, *, key: 'int | None' = None, sequence: 'int | None' = None,
        bad: bool = False) -> bytes:
    """A GRE message with ``flags``, carrying :data:`PAYLOAD`.

    The checksum is right, or wrong in both octets when ``bad``; there is none
    unless ``flags`` sets ``C``.

    """
    head = struct.pack('>HH', flags, 0x88B5)
    extra = (b'' if key is None else struct.pack('>I', key)) \
        + (b'' if sequence is None else struct.pack('>I', sequence))
    if not flags & 0x8000:
        return head + extra + PAYLOAD
    value = wire.checksum(head + bytes(4) + extra + PAYLOAD) ^ (0x0101 if bad else 0)
    return head + struct.pack('>HH', value, 0) + extra + PAYLOAD


#: The fields of each message with ``C`` set, for :func:`gre`, and its header's length.
CHECKSUMMED = {
    'C': ({'flags': 0x8000}, 8),
    'C, K': ({'flags': 0xA000, 'key': 0x11223344}, 12),
    'C, K, S': ({'flags': 0xB000, 'key': 0x11223344, 'sequence': 7}, 16),
}  # type: dict[str, tuple[dict[str, int], int]]


class GREHeaderCutTests(unittest.TestCase):
    """A GRE header the data ends inside holds no checksum to verify."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.corekit.checksum.internet import ChecksumStatus
        from pcapkit.protocols.link.gre.protocol import GRE
        from pcapkit.utilities import config
        from pcapkit.utilities.warnings import ChecksumWarning

        self.GRE = GRE
        self.Status = ChecksumStatus
        self.config = config
        self.ChecksumWarning = ChecksumWarning

    def read(self, data: bytes) -> 'tuple[Any, list[str]]':
        """``data`` read as GRE with verification on, and the checksum warnings that gave."""
        with mock.patch.object(self.config, 'CHECKSUM_VERIFY', True), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            layer = self.GRE(data, len(data))
        return layer, [str(item.message) for item in caught
                       if issubclass(item.category, self.ChecksumWarning)]

    def test_every_cut_inside_the_header_reads_truncated(self) -> None:
        for name, (fields, header) in CHECKSUMMED.items():
            for bad in (False, True):
                data = gre(**fields, bad=bad)
                # From one octet on, the octets held set ``C``.
                for count in range(1, header):
                    with self.subTest(flags=name, bad=bad, captured=count):
                        layer, caught = self.read(data[:count])
                        self.assertIsNotNone(layer.info.get('__short_read__'))
                        self.assertEqual((layer.info.checksum_status, caught), (self.Status.TRUNCATED, []))

    def test_a_whole_header_is_verified(self) -> None:
        for name, (fields, _) in CHECKSUMMED.items():
            with self.subTest(flags=name):
                msg, bad = gre(**fields), gre(**fields, bad=True)
                layer, caught = self.read(msg)
                self.assertIsNone(layer.info.get('__short_read__'))
                self.assertEqual((layer.info.checksum_status, caught), (self.Status.VALID, []))
                layer, caught = self.read(bad)
                self.assertIs(layer.info.checksum_status, self.Status.INVALID)
                self.assertEqual(caught, [f'GRE: checksum {int.from_bytes(bad[4:6], "big"):#06x} is wrong; '
                                          f'{int.from_bytes(msg[4:6], "big"):#06x} expected'])

    def test_a_cut_header_without_a_checksum_holds_none(self) -> None:
        # With ``C`` clear there is nothing to verify, cut or not.
        msg = gre(0x2000, key=0x11223344)
        for count in range(1, 8):
            with self.subTest(captured=count):
                layer, caught = self.read(msg[:count])
                self.assertEqual((layer.info.checksum_status, caught), (self.Status.NOT_COMPUTED, []))

    def test_parse_rebuild_is_exact(self) -> None:
        for name, (fields, header) in CHECKSUMMED.items():
            msg = gre(**fields)
            for count in range(1, header + 1):
                with self.subTest(flags=name, captured=count):
                    layer, _ = self.read(msg[:count])
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        self.assertEqual(self.GRE.from_data(layer.info).data, msg[:count])


if __name__ == '__main__':
    unittest.main()
