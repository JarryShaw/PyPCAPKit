# -*- coding: utf-8 -*-
"""An IGMP message the data ends inside reads ``TRUNCATED``, not ``INVALID``.

GitHub issue #2689: built directly on octets that end inside it, with no enclosing
length, an IGMPv1, IGMPv2 or IGMPv3 message reads the fields the data never held as
zeros, and verifying that zero-filled checksum would read ``INVALID`` with a
``ChecksumWarning``. Every version's checksum covers the whole message
(:rfc:`2236#section-2.3`, :rfc:`3376#section-4.1.2`), so
:meth:`IGMP._verify_checksum <pcapkit.protocols.internet.igmp.protocol.IGMP._verify_checksum>`
reads the header's own ``__short_read__`` record as ``TRUNCATED``, as GRE does. A
whole message is verified.

The messages are built here; this module is unit-tier and reads no capture file.

"""
from __future__ import annotations

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


def message(head: bytes, rest: bytes) -> bytes:
    """``head`` (type and Max Resp Code), the checksum over the whole message, then ``rest``."""
    return head + wire.checksum(head + b'\x00\x00' + rest).to_bytes(2, 'big') + rest


#: A group record of type MODE_IS_INCLUDE for 239.1.1.1 with one source, 10.0.0.1.
RECORD = bytes.fromhex('01000001ef0101010a000001')

#: Each message: the class it is read as, its octets, and the lengths of the cuts
#: that leave a short read on its header. Shorter than eight octets, an IGMPv2 or
#: IGMPv3 Query is refused by its class, which classifies a Query by its length.
#: Eight octets of the Report are a whole header whose record count no octet
#: backs, which reads short as well (#2711).
MESSAGES = {
    'v1-report': ('IGMPv1', message(b'\x12\x00', bytes([224, 0, 0, 1])), range(1, 8)),
    'v2-report': ('IGMPv2', message(b'\x16\x00', bytes([239, 1, 2, 3])), range(1, 8)),
    'v2-leave': ('IGMPv2', message(b'\x17\x00', bytes([239, 1, 2, 3])), range(1, 8)),
    'v3-report': ('IGMPv3', message(b'\x22\x00', bytes.fromhex('00000001') + RECORD),
                  range(1, 20)),
    # A General Query with QRV 2, QQIC 125 and one source, 10.0.0.1.
    'v3-query': ('IGMPv3', message(b'\x11\x64', bytes(4) + bytes.fromhex('027d00010a000001')),
                 range(12, 16)),
}


def wrong(msg: bytes) -> bytes:
    """``msg`` with its checksum flipped in both octets."""
    return msg[:2] + (int.from_bytes(msg[2:4], 'big') ^ 0x0101).to_bytes(2, 'big') + msg[4:]


class IGMPHeaderCutTests(unittest.TestCase):
    """An IGMP message the data ends inside holds no checksum to verify."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.corekit.checksum.internet import ChecksumStatus
        from pcapkit.protocols.internet.igmpv1.protocol import IGMPv1
        from pcapkit.protocols.internet.igmpv2.protocol import IGMPv2
        from pcapkit.protocols.internet.igmpv3.protocol import IGMPv3
        from pcapkit.utilities import config
        from pcapkit.utilities.warnings import ChecksumWarning

        self.classes = {'IGMPv1': IGMPv1, 'IGMPv2': IGMPv2, 'IGMPv3': IGMPv3}
        self.Status = ChecksumStatus
        self.config = config
        self.ChecksumWarning = ChecksumWarning

    def read(self, name: str, data: bytes) -> 'tuple[Any, list[str]]':
        """``data`` read as class ``name`` with verification on, and the checksum warnings."""
        with mock.patch.object(self.config, 'CHECKSUM_VERIFY', True), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            layer = self.classes[name](data, len(data))
        return layer, [str(item.message) for item in caught
                       if issubclass(item.category, self.ChecksumWarning)]

    def test_every_cut_reads_truncated(self) -> None:
        for label, (name, msg, cuts) in MESSAGES.items():
            for bad in (False, True):
                data = wrong(msg) if bad else msg
                for count in cuts:
                    with self.subTest(message=label, bad=bad, captured=count):
                        layer, caught = self.read(name, data[:count])
                        self.assertIsNotNone(layer.info.get('__short_read__'))
                        self.assertEqual((layer.info.checksum_status, caught), (self.Status.TRUNCATED, []))

    def test_a_whole_message_is_verified(self) -> None:
        for label, (name, msg, _) in MESSAGES.items():
            with self.subTest(message=label):
                layer, caught = self.read(name, msg)
                self.assertIsNone(layer.info.get('__short_read__'))
                self.assertEqual((layer.info.checksum_status, caught), (self.Status.VALID, []))
                layer, caught = self.read(name, wrong(msg))
                self.assertIs(layer.info.checksum_status, self.Status.INVALID)
                self.assertEqual(len(caught), 1)
                self.assertRegex(caught[0], r'^IGMP(v[23])?: checksum 0x[0-9a-f]{4} is wrong;')

    def test_parse_rebuild_is_exact(self) -> None:
        for label, (name, msg, cuts) in MESSAGES.items():
            for count in cuts:
                with self.subTest(message=label, captured=count):
                    layer, _ = self.read(name, msg[:count])
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        self.assertEqual(self.classes[name].from_data(layer.info).data, msg[:count])


if __name__ == '__main__':
    unittest.main()
