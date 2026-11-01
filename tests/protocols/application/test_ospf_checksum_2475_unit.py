# -*- coding: utf-8 -*-
"""OSPFv2 verifies and computes its checksum.

GitHub issue #2475: :meth:`OSPF.read <pcapkit.protocols.application.ospf.OSPF.read>`
verifies the OSPFv2 checksum under :data:`~pcapkit.utilities.config.CHECKSUM_VERIFY`,
and :meth:`OSPF.make <pcapkit.protocols.application.ospf.OSPF.make>` computes one it
is not given under :data:`~pcapkit.utilities.config.CHECKSUM_COMPUTE`. It covers the
packet but its Authentication field, with no pseudo-header
(:rfc:`2328#appendix-A.3.1`), and is unused under cryptographic authentication
(:rfc:`2328#appendix-D.4.3`). The packets were built with ``scapy.contrib.ospf``
2.7.0, and are cross-checked with the hand-written sum of
``tests/foundation/_roundtrip.py``.

"""
from __future__ import annotations

import importlib.util
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

#: Test tier (#1958): hand-picked parse -> rebuild and make -> parse round trips.
__tier__ = 'ALL'

#: An OSPFv2 Hello body: mask, interval, options, priority, dead interval, DR,
#: BDR and one neighbour.
HELLO = bytes.fromhex('ffffff00000a020100000028c000020100000000c0000202')

#: Hello packets as scapy builds them, with null and with simple password
#: authentication; only the AuType differs in what the checksum covers.
BUILT = (
    bytes.fromhex('02010030c000020100000000b69400000000000000000000') + HELLO,
    bytes.fromhex('02010030c000020100000000b69300017365637265742121') + HELLO,
)

HAS_SCAPY = importlib.util.find_spec('scapy') is not None


def expected(packet: bytes) -> bytes:
    """The checksum ``packet`` should carry: over all but the Authentication field."""
    return wire.checksum(packet[:12] + b'\x00\x00' + packet[14:16] + packet[24:]).to_bytes(2, 'big')


def with_checksum(packet: bytes, field: bytes) -> bytes:
    """``packet`` with ``field`` as its checksum."""
    return packet[:12] + field + packet[14:]


class OSPFChecksumTests(unittest.TestCase):
    """Reading and making the OSPFv2 checksum."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.protocols.application.ospf import OSPF
        from pcapkit.protocols.misc.checksum.checksum import ChecksumStatus
        from pcapkit.utilities import config
        from pcapkit.utilities.warnings import ProtocolWarning

        self.OSPF = OSPF
        self.Status = ChecksumStatus
        self.config = config
        self.ProtocolWarning = ProtocolWarning

    def parse(self, octets: bytes, *, verify: bool = True) -> 'tuple[object, list[str]]':
        """The OSPF packet parsed from ``octets``, and the ProtocolWarnings it gave."""
        with mock.patch.object(self.config, 'CHECKSUM_VERIFY', verify), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            ospf = self.OSPF(octets)
        return ospf, [str(item.message) for item in caught if issubclass(item.category, self.ProtocolWarning)]

    def status(self, octets: bytes, **kwargs: object) -> 'tuple[object, list[str]]':
        """The checksum status of ``octets``, and the ProtocolWarnings given."""
        ospf, messages = self.parse(octets, **kwargs)
        return ospf.info.get('checksum_status'), messages

    def test_built_checksums_verify(self) -> None:
        for packet in BUILT:
            with self.subTest(packet=packet.hex()):
                self.assertEqual(expected(packet), packet[12:14])
                self.assertEqual(self.status(packet), (self.Status.VALID, []))

    def test_a_corrupted_checksum_warns(self) -> None:
        status, messages = self.status(with_checksum(BUILT[0], b'\xb6\x95'))
        self.assertIs(status, self.Status.INVALID)
        self.assertEqual(messages, ['OSPFv2: checksum 0xb695 is wrong; 0xb694 expected'])

    def test_cryptographic_authentication_leaves_it_unused(self) -> None:
        packet = BUILT[0][:14] + b'\x00\x02' + bytes([0, 0, 1, 16]) + bytes(4) + HELLO
        self.assertEqual(self.status(packet), (self.Status.NOT_COMPUTED, []))
        made = self.OSPF(type='Hello', router_id='192.0.2.1', auth_type=2,
                         auth_data={'key_id': 1, 'len': 16, 'seq': 0}, payload=HELLO).data
        self.assertEqual(made[12:14], b'\x00\x00')

    def test_truncated_and_other_versions(self) -> None:
        self.assertEqual(self.status(BUILT[0][:-4]), (self.Status.TRUNCATED, []))
        self.assertEqual(self.status(b'\x03' + BUILT[0][1:]), (None, []))
        self.assertEqual(self.OSPF(version=3, payload=HELLO).data[12:14], b'\x00\x00')

    def test_off_verifies_nothing(self) -> None:
        self.assertEqual(self.status(with_checksum(BUILT[0], b'\xb6\x95'), verify=False), (None, []))

    def test_parse_rebuild_is_exact(self) -> None:
        for packet in (*BUILT, with_checksum(BUILT[0], b'\xb6\x95'), BUILT[0][:-4]):
            for verify in (True, False):
                with self.subTest(packet=packet.hex(), verify=verify):
                    ospf, _ = self.parse(packet, verify=verify)
                    self.assertEqual(self.OSPF.from_data(ospf.info).data, packet)

    def test_make_computes_the_checksum(self) -> None:
        for packet, kwargs in zip(BUILT, ({}, {'auth_type': 1, 'auth_data': b'secret!!'})):
            with self.subTest(kwargs=kwargs):
                made = self.OSPF(type='Hello', router_id='192.0.2.1', payload=HELLO, **kwargs).data
                self.assertEqual(made, packet)
                ospf, messages = self.parse(made)
                self.assertEqual((ospf.info.checksum_status, messages), (self.Status.VALID, []))
                self.assertEqual(self.OSPF.from_data(ospf.info).data, made)

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_make_agrees_with_scapy(self) -> None:
        from scapy.contrib.ospf import OSPF_Hdr

        made = self.OSPF(type='Hello', router_id='192.0.2.1', payload=HELLO).data
        packet = OSPF_Hdr(made)
        del packet.chksum
        self.assertEqual(bytes(packet), made)

    def test_off_or_given_is_written_as_is(self) -> None:
        with mock.patch.object(self.config, 'CHECKSUM_COMPUTE', False):
            self.assertEqual(self.OSPF(payload=HELLO).data[12:14], b'\x00\x00')
        self.assertEqual(self.OSPF(checksum=b'\xbe\xef', payload=HELLO).data[12:14], b'\xbe\xef')


if __name__ == '__main__':
    unittest.main()
