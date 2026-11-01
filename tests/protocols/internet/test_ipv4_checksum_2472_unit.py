# -*- coding: utf-8 -*-
"""IPv4 verifies and computes its header checksum.

GitHub issue #2472: :meth:`IPv4.read <pcapkit.protocols.internet.ipv4.IPv4.read>`
verifies the header checksum (:rfc:`791#section-3.1`) under
:data:`~pcapkit.utilities.config.CHECKSUM_VERIFY`, and :meth:`IPv4.make
<pcapkit.protocols.internet.ipv4.IPv4.make>` computes one it is not given under
:data:`~pcapkit.utilities.config.CHECKSUM_COMPUTE`. The captured headers are from
the tracked :file:`examples/captures/in.pcap` and :file:`examples/captures/dhcp.pcapng`.

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

#: IPv4 headers as captured: TCP from a remote host (``in.pcap`` frame 2) and a
#: DHCP Discover (``dhcp.pcapng`` frame 0), each with the sender's checksum.
CAPTURED = (
    bytes.fromhex('45000028c53440002b067a867b81d287c0a80164'),
    bytes.fromhex('4500012ca8360000fa11178b00000000ffffffff'),
)

HAS_SCAPY = importlib.util.find_spec('scapy') is not None


def with_checksum(header: bytes, field: bytes) -> bytes:
    """``header`` with ``field`` as its checksum."""
    return header[:10] + field + header[12:]


class IPv4ChecksumTests(unittest.TestCase):
    """Reading and making the IPv4 header checksum."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.misc.checksum.checksum import ChecksumStatus
        from pcapkit.utilities import config
        from pcapkit.utilities.warnings import ProtocolWarning

        self.IPv4 = IPv4
        self.Status = ChecksumStatus
        self.config = config
        self.ProtocolWarning = ProtocolWarning

    def parse(self, octets: bytes, *, verify: bool = True) -> 'tuple[object, list[str]]':
        """The IPv4 layer parsed from ``octets``, and the ProtocolWarnings it gave."""
        with mock.patch.object(self.config, 'CHECKSUM_VERIFY', verify), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            ipv4 = self.IPv4(octets)
        return ipv4, [str(item.message) for item in caught if issubclass(item.category, self.ProtocolWarning)]

    def test_captured_checksums_verify(self) -> None:
        for header in CAPTURED:
            with self.subTest(header=header.hex()):
                ipv4, messages = self.parse(header)
                self.assertIs(ipv4.info.checksum_status, self.Status.VALID)
                self.assertEqual(messages, [])

    def test_a_corrupted_checksum_warns(self) -> None:
        header = with_checksum(CAPTURED[0], b'\x7a\x87')
        ipv4, messages = self.parse(header)
        self.assertIs(ipv4.info.checksum_status, self.Status.INVALID)
        self.assertEqual(messages, ['IPv4: checksum 0x7a87 is wrong; 0x7a86 expected'])

    def test_a_zero_checksum_is_offload(self) -> None:
        ipv4, messages = self.parse(with_checksum(CAPTURED[0], b'\x00\x00'))
        self.assertIs(ipv4.info.checksum_status, self.Status.NOT_COMPUTED)
        self.assertEqual(messages, [])

    def test_off_verifies_nothing(self) -> None:
        ipv4, messages = self.parse(with_checksum(CAPTURED[0], b'\x7a\x87'), verify=False)
        self.assertNotIn('checksum_status', ipv4.info)
        self.assertEqual(messages, [])

    def test_a_rebuilt_frame_warns_once(self) -> None:
        from pcapkit.protocols.link.ethernet import Ethernet

        frame = wire.ethernet(with_checksum(CAPTURED[0], b'\x7a\x87'), 0x0800)
        with mock.patch.object(self.config, 'CHECKSUM_VERIFY', True), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            rebuilt = Ethernet.from_data(Ethernet(frame).info)
        self.assertEqual(rebuilt.data, frame)
        self.assertEqual([str(item.message) for item in caught if issubclass(item.category, self.ProtocolWarning)],
                         ['IPv4: checksum 0x7a87 is wrong; 0x7a86 expected'] * 2)

    def test_parse_rebuild_is_exact(self) -> None:
        for header in (*CAPTURED, with_checksum(CAPTURED[0], b'\x7a\x87'), with_checksum(CAPTURED[0], b'\x00\x00')):
            for verify in (True, False):
                with self.subTest(header=header.hex(), verify=verify):
                    ipv4, _ = self.parse(header, verify=verify)
                    self.assertEqual(self.IPv4.from_data(ipv4.info).data, header)

    def make(self, compute: bool = True, **kwargs: object) -> bytes:
        """The octets of an IPv4 header made with ``kwargs``."""
        with mock.patch.object(self.config, 'CHECKSUM_COMPUTE', compute):
            return self.IPv4(src='192.0.2.1', dst='198.51.100.2', ttl=64, id=0x1234,
                             protocol='UDP', **kwargs).data

    def test_make_computes_the_checksum(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber

        for options in (None, [(OptionNumber.RR, {'counts': 2, 'route': ['203.0.113.9']})]):
            with self.subTest(options=options):
                octets = self.make(options=options, payload=b'\x00' * 8)
                header = octets[:(octets[0] & 0x0F) * 4]
                self.assertEqual(header[10:12], wire.checksum(with_checksum(header, b'\x00\x00')).to_bytes(2, 'big'))
                ipv4, messages = self.parse(octets)
                self.assertIs(ipv4.info.checksum_status, self.Status.VALID)
                self.assertEqual(messages, [])
                self.assertEqual(self.IPv4.from_data(ipv4.info).data, octets)

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_make_agrees_with_scapy(self) -> None:
        from scapy.layers.inet import IP

        octets = self.make(payload=b'\x00' * 8)
        packet = IP(octets)
        del packet.chksum
        self.assertEqual(bytes(packet), octets)

    def test_off_or_given_is_written_as_is(self) -> None:
        self.assertEqual(self.make(compute=False)[10:12], b'\x00\x00')
        self.assertEqual(self.make(checksum=b'\xbe\xef')[10:12], b'\xbe\xef')


if __name__ == '__main__':
    unittest.main()
