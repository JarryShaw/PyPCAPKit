# -*- coding: utf-8 -*-
"""IGMPv1, IGMPv2 and IGMPv3 verify and compute their checksums.

GitHub issue #2618: the checksum of every IGMP version covers the whole message,
the entire IP payload, with no pseudo-header (:rfc:`2236#section-2.3`,
:rfc:`2236#section-2.5`, :rfc:`3376#section-4.1.2`, :rfc:`3376#section-4.2.2`).
:class:`~pcapkit.protocols.internet.igmp.IGMP` verifies it on read for all three
versions under :data:`~pcapkit.utilities.config.CHECKSUM_VERIFY`, as ICMP does, and
``make()`` computes one it is not given under
:data:`~pcapkit.utilities.config.CHECKSUM_COMPUTE`.

No capture under :file:`examples/captures/`, tracked or generated, carries IGMP, so
the messages are built here; their checksums are the hand-written sum of
``tests/foundation/_roundtrip.py``, and scapy's IGMP layers agree with what
``make()`` writes.

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

HAS_SCAPY = importlib.util.find_spec('scapy') is not None


def message(head: bytes, rest: bytes) -> bytes:
    """``head`` (type and Max Resp Code), the checksum over the whole message, then ``rest``."""
    return head + wire.checksum(head + b'\x00\x00' + rest).to_bytes(2, 'big') + rest


def with_checksum(packet: bytes, field: bytes, at: int = 2) -> bytes:
    """``packet`` with ``field`` at ``at``."""
    return packet[:at] + field + packet[at + 2:]


#: A group record of type MODE_IS_INCLUDE for 239.1.1.1 with one source, 10.0.0.1.
RECORD = bytes.fromhex('01000001ef0101010a000001')

#: One message per IGMP version and shape: its octets, the class it is read as,
#: and that class's alias.
MESSAGES = {
    'v1-query': (message(b'\x11\x00', bytes(4)), 'IGMPv1', 'IGMP'),
    'v1-report': (message(b'\x12\x00', bytes([224, 0, 0, 1])), 'IGMPv1', 'IGMP'),
    'v2-query': (message(b'\x11\x64', bytes(4)), 'IGMPv2', 'IGMPv2'),
    'v2-report': (message(b'\x16\x00', bytes([239, 1, 2, 3])), 'IGMPv2', 'IGMPv2'),
    'v2-leave': (message(b'\x17\x00', bytes([239, 1, 2, 3])), 'IGMPv2', 'IGMPv2'),
    # A General Query with QRV 2, QQIC 125 and one source, 10.0.0.1.
    'v3-query': (message(b'\x11\x64', bytes(4) + bytes.fromhex('027d00010a000001')), 'IGMPv3', 'IGMPv3'),
    'v3-report': (message(b'\x22\x00', bytes.fromhex('00000001') + RECORD), 'IGMPv3', 'IGMPv3'),
}


class IGMPChecksumTestCase(unittest.TestCase):
    """Imports and helpers every IGMP checksum test shares."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.corekit.checksum.internet import ChecksumStatus
        from pcapkit.protocols.internet.igmp import IGMP
        from pcapkit.protocols.internet.igmpv1 import IGMPv1
        from pcapkit.protocols.internet.igmpv2 import IGMPv2
        from pcapkit.protocols.internet.igmpv3 import IGMPv3
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.utilities import config
        from pcapkit.utilities.warnings import ChecksumWarning, ProtocolWarning

        self.IGMP, self.IPv4 = IGMP, IPv4
        self.classes = {'IGMPv1': IGMPv1, 'IGMPv2': IGMPv2, 'IGMPv3': IGMPv3}
        self.Status = ChecksumStatus
        self.config = config
        self.ProtocolWarning = ProtocolWarning
        self.ChecksumWarning = ChecksumWarning

    def parse(self, octets: bytes, cls: type, *, verify: bool = True) -> 'tuple[object, list[tuple[type, str]]]':
        """``octets`` parsed as ``cls``, and its ProtocolWarnings as ``(category, message)``."""
        with mock.patch.object(self.config, 'CHECKSUM_VERIFY', verify), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            layer = cls(octets)
        return layer, [(item.category, str(item.message))
                       for item in caught if issubclass(item.category, self.ProtocolWarning)]

    def status(self, octets: bytes, **kwargs: object) -> 'tuple[object, list[tuple[type, str]]]':
        """The IGMP checksum status of the IPv4 packet ``octets``, and its ProtocolWarnings."""
        layer, messages = self.parse(octets, self.IPv4, **kwargs)
        return layer['IGMP'].info.get('checksum_status'), messages


class IGMPChecksumReadTests(IGMPChecksumTestCase):
    """Reading the checksum of every IGMP version."""

    def test_a_good_checksum_verifies(self) -> None:
        for name, (packet, version, _) in MESSAGES.items():
            with self.subTest(name, via='fixture'):
                self.assertEqual(wire.checksum(packet), 0)
            cls = self.classes[version]
            for via in (cls, self.IGMP):
                with self.subTest(name, via=via.__name__):
                    layer, messages = self.parse(packet, via)
                    self.assertIs(type(layer), cls)
                    self.assertEqual((layer.info.checksum_status, messages), (self.Status.VALID, []))
            with self.subTest(name, via='IPv4'):
                self.assertEqual(self.status(wire.ipv4(packet, proto=2)), (self.Status.VALID, []))

    def test_a_bad_checksum_is_recorded_and_warns(self) -> None:
        for name, (packet, version, alias) in MESSAGES.items():
            good = int.from_bytes(packet[2:4], 'big')
            bad = good ^ 0x0101
            corrupt = with_checksum(packet, bad.to_bytes(2, 'big'))
            warning = (self.ChecksumWarning, f'{alias}: checksum {bad:#06x} is wrong; {good:#06x} expected')
            with self.subTest(name):
                layer, messages = self.parse(corrupt, self.classes[version])
                self.assertEqual((layer.info.checksum_status, messages), (self.Status.INVALID, [warning]))
                self.assertEqual(layer.info.checksum, bad.to_bytes(2, 'big'))
            with self.subTest(name, via='IPv4'):
                self.assertEqual(self.status(wire.ipv4(corrupt, proto=2)), (self.Status.INVALID, [warning]))

    def test_a_zero_checksum_is_wrong_not_absent(self) -> None:
        # IGMP lets no sender leave its checksum out (RFC 2236 section 2.3), so zero
        # is a wrong checksum, unlike UDP's over IPv4.
        for name, (packet, version, _) in MESSAGES.items():
            with self.subTest(name):
                layer, messages = self.parse(with_checksum(packet, b'\x00\x00'), self.classes[version])
                self.assertIs(layer.info.checksum_status, self.Status.INVALID)
                self.assertEqual([category for category, _ in messages], [self.ChecksumWarning])

    def test_the_checksum_covers_the_whole_ip_payload(self) -> None:
        # Octets past the message are summed too (RFC 2236 section 2.5), IGMPv1's
        # included, since RFC 2236 updates RFC 1112.
        for name in ('v1-report', 'v2-report', 'v3-report'):
            packet, version, alias = MESSAGES[name]
            whole = message(packet[:2], packet[4:] + b'XY')
            header_only = packet + b'XY'
            with self.subTest(name):
                self.assertEqual(self.status(wire.ipv4(whole, proto=2)), (self.Status.VALID, []))
                status, messages = self.status(wire.ipv4(header_only, proto=2))
                self.assertIs(status, self.Status.INVALID)
                self.assertEqual(messages, [(self.ChecksumWarning,
                                             f'{alias}: checksum 0x{packet[2:4].hex()} is wrong; '
                                             f'0x{whole[2:4].hex()} expected')])

    def test_truncated_and_off(self) -> None:
        # An IGMPv3 Report cut short parses as far as it goes (#2650).
        for name in ('v2-report', 'v3-query', 'v3-report'):
            packet = message(MESSAGES[name][0][:2], MESSAGES[name][0][4:] + b'XY')
            with self.subTest(name):
                self.assertEqual(self.status(wire.ipv4(packet, proto=2)[:-1]), (self.Status.TRUNCATED, []))
                corrupt = with_checksum(packet, b'\xbe\xef')
                self.assertEqual(self.status(wire.ipv4(corrupt, proto=2), verify=False), (None, []))

    def test_a_fragment_is_not_verified(self) -> None:
        # The first of two fragments, More Fragments set: the checksum covers the
        # whole message, which this fragment carries part of.
        whole = message(b'\x16\x00', bytes([239, 1, 2, 3]) + bytes(8))
        layer, messages = self.parse(wire.ipv4(whole, mf=True, proto=2), self.IPv4)
        self.assertEqual((layer['IGMP'].info.checksum_status, messages), (self.Status.NO_PSEUDO_HEADER, []))
        self.assertEqual(self.IPv4.from_data(layer.info).data, wire.ipv4(whole, mf=True, proto=2))

    def test_parse_rebuild_is_exact(self) -> None:
        # Whatever the status recorded, the checksum is rebuilt as captured.
        for name, (packet, version, _) in MESSAGES.items():
            cls = self.classes[version]
            cases = ((packet, self.Status.VALID), (with_checksum(packet, b'\xbe\xef'), self.Status.INVALID))
            for octets, status in cases:
                for verify in (True, False):
                    with self.subTest(name, octets=octets.hex(), verify=verify):
                        layer, _ = self.parse(octets, cls, verify=verify)
                        self.assertEqual(layer.info.get('checksum_status'), status if verify else None)
                        self.assertEqual(cls.from_data(layer.info).data, octets)
                        datagram = wire.ipv4(octets, proto=2)
                        layer, _ = self.parse(datagram, self.IPv4, verify=verify)
                        self.assertEqual(self.IPv4.from_data(layer.info).data, datagram)


class IGMPChecksumMakeTests(IGMPChecksumTestCase):
    """Making the checksum of every IGMP version."""

    #: ``make()`` arguments of each fixture, the checksum left out.
    FIELDS = {
        'v1-query': {'type': 0x11},
        'v1-report': {'type': 0x12, 'group': '224.0.0.1'},
        'v2-query': {'type': 0x11, 'max_resp_time': 100},
        'v2-report': {'type': 0x16, 'group': '239.1.2.3'},
        'v2-leave': {'type': 0x17, 'group': '239.1.2.3'},
        'v3-query': {'max_resp_time': 100, 'qrv': 2, 'qqic': 125, 'sources': ['10.0.0.1']},
        'v3-report': {'type': 0x22, 'records': [{'record_type': 1, 'multicast_address': '239.1.1.1',
                                                 'sources': ['10.0.0.1']}]},
    }

    def test_make_computes_the_checksum(self) -> None:
        self.assertEqual(set(self.FIELDS), set(MESSAGES))
        for name, fields in self.FIELDS.items():
            packet, version, _ = MESSAGES[name]
            cls = self.classes[version]
            with self.subTest(name):
                self.assertEqual(cls(**fields).data, packet)
                self.assertEqual(self.IGMP(version=int(version[-1]), **fields).data, packet)
                layer, messages = self.parse(cls(**fields).data, cls)
                self.assertEqual((layer.info.checksum_status, messages), (self.Status.VALID, []))
                # Off, it is left zero; given, it is written as given.
                with mock.patch.object(self.config, 'CHECKSUM_COMPUTE', False):
                    self.assertEqual(cls(**fields).data, with_checksum(packet, b'\x00\x00'))
                self.assertEqual(cls(checksum=b'\xbe\xef', **fields).data, with_checksum(packet, b'\xbe\xef'))

    def test_the_computed_checksum_covers_the_payload(self) -> None:
        for name in ('v2-report', 'v3-report'):
            packet, version, _ = MESSAGES[name]
            with self.subTest(name):
                made = self.classes[version](payload=b'XY', **self.FIELDS[name]).data
                self.assertEqual(made, message(packet[:2], packet[4:] + b'XY'))

    def test_the_ipv4_payload_verifies(self) -> None:
        igmp = self.classes['IGMPv2'](**self.FIELDS['v2-report'])
        made = self.IPv4(src='10.0.0.1', dst='239.1.2.3', protocol='IGMP', payload=igmp).data
        self.assertEqual(made[20:], MESSAGES['v2-report'][0])
        self.assertEqual(self.status(made), (self.Status.VALID, []))

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_make_agrees_with_scapy(self) -> None:
        from scapy.contrib.igmp import IGMP
        from scapy.contrib.igmpv3 import IGMPv3

        for name, fields in self.FIELDS.items():
            version = MESSAGES[name][1]
            # Octets past a Query change its version, so only a Report carries some.
            payload = b'XY' if 'report' in name else b''
            made = self.classes[version](payload=payload, **fields).data
            with self.subTest(name):
                packet = (IGMPv3 if version == 'IGMPv3' else IGMP)(made)
                del packet.chksum
                self.assertEqual(bytes(packet), made)


if __name__ == '__main__':
    unittest.main()
