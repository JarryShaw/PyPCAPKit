# -*- coding: utf-8 -*-
"""GRE verifies and computes its checksum when ``C`` is set.

GitHub issue #2618: with the Checksum Present bit set, the GRE checksum covers the
header and the payload, with no pseudo-header (:rfc:`2784#section-2.5`).
:meth:`GRE.read <pcapkit.protocols.link.gre.protocol.GRE.read>` verifies it under
:data:`~pcapkit.utilities.config.CHECKSUM_VERIFY`, as ICMP's is verified, and records
:attr:`~pcapkit.corekit.checksum.internet.ChecksumStatus.NOT_COMPUTED` when ``C`` is
clear; :meth:`GRE.make <pcapkit.protocols.link.gre.protocol.GRE.make>` computes one that
``checksum_present`` asks for without giving it, under
:data:`~pcapkit.utilities.config.CHECKSUM_COMPUTE`.

No capture under :file:`examples/captures/`, tracked or generated, carries GRE, so the
frames are built here; their checksums are the hand-written sum of
``tests/foundation/_roundtrip.py``, and scapy's GRE layer agrees with what ``make()``
writes.

"""
from __future__ import annotations

import importlib.util
import struct
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

#: Test tier (#1958): hand-picked parse -> rebuild and make -> parse round trips.
__tier__ = 'ALL'

HAS_SCAPY = importlib.util.find_spec('scapy') is not None

#: An IPv4 header (protocol UDP) and an 8-octet UDP header, the payload GRE carries.
IPV4 = bytes.fromhex('4500001c00010000401100000a0000010a000002') + bytes.fromhex('3039003500080000')


def gre(payload: bytes, *, checksum: 'int | bool' = True, key: 'int | None' = None) -> bytes:
    """A GRE header carrying IPv4 and ``payload``.

    ``checksum`` is the field's value, :data:`True` for the right one, or
    :data:`False` to leave ``C`` clear.

    """
    flags = (0x8000 if checksum is not False else 0) | (0x2000 if key is not None else 0)
    extra = b'' if key is None else struct.pack('>I', key)
    if checksum is False:
        return struct.pack('>HH', flags, 0x0800) + extra + payload
    head = struct.pack('>HH', flags, 0x0800)
    value = wire.checksum(head + b'\x00\x00\x00\x00' + extra + payload) if checksum is True else checksum
    return head + struct.pack('>HH', value, 0) + extra + payload


def linux_sll(frame: bytes) -> bytes:
    """``frame`` behind a ``LINUX_SLL`` header whose ``arphrd_type`` is ``ARPHRD_IPGRE``."""
    return struct.pack('>HHH', 0, 778, 0) + bytes(8) + struct.pack('>H', 0x0800) + frame


#: GRE frames with ``C`` set and a right checksum.
FRAMES = {
    'checksum': gre(IPV4),
    'checksum-key': gre(IPV4, key=0x11223344),
    'odd-payload': gre(b'\x01\x02\x03'),
}


class GREChecksumTests(unittest.TestCase):
    """Reading and making the GRE checksum."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.corekit.checksum.internet import ChecksumStatus
        from pcapkit.protocols.link.gre.protocol import GRE
        from pcapkit.protocols.link.linux_sll1.protocol import LinuxSLL1
        from pcapkit.utilities import config
        from pcapkit.utilities.warnings import ChecksumWarning, ProtocolWarning

        self.GRE, self.LinuxSLL1 = GRE, LinuxSLL1
        self.Status = ChecksumStatus
        self.config = config
        self.ProtocolWarning = ProtocolWarning
        self.ChecksumWarning = ChecksumWarning

    def parse(self, octets: bytes, cls: 'type | None' = None, *,
              verify: bool = True) -> 'tuple[object, list[tuple[type, str]]]':
        """``octets`` parsed as ``cls``, GRE by default, and its ProtocolWarnings."""
        with mock.patch.object(self.config, 'CHECKSUM_VERIFY', verify), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            layer = (cls or self.GRE)(octets)
        return layer, [(item.category, str(item.message))
                       for item in caught if issubclass(item.category, self.ProtocolWarning)]

    def status(self, octets: bytes, **kwargs: object) -> 'tuple[object, list[tuple[type, str]]]':
        """The GRE checksum status of ``octets``, and its ProtocolWarnings."""
        layer, messages = self.parse(octets, **kwargs)
        return layer.info.get('checksum_status'), messages

    def test_a_good_checksum_verifies(self) -> None:
        for name, frame in FRAMES.items():
            with self.subTest(name):
                self.assertEqual(wire.checksum(frame), 0)
                self.assertEqual(self.status(frame), (self.Status.VALID, []))
                layer, messages = self.parse(linux_sll(frame), self.LinuxSLL1)
                self.assertEqual((layer['GRE'].info.checksum_status, messages), (self.Status.VALID, []))

    def test_a_bad_checksum_is_recorded_and_warns(self) -> None:
        good = int.from_bytes(FRAMES['checksum'][4:6], 'big')
        frame = gre(IPV4, checksum=good ^ 0x0101)
        warning = (self.ChecksumWarning, f'GRE: checksum {good ^ 0x0101:#06x} is wrong; {good:#06x} expected')
        self.assertEqual(self.status(frame), (self.Status.INVALID, [warning]))
        layer, messages = self.parse(linux_sll(frame), self.LinuxSLL1)
        self.assertEqual((layer['GRE'].info.checksum_status, messages), (self.Status.INVALID, [warning]))
        # The payload still parses.
        self.assertEqual(layer.protochain.chain, 'LINUX_SLL1:GRE:IPv4:UDP')

    def test_c_clear_and_off(self) -> None:
        for frame in (gre(IPV4, checksum=False), gre(IPV4, checksum=False, key=7)):
            with self.subTest(frame=frame.hex()):
                self.assertEqual(self.status(frame), (self.Status.NOT_COMPUTED, []))
                self.assertEqual(self.status(frame, verify=False), (None, []))
        # Off, a wrong checksum is not looked at either.
        bad = gre(IPV4, checksum=0xBEEF)
        self.assertEqual(self.status(bad, verify=False), (None, []))
        self.assertIs(self.status(bad)[0], self.Status.INVALID)

    def test_a_fragment_is_not_verified(self) -> None:
        # A layer an IP fragment carries is not verified, whatever it is.
        from pcapkit.corekit.checksum.internet import fragment_payload

        with fragment_payload(True):
            self.assertEqual(self.status(gre(IPV4, checksum=0xBEEF)), (self.Status.NO_PSEUDO_HEADER, []))
            self.assertEqual(self.status(gre(IPV4, checksum=False)), (self.Status.NOT_COMPUTED, []))

    def test_parse_rebuild_is_exact(self) -> None:
        # Whatever the status recorded, the checksum is rebuilt as captured.
        cases = [(frame, self.Status.VALID) for frame in FRAMES.values()]
        cases += [(gre(IPV4, checksum=0xBEEF), self.Status.INVALID),
                  (gre(IPV4, checksum=False), self.Status.NOT_COMPUTED)]
        for frame, status in cases:
            for verify in (True, False):
                with self.subTest(frame=frame.hex(), verify=verify):
                    layer, _ = self.parse(frame, verify=verify)
                    self.assertEqual(layer.info.get('checksum_status'), status if verify else None)
                    self.assertEqual(self.GRE.from_data(layer.info).data, frame)
                    layer, _ = self.parse(linux_sll(frame), self.LinuxSLL1, verify=verify)
                    self.assertEqual(self.LinuxSLL1.from_data(layer.info).data, linux_sll(frame))

    def test_make_computes_the_checksum(self) -> None:
        self.assertEqual(self.GRE(checksum_present=True, payload=IPV4).data, FRAMES['checksum'])
        self.assertEqual(self.GRE(checksum_present=True, key=0x11223344, payload=IPV4).data,
                         FRAMES['checksum-key'])
        made = self.GRE(checksum_present=True, payload=b'\x01\x02\x03').data
        self.assertEqual(made, FRAMES['odd-payload'])
        self.assertEqual(self.status(made), (self.Status.VALID, []))

    def test_off_given_or_absent_is_written_as_is(self) -> None:
        with mock.patch.object(self.config, 'CHECKSUM_COMPUTE', False):
            self.assertEqual(self.GRE(checksum_present=True, payload=IPV4).data, gre(IPV4, checksum=0))
        self.assertEqual(self.GRE(checksum=0xBEEF, payload=IPV4).data, gre(IPV4, checksum=0xBEEF))
        self.assertEqual(self.GRE(checksum_present=True, checksum=0xBEEF, payload=IPV4).data,
                         gre(IPV4, checksum=0xBEEF))
        self.assertEqual(self.GRE(payload=IPV4).data, gre(IPV4, checksum=False))
        self.assertEqual(self.GRE(checksum_present=False, payload=IPV4).data, gre(IPV4, checksum=False))

    def test_make_refuses_a_checksum_with_c_clear(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        for kwargs in ({'checksum_present': False, 'checksum': 0}, {'checksum_present': False, 'reserved1': 0}):
            with self.subTest(**kwargs), self.assertRaises(ProtocolError):
                self.GRE(**kwargs)
        # Reserved1 goes with C, whether or not the checksum is given.
        self.assertEqual(self.GRE(checksum_present=True, reserved1=5).data[6:8], b'\x00\x05')

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_make_agrees_with_scapy(self) -> None:
        from scapy.layers.l2 import GRE

        for kwargs in ({}, {'key': 0x11223344}):
            made = self.GRE(checksum_present=True, payload=b'\x01\x02\x03', **kwargs).data
            with self.subTest(**kwargs):
                packet = GRE(made)
                del packet.chksum
                self.assertEqual(bytes(packet), made)


if __name__ == '__main__':
    unittest.main()
