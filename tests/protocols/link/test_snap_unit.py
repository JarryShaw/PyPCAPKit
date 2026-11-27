# -*- coding: utf-8 -*-
"""GitHub issue #2936: the IEEE 802 SNAP header behind LLC.

:class:`~pcapkit.protocols.link.snap.protocol.SNAP` reads the OUI and the protocol
identifier. Under the OUI ``00-00-00`` the protocol identifier is an EtherType
(:rfc:`9542#section-3`) and the payload is dispatched as Ethernet dispatches it;
under any other the payload is kept raw. Every octet string here is built by
hand, and every layer rebuilds byte-exactly.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`.

"""

import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): per-protocol field tests, interpreter-independent pure Python.
__tier__ = 'LATEST'

#: An option-less IPv4 header of protocol 59 and no payload, 192.0.2.1 to 198.51.100.1.
IPV4 = bytes.fromhex('4500001400000000403b0000c0000201c6336401')

#: An IPv6 header of next header 59 and no payload, :: to ::.
IPV6 = bytes.fromhex('60000000' '0000' '3b' '40') + bytes(32)


class TestSNAP(unittest.TestCase):
    """Pin the SNAP header: parse, build, and dispatch."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _parse(self, data: bytes):  # type: ignore[no-untyped-def]
        from pcapkit.protocols.link.snap.protocol import SNAP
        return SNAP(data, len(data))

    def _assert_rebuilds(self, layer) -> None:  # type: ignore[no-untyped-def]
        """``layer`` rebuilds byte-exactly from its info, and from ``info.to_dict()``."""
        for data in (layer.info, layer.info.to_dict()):
            with self.subTest(layer=type(layer).__name__, data=type(data).__name__):
                rebuilt = type(layer).from_data(data)
                self.assertEqual(rebuilt.data.hex(), layer.data.hex())
                self.assertEqual(rebuilt.info, layer.info)

    def test_oui_zero_carries_an_ethertype(self) -> None:
        from pcapkit.const.reg.ethertype import EtherType

        for pid, payload, chain in ((0x0800, IPV4, 'SNAP:IPv4'), (0x86DD, IPV6, 'SNAP:IPv6')):
            with self.subTest(pid=hex(pid)):
                snap = self._parse(bytes.fromhex('000000') + pid.to_bytes(2, 'big') + payload)
                self.assertEqual(snap.info.oui, 0)
                self.assertIs(snap.info.pid, EtherType.get(pid))
                self.assertEqual(snap.protochain.chain, chain)
                self._assert_rebuilds(snap)

    def test_another_oui_keeps_its_payload_raw(self) -> None:
        """Cisco's ``00-00-0C`` with PID ``0x2000`` is that organization's protocol, not an EtherType."""
        snap = self._parse(bytes.fromhex('00000c' '2000') + IPV4)
        self.assertEqual((snap.info.oui, snap.info.pid), (0x00000C, 0x2000))
        self.assertIs(type(snap.info.pid), int)
        self.assertEqual(type(snap.payload).__name__, 'Raw')
        self.assertEqual(bytes(snap.payload.data), IPV4)
        self._assert_rebuilds(snap)

    def test_names_and_index(self) -> None:
        from pcapkit.const.llc.lsap import LSAP
        from pcapkit.protocols.link.snap.protocol import SNAP

        snap = self._parse(bytes.fromhex('000000' '0800') + IPV4)
        self.assertEqual((snap.name, snap.alias, snap.length), ('Subnetwork Access Protocol', 'SNAP', 5))
        self.assertEqual(SNAP.id(), ('SNAP',))
        self.assertIs(SNAP.__index__(), LSAP.SNAP)

    def test_make(self) -> None:
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.protocols.link.snap.protocol import SNAP
        from pcapkit.utilities.exceptions import ProtocolError

        self.assertEqual(bytes(SNAP.from_fields(payload=IPV4)), bytes.fromhex('000000' '0800') + IPV4)
        made = SNAP.from_fields(pid=EtherType.Internet_Protocol_version_6, payload=IPV6)
        self.assertEqual(bytes(made), bytes.fromhex('000000' '86dd') + IPV6)
        self.assertEqual(bytes(SNAP.from_fields(oui=0x00000C, pid=0x2000)), bytes.fromhex('00000c2000'))
        for fields in ({'oui': 1 << 24}, {'pid': 'Internet_Protocol_version_4'}, {'pid': 1 << 16},
                       {'oui': 0x00000C, 'pid': 1 << 16}, {'pid': True}):
            with self.subTest(fields=fields):
                with self.assertRaises(ProtocolError):
                    SNAP.from_fields(**fields)


if __name__ == '__main__':
    unittest.main()
