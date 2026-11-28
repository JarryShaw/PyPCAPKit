# -*- coding: utf-8 -*-
"""STP, RSTP and MSTP BPDUs are a versioned family behind LLC SAP 0x42 (#3115).

IEEE 802.1D-2004 clause 9 lays out the Configuration and TCN BPDUs, and IEEE
802.1Q-2022 clause 14 the RST and MST BPDUs; clause 14.4 decodes a BPDU by its
Protocol Identifier, BPDU Type, Protocol Version Identifier and length, so a
Configuration BPDU is one whatever its version, and a BPDU of version 3 or more
failing the MST checks is an RST BPDU. MSTP reads and builds version 3 alone: a
later version passing them is the SPT BPDU, which no member reads. LLC hands a PDU
on to the family only when its DSAP and SSAP are both 0x42. The Configuration BPDU below was built with
``scapy`` 2.7.0, and the RST and MST BPDUs read field for field as tshark 4.6
reads them.

Every case builds its own octets in memory and reads no capture.

"""
from __future__ import annotations

import importlib.util
import struct
import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): hand-picked parse -> rebuild and make -> parse round trips.
__tier__ = 'ALL'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: ``Dot3(dst='01:80:c2:00:00:00', src='00:11:22:33:44:55')/LLC(dsap=0x42, ssap=0x42,
#: ctrl=3)/STP(bpduflags=0x81, rootid=32768, rootmac='00:11:22:33:44:55', pathcost=4,
#: bridgeid=32769, bridgemac='00:aa:bb:cc:dd:ee', portid=0x8002, age=1, maxage=20,
#: hellotime=2, fwddelay=15)``, as scapy 2.7.0 builds it: a Configuration BPDU.
CONFIG_FRAME = bytes.fromhex(
    '0180c2000000001122334455002642420300000000818000001122334455'
    '00000004800100aabbccddee80020100140002000f00'
)

#: An RST BPDU of flags 0x7d: Topology Change, Designated, Learning, Forwarding and
#: Agreement; tshark reads Message Age 1.5 and a Version 1 Length of 0.
RST = bytes.fromhex(
    '000002027d100100112233445500004e20800100aabbccddee80010180140002000f0000'
)

#: An MST BPDU with one MSTI Configuration Message, MSTID 10, a Master flag and
#: priorities 36864 and 144; tshark reads a Version 3 Length of 80.
MST = bytes.fromhex(
    '0000030279100000112233445500030d40200000aabbccddee80030100140002000f'
    '0000005000726567696f6e3100000000000000000000000000000000000000000000'
    '0000000007000102030405060708090a0b0c0d0e0f00004e20800000010203040514'
    '8e800a00aabbccddee000007d0909013'
)

#: A TCN BPDU.
TCN = bytes.fromhex('00000080')


def frame(bpdu: bytes, dsap: int = 0x42, ssap: int = 0x42) -> bytes:
    """An 802.3 frame to the Bridge Group Address carrying ``bpdu`` in a UI PDU."""
    pdu = bytes([dsap, ssap, 0x03]) + bpdu
    head = bytes.fromhex('0180c2000000' '001122334455') + struct.pack('!H', len(pdu)) + pdu
    return head + bytes(max(60 - len(head), 0))


def mst(version: int = 3, v1: int = 0, v3: int = 64, msti: bytes = b'', tail: bytes = b'') -> bytes:
    """An MST BPDU of zeros, with the given version, lengths, messages and trailing octets."""
    return (struct.pack('!HBB', 0, version, 2) + bytes(31) + struct.pack('!BH', v1, v3)
            + bytes(64) + msti + tail)


class _STPTestCase(unittest.TestCase):
    """A fresh :mod:`pcapkit` per class, and the names each case shares."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.const.llc.lsap import LSAP
        from pcapkit.const.stp.bpdu_type import BPDUType
        from pcapkit.const.stp.port_role import PortRole
        from pcapkit.const.stp.protocol_version import ProtocolVersion
        from pcapkit.protocols.application.mstp.data import MSTIFlags, MSTIMessage
        from pcapkit.protocols.application.mstp.protocol import MSTP
        from pcapkit.protocols.application.rstp.protocol import RSTP
        from pcapkit.protocols.application.stp.data import BridgeID, Flags, PortID
        from pcapkit.protocols.application.stp.protocol import STP
        from pcapkit.protocols.application.stpv0.data import ConfigFlags
        from pcapkit.protocols.application.stpv0.protocol import STPv0
        from pcapkit.protocols.link.ethernet.protocol import Ethernet
        from pcapkit.protocols.link.llc.protocol import LLC
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.utilities.exceptions import ProtocolError

        self.LSAP, self.BPDUType, self.PortRole, self.ProtocolVersion = LSAP, BPDUType, PortRole, ProtocolVersion
        self.STP, self.STPv0, self.RSTP, self.MSTP = STP, STPv0, RSTP, MSTP
        self.BridgeID, self.PortID, self.Flags, self.ConfigFlags = BridgeID, PortID, Flags, ConfigFlags
        self.MSTIFlags, self.MSTIMessage = MSTIFlags, MSTIMessage
        self.Ethernet, self.LLC, self.Raw, self.ProtocolError = Ethernet, LLC, Raw, ProtocolError

    def assertRebuilds(self, layer: 'object') -> None:  # pylint: disable=invalid-name
        """``layer`` rebuilds to its octets and values, from its data model and its dict."""
        klass = type(layer)
        octets = bytes(layer)  # type: ignore[call-overload]
        for data in (layer.info, layer.info.to_dict()):  # type: ignore[attr-defined]
            with self.subTest(data=type(data).__name__):
                rebuilt = klass.from_data(data)  # type: ignore[attr-defined]
                self.assertEqual(bytes(rebuilt), octets)
                self.assertEqual(rebuilt.info, layer.info)  # type: ignore[attr-defined]


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class SpecificationTests(_STPTestCase):
    """A parse holds the values IEEE 802.1D-2004 clause 9 and IEEE 802.1Q-2022 clause 14 give."""

    def test_a_configuration_bpdu_behind_llc(self) -> None:
        eth = self.Ethernet(CONFIG_FRAME)
        self.assertEqual(str(eth.protochain), 'Ethernet:LLC:STP')
        stp = eth.payload.payload
        self.assertIsInstance(stp, self.STPv0)
        info = stp.info
        self.assertEqual((info.protocol_version, info.type), (self.ProtocolVersion.STP, self.BPDUType.Configuration))
        self.assertEqual(info.flags, self.ConfigFlags(tc=True, reserved=0, tc_ack=True))
        self.assertEqual(info.root_id, self.BridgeID(priority=32768, extension=0, address='00:11:22:33:44:55'))
        self.assertEqual(info.root_path_cost, 4)
        self.assertEqual(info.bridge_id, self.BridgeID(priority=32768, extension=1, address='00:aa:bb:cc:dd:ee'))
        self.assertEqual(info.port_id, self.PortID(priority=128, number=2))
        self.assertEqual((info.message_age, info.max_age, info.hello_time, info.forward_delay), (1.0, 20.0, 2.0, 15.0))
        self.assertEqual(stp.length, 35)
        self.assertEqual(bytes(self.Ethernet.from_data(eth.info)), CONFIG_FRAME)
        self.assertRebuilds(stp)

    def test_a_tcn_bpdu_ends_after_its_type(self) -> None:
        stp = self.Ethernet(frame(TCN)).payload.payload
        self.assertIsInstance(stp, self.STPv0)
        self.assertEqual(stp.info.type, self.BPDUType.TCN)
        self.assertEqual(stp.length, 4)
        self.assertNotIn('flags', stp.info)
        self.assertRebuilds(stp)

    def test_an_rst_bpdu(self) -> None:
        rstp = self.STP(RST)
        self.assertIsInstance(rstp, self.RSTP)
        info = rstp.info
        self.assertEqual(info.flags, self.Flags(tc=True, proposal=False, role=self.PortRole.Designated, learning=True,
                                                forwarding=True, agreement=True, tc_ack=False))
        self.assertEqual(info.root_id, self.BridgeID(priority=4096, extension=1, address='00:11:22:33:44:55'))
        self.assertEqual(info.root_path_cost, 20000)
        self.assertEqual(info.port_id, self.PortID(priority=128, number=1))
        self.assertEqual((info.message_age, info.version_1_length), (1.5, 0))
        self.assertEqual(rstp.length, 36)
        self.assertRebuilds(rstp)

    def test_an_mst_bpdu(self) -> None:
        mstp = self.STP(MST)
        self.assertIsInstance(mstp, self.MSTP)
        info = mstp.info
        self.assertEqual(info.flags.role, self.PortRole.Root)
        self.assertEqual(info.cist_root_id.priority, 4096)
        self.assertEqual(info.cist_external_root_path_cost, 200000)
        self.assertEqual(info.cist_regional_root_id.priority, 8192)
        self.assertEqual(info.cist_port_id, self.PortID(priority=128, number=3))
        self.assertEqual((info.version_1_length, info.version_3_length), (0, 80))
        self.assertEqual(info.config_id.name.rstrip(b'\x00'), b'region1')
        self.assertEqual((info.config_id.revision_level, info.config_id.digest), (7, bytes(range(16))))
        self.assertEqual(info.cist_internal_root_path_cost, 20000)
        self.assertEqual(info.cist_bridge_id.address, '00:01:02:03:04:05')
        self.assertEqual(info.cist_remaining_hops, 20)
        (msti,) = info.msti
        self.assertEqual(msti.flags, self.MSTIFlags(tc=False, proposal=True, role=self.PortRole.Designated,
                                                    learning=False, forwarding=False, agreement=False, master=True))
        self.assertEqual(msti.regional_root_id, self.BridgeID(priority=32768, extension=10, address='00:aa:bb:cc:dd:ee'))
        self.assertEqual((msti.internal_root_path_cost, msti.bridge_priority, msti.port_priority, msti.remaining_hops),
                         (2000, 36864, 144, 19))
        self.assertEqual(mstp.length, 118)
        self.assertRebuilds(mstp)

    def test_reserved_bits_are_kept(self) -> None:
        # NOTE: Bits sent as zero and ignored on receipt are read back as captured.
        config = bytearray(bytes(self.STPv0.from_fields()))
        config[4] = 0x7E
        stp = self.STPv0(bytes(config))
        self.assertEqual(stp.info.flags.reserved, 0x3F)
        self.assertRebuilds(stp)
        octets = bytearray(MST)
        octets[115:117] = b'\x9a\x95'
        mstp = self.MSTP(bytes(octets))
        self.assertEqual((mstp.info.msti[0].bridge_reserved, mstp.info.msti[0].port_reserved), (0xA, 0x5))
        self.assertRebuilds(mstp)

    def test_names_and_index(self) -> None:
        self.assertEqual(self.STP.id(), ('STP', 'RSTP', 'MSTP'))
        self.assertEqual((self.STPv0.id(), self.RSTP.id(), self.MSTP.id()), (('STP',), ('RSTP',), ('MSTP',)))
        for octets, alias, name in ((CONFIG_FRAME[17:52], 'STP', 'Spanning Tree Protocol'),
                                    (RST, 'RSTP', 'Rapid Spanning Tree Protocol'),
                                    (MST, 'MSTP', 'Multiple Spanning Tree Protocol')):
            layer = self.STP(octets)
            self.assertEqual((layer.alias, layer.name, layer.info_name), (alias, name, 'stp'))
        for klass in (self.STP, self.STPv0, self.RSTP, self.MSTP):
            self.assertIs(klass.__index__(), self.LSAP.Bridge_Spanning_Tree_Protocol)

    def test_codes_the_standards_leave_unassigned(self) -> None:
        self.assertEqual(self.ProtocolVersion.get(1).name, 'Unassigned')
        self.assertEqual(self.BPDUType.get(0x55).name, 'Unassigned')
        for registry, code in ((self.ProtocolVersion, 256), (self.BPDUType, -1), (self.PortRole, 4)):
            with self.subTest(registry=registry.__name__):
                with self.assertRaises(ValueError):
                    registry(code)

    def test_streams_cuts_and_hints(self) -> None:
        import io

        layer = self.STP(io.BytesIO(RST))
        self.assertIsInstance(layer, self.RSTP)
        self.assertEqual(layer.type, self.BPDUType.RST)
        with self.assertRaises(TypeError):
            self.STP(None)
        for klass in (self.STPv0, self.RSTP, self.MSTP):
            with self.subTest(klass=klass.__name__):
                with self.assertRaises(self.ProtocolError):
                    klass(b'\x00\x01' + bytes(120))
        # NOTE: On its own a capture ending inside the version is a cut, rebuilt as captured.
        cut = self.RSTP(RST[:2])
        self.assertEqual(cut.info.__short_read__[0], 'version')
        self.assertEqual(bytes(self.RSTP.from_data(cut.info)), RST[:2])
        mstp = self.STP(MST)
        self.assertEqual([klass.__length_hint__(mstp) for klass in (self.STP, self.STPv0, self.RSTP, self.MSTP)],
                         [102, 35, 36, 102])

    def test_selectors(self) -> None:
        rst = self.Ethernet(frame(RST))
        self.assertIn('STP', rst)
        self.assertIn('RSTP', rst)
        self.assertNotIn('MSTP', rst)
        self.assertNotIn('STPv0', rst)
        self.assertIn('STP', self.Ethernet(CONFIG_FRAME))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ValidationTests(_STPTestCase):
    """The member is the one IEEE 802.1Q-2022 clause 14.4 decodes a BPDU as."""

    def test_the_decoding_matrix(self) -> None:
        cases = (
            ('Configuration BPDU of version 2', bytes.fromhex('00000200') + bytes(31), 'STPv0'),
            ('TCN BPDU of version 3', bytes.fromhex('00000380'), 'STPv0'),
            ('version 3, 36 octets', bytes(RSTP_V3), 'RSTP'),
            ('version 3, 35 octets', RSTP_V3[:35], 'RSTP'),
            ('version 3, Version 1 Length 1', mst(v1=1), 'RSTP'),
            ('version 3, Version 3 Length 70', mst(v3=70), 'RSTP'),
            ('version 3, Version 3 Length 63', mst(v3=63), 'RSTP'),
            ('version 3, 65 messages', mst(v3=64 + 16 * 65, msti=bytes(16 * 65)), 'RSTP'),
            ('version 3, 101 octets', mst()[:101], 'RSTP'),
            ('version 3, 64 messages', mst(v3=64 + 16 * 64, msti=bytes(16 * 64)), 'MSTP'),
            ('version 3, octets past its messages', mst(tail=b'\x00\x10'), 'MSTP'),
            ('version 4, Version 1 Length 1', mst(version=4, v1=1), 'RSTP'),
        )
        for label, octets, member in cases:
            with self.subTest(label):
                layer = self.STP(octets)
                self.assertEqual(type(layer).__name__, member)
                self.assertEqual(bytes(type(layer).from_data(layer.info)), octets)
        self.assertIsNone(self.STP(RSTP_V3[:35]).info.version_1_length)
        self.assertEqual(self.STP(mst(version=4, v1=1)).info.protocol_version, self.ProtocolVersion.SPT)

    def test_what_the_clause_discards(self) -> None:
        cases = (
            ('Protocol Identifier 1', b'\x00\x01' + bytes(33)),
            ('BPDU Type 0x01', bytes.fromhex('00000001') + bytes(31)),
            ('BPDU Type 0x02 of version 0', bytes.fromhex('00000002') + bytes(32)),
            ('BPDU Type 0x02 of version 1', bytes.fromhex('00000102') + bytes(32)),
            ('RST BPDU of version 2, 35 octets', RSTP_V2[:35]),
            ('Configuration BPDU of 34 octets', bytes(34)),
            ('version 3, 34 octets', RSTP_V3[:34]),
            ('3 octets', bytes(3)),
            # NOTE: An SPT BPDU extends an MST BPDU past its messages, and no member reads it.
            ('version 4 holding an MST BPDU, an SPT BPDU', mst(version=4, tail=b'\x00\x10')),
            ('version 4 holding an MST BPDU and nothing past it', mst(version=4)),
            ('version 255 holding an MST BPDU', mst(version=255)),
        )
        for label, octets in cases:
            with self.subTest(label):
                with self.assertRaises(self.ProtocolError):
                    self.STP(octets)
                llc = self.Ethernet(frame(octets)).payload
                self.assertIsInstance(llc.payload, self.Raw)
                self.assertIn('STP', llc.payload.info.error)

    def test_a_member_refuses_another_members_bpdu(self) -> None:
        for klass, octets in ((self.STPv0, RST), (self.RSTP, CONFIG_FRAME[17:52]), (self.RSTP, MST),
                              (self.MSTP, mst(v1=1)), (self.MSTP, mst(v3=70)), (self.MSTP, RST),
                              (self.MSTP, mst(version=4)), (self.MSTP, mst(version=4, tail=b'\x00\x10'))):
            with self.subTest(klass=klass.__name__, octets=octets.hex()):
                with self.assertRaises(self.ProtocolError):
                    klass(octets)
        with self.assertRaises(self.ProtocolError):
            self.STP(RST, version=0)


#: An RST BPDU of version 2 and one of version 3, otherwise zeros.
RSTP_V2 = struct.pack('!HBB', 0, 2, 2) + bytes(32)
RSTP_V3 = struct.pack('!HBB', 0, 3, 2) + bytes(32)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PairingTests(_STPTestCase):
    """LLC hands a PDU on to the family only with DSAP and SSAP both 0x42."""

    def test_the_ssap_must_be_the_bridge_sap(self) -> None:
        llc = self.Ethernet(frame(RST, ssap=0x40)).payload
        self.assertIsInstance(llc.payload, self.Raw)
        self.assertIsNone(llc.payload.info.get('error'))
        # NOTE: The C/R bit is the low bit of the SSAP octet, so a response is still paired.
        self.assertIsInstance(self.Ethernet(frame(RST, ssap=0x43)).payload.payload, self.RSTP)

    def test_the_row_ships_paired_and_a_restore_keeps_it(self) -> None:
        from pcapkit.foundation.registry.protocols.link import register_lsap

        code = self.LSAP.Bridge_Spanning_Tree_Protocol
        self.assertIs(self.LLC.__paired__.get(code), True)
        shipped = self.LLC.__proto__[code]
        try:
            with self.assertWarns(Warning):
                register_lsap(code, self.Raw)
            self.assertNotIn(code, self.LLC.__paired__)
        finally:
            with self.assertWarns(Warning):
                register_lsap(code, shipped)
        self.assertIs(self.LLC.__paired__.get(code), True)
        self.assertIsInstance(self.Ethernet(frame(RST)).payload.payload, self.RSTP)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class FamilyTests(_STPTestCase):
    """The base gives the member ``version`` names on both paths, and the data model's on ``from_data``."""

    def test_version_names_the_member_on_construction(self) -> None:
        for version, klass in ((0, self.STPv0), (2, self.RSTP), (3, self.MSTP)):
            with self.subTest(version=version):
                layer = self.STP(version=version)
                self.assertIs(type(layer), klass)
                self.assertIs(type(self.STP(bytes(layer))), klass)
                self.assertIs(type(self.STP.from_fields(version=version)), klass)
                self.assertIs(type(klass(version=version)), klass)
        for version in (1, 4, True, '0'):
            with self.subTest(version=version):
                with self.assertRaises(self.ProtocolError):
                    self.STP(version=version)
        with self.assertRaises(self.ProtocolError):
            self.STP()
        with self.assertRaises(self.ProtocolError):
            self.RSTP(version=3)
        with self.assertRaises(self.ProtocolError):
            self.STP(MST, version=4)

    def test_from_data_reads_the_data_models_class(self) -> None:
        for octets, klass in ((CONFIG_FRAME[17:52], self.STPv0), (RST, self.RSTP), (MST, self.MSTP)):
            with self.subTest(klass=klass.__name__):
                info = self.STP(octets).info
                self.assertIs(type(self.STP.from_data(info)), klass)
                with self.assertRaises(self.ProtocolError):
                    self.STP.from_data(info.to_dict())
        # NOTE: An RST BPDU of version 3 stays RSTP's, whatever its version names.
        info = self.STP(RSTP_V3).info
        self.assertIs(type(self.STP.from_data(info)), self.RSTP)

    def test_construction_from_data_models_mappings_and_codes(self) -> None:
        flags = self.Flags(tc=False, proposal=True, role=self.PortRole.Alternate_or_Backup, learning=False,
                           forwarding=False, agreement=False, tc_ack=True)
        by_model = self.RSTP(flags=flags, root_id=self.BridgeID(priority=61440, extension=4095, address='ff:ff:ff:ff:ff:ff'),
                             port_id=self.PortID(priority=240, number=4095), max_age=20)
        by_mapping = self.RSTP(flags=dict(flags, role=1), root_id=b'\xff' * 8, port_id=0xFFFF, max_age=20.0,
                               protocol_version=self.ProtocolVersion.RSTP)
        self.assertEqual(bytes(by_model), bytes(by_mapping))
        self.assertEqual(bytes(by_model)[4], 0x86)
        tcn = self.STPv0(type=self.BPDUType.TCN, protocol_version=7)
        self.assertEqual(bytes(tcn), bytes.fromhex('00000780'))

    def test_make_refuses_what_it_would_not_read_back(self) -> None:
        refusals = (
            (self.STPv0, {'type': self.BPDUType.TCN, 'flags': 0}),
            (self.STPv0, {'type': self.BPDUType.RST}),
            (self.STPv0, {'type': 'Configuration'}),
            (self.RSTP, {'version_1_length': None}),
            (self.RSTP, {'protocol_version': 1}),
            (self.RSTP, {'protocol_version': 3, 'payload': mst()[36:]}),
            (self.MSTP, {'protocol_version': 2}),
            (self.MSTP, {'protocol_version': 4}),
            (self.MSTP, {'protocol_version': self.ProtocolVersion.SPT, 'payload': b'\x00\x10'}),
            (self.RSTP, {'protocol_version': 4, 'payload': mst()[36:]}),
            (self.MSTP, {'version_3_length': 70}),
            (self.MSTP, {'msti': [bytes(16)] * 65}),
            (self.MSTP, {'msti': [object()]}),
            (self.RSTP, {'root_id': self.BridgeID(priority=100, extension=0, address='00:00:00:00:00:00')}),
            (self.RSTP, {'root_id': bytes(7)}),
            (self.RSTP, {'root_id': 8}),
            (self.RSTP, {'port_id': self.PortID(priority=7, number=0)}),
            (self.RSTP, {'max_age': 1 / 512}),
            (self.RSTP, {'max_age': True}),
            (self.RSTP, {'max_age': 256}),
            (self.MSTP, {'msti': [dict(MST_MESSAGE, bridge_priority=100)]}),
            (self.MSTP, {'msti': [dict(MST_MESSAGE, port_priority=7)]}),
            (self.MSTP, {'config_id': bytes(50)}),
        )
        for klass, fields in refusals:
            with self.subTest(klass=klass.__name__, fields=sorted(fields)):
                with self.assertRaises(self.ProtocolError):
                    klass(**fields)

    def test_an_mst_bpdu_built_from_fields(self) -> None:
        mstp = self.STP(MST)
        built = self.MSTP(**{key: value for key, value in self.MSTP._make_data(mstp.info).items()
                             if key not in ('version_3_length', 'payload')})
        self.assertEqual(bytes(built), MST)
        by_octets = self.MSTP(config_id=MST[38:89], msti=[MST[102:118]], flags=MST[4],
                              cist_root_id=MST[5:13], cist_regional_root_id=MST[17:25])
        self.assertEqual(bytes(by_octets)[38:89], MST[38:89])
        self.assertEqual(bytes(by_octets)[102:], MST[102:])


#: An MSTI Configuration Message's fields, as a mapping, all zeros.
MST_MESSAGE = {
    'flags': 0, 'regional_root_id': bytes(8), 'internal_root_path_cost': 0, 'bridge_priority': 0,
    'bridge_reserved': 0, 'port_priority': 0, 'port_reserved': 0, 'remaining_hops': 0,
}


if __name__ == '__main__':
    unittest.main()
