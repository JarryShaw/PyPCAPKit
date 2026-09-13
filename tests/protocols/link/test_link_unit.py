from __future__ import annotations

import importlib.util
from ipaddress import ip_address
import types
import unittest
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class DummyData(dict):
    __getattr__ = dict.__getitem__


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class LinkProtocolUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_vlan_index_is_unsupported(self) -> None:
        from pcapkit.protocols.link.vlan import VLAN
        from pcapkit.utilities.exceptions import UnsupportedCall

        with self.assertRaises(UnsupportedCall):
            VLAN.__index__()

    def test_ethernet_index_and_length_hint_are_stable(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.link.ethernet import Ethernet

        proto = object.__new__(Ethernet)

        self.assertEqual(Ethernet.__index__(), LinkType.ETHERNET)
        self.assertEqual(proto.__length_hint__(), 14)

    def test_arp_id_index_and_length_hint_are_stable(self) -> None:
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.protocols.link.arp import ARP, InARP

        proto = object.__new__(ARP)

        self.assertEqual(ARP.id(), ('ARP',))
        self.assertEqual(InARP.id(), ('InARP',))
        self.assertEqual(ARP.__index__(), EtherType.Address_Resolution_Protocol)
        self.assertEqual(proto.__length_hint__(), 28)

    def test_rarp_ids_and_index_are_stable(self) -> None:
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.protocols.link.rarp import DRARP, RARP

        self.assertEqual(RARP.id(), ('RARP', 'DRARP'))
        self.assertEqual(DRARP.id(), ('DRARP',))
        self.assertEqual(RARP.__index__(), EtherType.Reverse_Address_Resolution_Protocol)

    def test_vlan_length_hint_is_stable(self) -> None:
        from pcapkit.protocols.link.vlan import VLAN

        proto = object.__new__(VLAN)

        self.assertEqual(proto.__length_hint__(), 4)

    def test_arp_cached_properties_expose_grouped_addresses_and_types(self) -> None:
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.const.arp.operation import Operation
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.protocols.link.arp import ARP

        arp = object.__new__(ARP)
        arp._info = types.SimpleNamespace(
            htype=Hardware.Ethernet,
            ptype=EtherType.Internet_Protocol_version_4,
            hlen=6,
            plen=4,
            oper=Operation.REQUEST,
            sha='00:11:22:33:44:55',
            spa='192.0.2.1',
            tha='66:77:88:99:aa:bb',
            tpa='192.0.2.2',
            len=28,
        )

        self.assertEqual(arp.length, 28)
        self.assertEqual(arp.src.hardware, '00:11:22:33:44:55')
        self.assertEqual(arp.src.protocol, '192.0.2.1')
        self.assertEqual(arp.dst.hardware, '66:77:88:99:aa:bb')
        self.assertEqual(arp.dst.protocol, '192.0.2.2')
        self.assertEqual(arp.type.hardware, Hardware.Ethernet)
        self.assertEqual(arp.type.protocol, EtherType.Internet_Protocol_version_4)

    def test_ethernet_make_data_preserves_core_fields(self) -> None:
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.protocols.link.ethernet import Ethernet

        data = DummyData(
            dst='aa:bb:cc:dd:ee:ff',
            src='11:22:33:44:55:66',
            type=EtherType.Address_Resolution_Protocol,
            __next_type__=None,
        )

        values = Ethernet._make_data(data)

        self.assertEqual(values['dst'], 'aa:bb:cc:dd:ee:ff')
        self.assertEqual(values['src'], '11:22:33:44:55:66')
        self.assertEqual(values['type'], EtherType.Address_Resolution_Protocol)
        self.assertIn('payload', values)

    def test_arp_index_and_make_data_preserve_expected_values(self) -> None:
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.const.arp.operation import Operation
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.protocols.link.arp import ARP

        data = DummyData(
            htype=Hardware.Ethernet,
            ptype=EtherType.Internet_Protocol_version_4,
            hlen=6,
            plen=4,
            oper=Operation.REPLY,
            sha='00:aa:bb:cc:dd:ee',
            spa='198.51.100.1',
            tha='11:22:33:44:55:66',
            tpa='198.51.100.2',
            __next_type__=None,
        )

        self.assertEqual(ARP.__index__(), EtherType.Address_Resolution_Protocol)
        values = ARP._make_data(data)
        self.assertEqual(values['oper'], Operation.REPLY)
        self.assertEqual(values['sha'], '00:aa:bb:cc:dd:ee')
        self.assertEqual(values['tpa'], '198.51.100.2')
        self.assertIn('payload', values)

    def test_arp_make_builds_schema_with_resolved_addresses(self) -> None:
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.const.arp.operation import Operation
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.protocols.link.arp import ARP

        proto = object.__new__(ARP)
        schema = proto.make(
            htype=Hardware.Ethernet,
            ptype=EtherType.Internet_Protocol_version_4,
            hlen=6,
            plen=4,
            oper=Operation.REPLY,
            sha='00:aa:bb:cc:dd:ee',
            spa='198.51.100.1',
            tha='11:22:33:44:55:66',
            tpa='198.51.100.2',
        )

        self.assertEqual(schema.htype, Hardware.Ethernet)
        self.assertEqual(schema.ptype, EtherType.Internet_Protocol_version_4)
        self.assertEqual(schema.oper, Operation.REPLY)
        self.assertEqual(schema.sha, b'00aabbccddee')
        self.assertEqual(schema.spa, b'\xc6\x33\x64\x01')
        self.assertEqual(schema.tha, b'112233445566')
        self.assertEqual(schema.tpa, b'\xc6\x33\x64\x02')

    def test_vlan_make_data_preserves_tci_and_type(self) -> None:
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.const.vlan.priority_level import PriorityLevel
        from pcapkit.protocols.link.vlan import VLAN

        class DummyTCI(dict):
            __getattr__ = dict.__getitem__

        class DummyData(dict):
            __getattr__ = dict.__getitem__

        data = DummyData(
            tci=DummyTCI(pcp=PriorityLevel.BE, dei=False, vid=100),
            type=EtherType.Internet_Protocol_version_6,
            __next_type__=None,
        )

        values = VLAN._make_data(data)
        self.assertEqual(values['tci']['pcp'], PriorityLevel.BE)
        self.assertEqual(values['tci']['dei'], False)
        self.assertEqual(values['tci']['vid'], 100)
        self.assertEqual(values['type'], EtherType.Internet_Protocol_version_6)
        self.assertIn('payload', values)

    def test_l2tp_index_is_unsupported_and_make_data_preserves_flags(self) -> None:
        from pcapkit.protocols.link.l2tp import L2TP
        from pcapkit.utilities.exceptions import UnsupportedCall

        data = DummyData(
            flags=DummyData(type=True, prio=False),
            version=2,
            length=32,
            tunnelid=3,
            sessionid=4,
            ns=5,
            nr=6,
            offset=0,
            __next_type__=None,
        )
        proto = object.__new__(L2TP)

        with self.assertRaises(UnsupportedCall):
            L2TP.__index__()
        self.assertEqual(proto.__length_hint__(), 16)
        values = L2TP._make_data(data)
        self.assertEqual(values['type'], True)
        self.assertEqual(values['prio'], False)
        self.assertEqual(values['version'], 2)
        self.assertEqual(values['tunnel_id'], 3)
        self.assertEqual(values['session_id'], 4)
        self.assertIn('payload', values)

    def test_ospf_index_is_unsupported_and_make_data_preserves_header(self) -> None:
        from pcapkit.const.ospf.packet import Packet
        from pcapkit.protocols.link.ospf import OSPF
        from pcapkit.utilities.exceptions import UnsupportedCall

        data = DummyData(
            version=2,
            type=Packet.Hello,
            router_id='192.0.2.1',
            area_id='0.0.0.0',
            chksum=b'\x12\x34',
            autype=0,
            auth=b'\x00' * 8,
            __next_type__=None,
        )
        proto = object.__new__(OSPF)

        with self.assertRaises(UnsupportedCall):
            OSPF.__index__()
        self.assertEqual(proto.__length_hint__(), 24)
        values = OSPF._make_data(data)
        self.assertEqual(values['version'], 2)
        self.assertEqual(values['type'], Packet.Hello)
        self.assertEqual(values['router_id'], '192.0.2.1')
        self.assertEqual(values['area_id'], '0.0.0.0')
        self.assertEqual(values['checksum'], b'\x12\x34')
        self.assertEqual(values['auth_data'], b'\x00' * 8)
        self.assertIn('payload', values)

    def test_link_schema_callbacks_resolve_payload_and_auth_fields(self) -> None:
        from pcapkit.const.ospf.authentication import Authentication
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.corekit.fields.misc import PayloadField, SchemaField
        from pcapkit.corekit.fields.strings import BytesField
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.schema.link.ethernet import callback_payload
        from pcapkit.protocols.schema.link.ospf import (
            CrytographicAuthentication,
            ospf_auth_data_selector,
        )

        custom_type = EtherType.get(0x88B5)
        registry = Ethernet.__proto__
        had_original = custom_type in registry
        original = registry.get(custom_type)
        try:
            direct_field = PayloadField()
            registry[custom_type] = Raw
            callback_payload(direct_field, {'type': custom_type})
            self.assertIs(direct_field.protocol, Raw)

            descriptor_field = PayloadField()
            registry[custom_type] = ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw')
            callback_payload(descriptor_field, {'type': custom_type})
            self.assertIs(descriptor_field.protocol, Raw)
        finally:
            if had_original:
                registry[custom_type] = original
            else:
                registry.pop(custom_type, None)

        crypto_field = ospf_auth_data_selector({
            'auth_type': Authentication.Cryptographic_authentication,
        })
        self.assertIsInstance(crypto_field, SchemaField)
        self.assertIs(crypto_field.schema, CrytographicAuthentication)

        plain_field = ospf_auth_data_selector({'auth_type': Authentication.No_Authentication})
        self.assertIsInstance(plain_field, BytesField)
        self.assertEqual(plain_field.length, 8)

    def test_link_base_layer_registry_and_protocol_reader(self) -> None:
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.protocols.link.link import Link
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities.exceptions import RegistryError

        link = object.__new__(Ethernet)
        link._read_unpack = mock.Mock(return_value=int(EtherType.Internet_Protocol_version_6))

        self.assertEqual(link.layer, 'Link')
        self.assertEqual(link._read_protos(2), EtherType.Internet_Protocol_version_6)

        registry = Link.__dict__['__proto__']
        custom_code = EtherType.get(0x88B5)
        original = registry.get(custom_code)
        try:
            Link.register(custom_code, ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'))
            self.assertIs(registry[custom_code], Raw)
            with mock.patch('pcapkit.protocols.link.link.warn') as warn:
                Link.register(custom_code, Raw)
            warn.assert_called_once()
            with self.assertRaises(RegistryError):
                Link.register(custom_code, object)
        finally:
            if original is None:
                registry.pop(custom_code, None)
            else:
                registry[custom_code] = original

    def test_ethernet_properties_read_make_and_mac_helpers(self) -> None:
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.protocols.schema.link.ethernet import Ethernet as SchemaEthernet
        from pcapkit.utilities.exceptions import ProtocolError

        ethernet = object.__new__(Ethernet)
        ethernet._info = types.SimpleNamespace(
            dst='aa:bb:cc:dd:ee:ff',
            src='11:22:33:44:55:66',
            type=EtherType.Address_Resolution_Protocol,
        )

        self.assertEqual(ethernet.name, 'Ethernet Protocol')
        self.assertEqual(ethernet.length, 14)
        self.assertEqual(ethernet.protocol, EtherType.Address_Resolution_Protocol)
        self.assertEqual(ethernet.src, '11:22:33:44:55:66')
        self.assertEqual(ethernet.dst, 'aa:bb:cc:dd:ee:ff')

        reader = object.__new__(Ethernet)
        reader.__cached__ = {}
        reader._data = b'\x00' * 60
        reader.__header__ = SchemaEthernet(
            dst=b'\xaa\xbb\xcc\xdd\xee\xff',
            src=b'\x11\x22\x33\x44\x55\x66',
            type=EtherType.Address_Resolution_Protocol,
            payload=b'arp',
        )
        reader._decode_next_layer = mock.Mock(side_effect=lambda data, proto, length: data)
        data = reader.read()
        self.assertEqual(data.dst, 'aa:bb:cc:dd:ee:ff')
        self.assertEqual(data.src, '11:22:33:44:55:66')
        reader._decode_next_layer.assert_called_once()

        maker = object.__new__(Ethernet)
        schema = maker.make(
            dst='aa-bb-cc-dd-ee-ff',
            src=b'11:22:33:44:55:66',
            type=EtherType.Internet_Protocol_version_6,
            payload=b'payload',
        )
        self.assertEqual(schema.dst, b'aabbccddeeff')
        self.assertEqual(schema.src, b'112233445566')
        self.assertEqual(schema.type, EtherType.Internet_Protocol_version_6)

        with mock.patch('pcapkit.protocols.link.ethernet.py38', False):
            self.assertEqual(maker._read_mac_addr(b'\xaa\xbb\xcc\xdd\xee\xff'),
                             'aa:bb:cc:dd:ee:ff')
        with self.assertRaises(ProtocolError):
            maker._make_mac_addr('not-a-mac')

    def test_arp_read_variants_and_address_resolution_helpers(self) -> None:
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.const.arp.operation import Operation
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.protocols.link.arp import ARP
        from pcapkit.protocols.schema.link.arp import ARP as SchemaARP
        from pcapkit.utilities.exceptions import ProtocolError

        def read_operation(oper: int) -> tuple[str, str]:
            proto = object.__new__(ARP)
            proto.__cached__ = {}
            proto._data = b'\x00' * 28
            proto.__header__ = SchemaARP(
                htype=Hardware.Ethernet,
                ptype=EtherType.Internet_Protocol_version_4,
                hlen=6,
                plen=4,
                oper=oper,
                sha=b'\x00\x11\x22\x33\x44\x55',
                spa=b'\xc0\x00\x02\x01',
                tha=b'\x66\x77\x88\x99\xaa\xbb',
                tpa=b'\xc0\x00\x02\x02',
                payload=b'',
            )
            proto._decode_next_layer = mock.Mock(side_effect=lambda data, proto, length: data)
            data = proto.read()
            self.assertEqual(str(data.spa), '192.0.2.1')
            self.assertEqual(str(data.tpa), '192.0.2.2')
            return proto.alias, proto.name

        self.assertEqual(read_operation(5), ('DRARP', 'Dynamic Reverse Address Resolution Protocol'))
        self.assertEqual(read_operation(8), ('InARP', 'Inverse Address Resolution Protocol'))
        self.assertEqual(read_operation(3), ('RARP', 'Reverse Address Resolution Protocol'))

        arp = object.__new__(ARP)
        self.assertEqual(arp._read_addr_resolve(b'\x01\x02', Hardware.Experimental_Ethernet), '0102')
        with mock.patch('pcapkit.protocols.link.arp.py38', False):
            self.assertEqual(arp._read_addr_resolve(b'\x00\x11\x22\x33\x44\x55', Hardware.Ethernet),
                             '00:11:22:33:44:55')
        self.assertEqual(arp._read_proto_resolve(b'\x20\x01\x0d\xb8' + b'\x00' * 12,
                                                 EtherType.Internet_Protocol_version_6),
                         ip_address('2001:db8::'))
        self.assertEqual(arp._read_proto_resolve(b'\x01\x02', EtherType.get(0x88B5)), '0102')

        self.assertEqual(arp._make_addr_resolve(b'raw', Hardware.Experimental_Ethernet), b'raw')
        with self.assertRaises(ProtocolError):
            arp._make_addr_resolve('not-a-mac', Hardware.Ethernet)

        self.assertEqual(arp._make_proto_resolve('2001:db8::1',
                                                 EtherType.Internet_Protocol_version_6),
                         ip_address('2001:db8::1').packed)
        self.assertEqual(arp._make_proto_resolve('raw', EtherType.get(0x88B5)), b'raw')
        self.assertEqual(arp._make_proto_resolve(ip_address('192.0.2.9'), EtherType.get(0x88B5)),
                         ip_address('192.0.2.9').packed)
        self.assertEqual(arp._make_proto_resolve(b'bytes', EtherType.get(0x88B5)), b'bytes')

        schema = arp.make(
            htype=Hardware.Experimental_Ethernet,
            ptype=EtherType.Internet_Protocol_version_6,
            hlen=3,
            plen=16,
            oper=Operation.REPLY,
            sha=b'abc',
            spa='2001:db8::1',
            tha=b'def',
            tpa='2001:db8::2',
        )
        self.assertEqual(schema.sha, b'abc')
        self.assertEqual(schema.spa, ip_address('2001:db8::1').packed)

    def test_l2tp_properties_read_and_make_variants(self) -> None:
        from pcapkit.const.l2tp.type import Type
        from pcapkit.protocols.link.l2tp import L2TP
        from pcapkit.protocols.schema.link.l2tp import L2TP as SchemaL2TP

        l2tp = object.__new__(L2TP)
        l2tp._info = types.SimpleNamespace(
            hdr_len=12,
            flags=types.SimpleNamespace(type=Type.Data),
        )

        self.assertEqual(l2tp.name, 'Layer 2 Tunnelling Protocol')
        self.assertEqual(l2tp.length, 12)
        self.assertEqual(l2tp.type, Type.Data)

        reader = object.__new__(L2TP)
        reader.__header__ = SchemaL2TP(
            flags={'type': Type.Control, 'len': True, 'seq': True, 'offset': True,
                   'prio': True, 'version': 2},
            length=24,
            tunnel_id=1,
            session_id=2,
            ns=3,
            nr=4,
            offset=2,
            payload=b'xxpayload',
        )
        reader._read_fileng = mock.Mock(return_value=b'\x00\x00')
        reader._decode_next_layer = mock.Mock(side_effect=lambda data, length: data)
        data = reader.read()
        self.assertTrue(data.flags.len)
        self.assertTrue(data.flags.seq)
        self.assertTrue(data.flags.offset)
        self.assertEqual(data.hdr_len, 16)
        reader._read_fileng.assert_called_once_with(2)

        reader_no_flags = object.__new__(L2TP)
        reader_no_flags.__cached__ = {}
        reader_no_flags._data = b'\x00' * 14
        reader_no_flags.__header__ = SchemaL2TP(
            flags={'type': Type.Data, 'len': False, 'seq': False, 'offset': False,
                   'prio': False, 'version': 2},
            length=None,
            tunnel_id=5,
            session_id=6,
            ns=None,
            nr=None,
            offset=None,
            payload=b'payload',
        )
        reader_no_flags._decode_next_layer = mock.Mock(side_effect=lambda data, length: data)
        data_no_flags = reader_no_flags.read()
        self.assertIsNone(data_no_flags.length)
        self.assertIsNone(data_no_flags.ns)
        self.assertIsNone(data_no_flags.offset)
        self.assertEqual(data_no_flags.hdr_len, 6)

        maker = object.__new__(L2TP)
        schema = maker.make(
            type=Type.Control,
            priority=True,
            length=20,
            tunnel_id=7,
            session_id=8,
            ns=9,
            nr=10,
            offset=2,
            payload=b'payload',
        )
        self.assertTrue(schema.flags['len'])
        self.assertTrue(schema.flags['seq'])
        self.assertTrue(schema.flags['offset'])
        self.assertTrue(schema.flags['prio'])
        self.assertEqual(schema.tunnel_id, 7)

    def test_vlan_properties_read_and_make_variants(self) -> None:
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.const.vlan.priority_level import PriorityLevel
        from pcapkit.protocols.link.vlan import VLAN
        from pcapkit.protocols.schema.link.vlan import TCI as SchemaTCI
        from pcapkit.protocols.schema.link.vlan import VLAN as SchemaVLAN

        vlan = object.__new__(VLAN)
        vlan._info = types.SimpleNamespace(type=EtherType.Internet_Protocol_version_4)

        self.assertEqual(vlan.name, '802.1Q Customer VLAN Tag Type')
        self.assertEqual(vlan.alias, '802.1Q')
        self.assertEqual(vlan.info_name, 'c_tag')
        self.assertEqual(vlan.length, 4)
        self.assertEqual(vlan.protocol, EtherType.Internet_Protocol_version_4)

        reader = object.__new__(VLAN)
        reader.__cached__ = {}
        reader._data = b'\x00' * 18
        reader.__header__ = SchemaVLAN(
            tci={'pcp': PriorityLevel.EE, 'dei': True, 'vid': 4094},
            type=EtherType.Internet_Protocol_version_6,
            payload=b'payload',
        )
        reader._decode_next_layer = mock.Mock(side_effect=lambda data, proto, length: data)
        data = reader.read()
        self.assertEqual(data.tci.pcp, PriorityLevel.EE)
        self.assertTrue(data.tci.dei)
        self.assertEqual(data.tci.vid, 4094)
        self.assertEqual(data.type, EtherType.Internet_Protocol_version_6)

        explicit_length = object.__new__(VLAN)
        explicit_length.__header__ = reader.__header__
        explicit_length._decode_next_layer = mock.Mock(side_effect=lambda data, proto, length: data)
        self.assertEqual(explicit_length.read(64).type, EtherType.Internet_Protocol_version_6)
        explicit_length._decode_next_layer.assert_called_once()

        maker = object.__new__(VLAN)
        schema = maker.make(
            pcp=PriorityLevel.CA,
            dei=True,
            vid=100,
            type=EtherType.Internet_Protocol_version_6,
            payload=b'payload',
        )
        self.assertEqual(schema.tci['pcp'], PriorityLevel.CA)
        self.assertTrue(schema.tci['dei'])
        self.assertEqual(schema.tci['vid'], 100)

        explicit_schema = maker.make(
            tci=SchemaTCI(pcp=PriorityLevel.VI, dei=False, vid=200),
            type=EtherType.Address_Resolution_Protocol,
        )
        self.assertEqual(explicit_schema.tci['pcp'], PriorityLevel.VI)
        self.assertFalse(explicit_schema.tci['dei'])
        self.assertEqual(explicit_schema.type, EtherType.Address_Resolution_Protocol)

    def test_ospf_properties_read_make_and_auth_helpers(self) -> None:
        from pcapkit.const.ospf.authentication import Authentication
        from pcapkit.const.ospf.packet import Packet
        from pcapkit.protocols.data.link.ospf import \
            CrytographicAuthentication as DataCryptoAuth
        from pcapkit.protocols.link.ospf import OSPF
        from pcapkit.protocols.schema.link.ospf import \
            CrytographicAuthentication as SchemaCryptoAuth
        from pcapkit.protocols.schema.link.ospf import OSPF as SchemaOSPF
        from pcapkit.utilities.exceptions import ProtocolError

        ospf = object.__new__(OSPF)
        ospf._info = types.SimpleNamespace(version=2, type=Packet.Hello)

        self.assertEqual(ospf.name, 'Open Shortest Path First version 2')
        self.assertEqual(ospf.alias, 'OSPFv2')
        self.assertEqual(ospf.length, 24)
        self.assertEqual(ospf.type, Packet.Hello)

        reader = object.__new__(OSPF)
        reader.__schema__ = SchemaOSPF(
            version=2,
            type=Packet.Database_Description,
            length=24,
            router_id='192.0.2.1',
            area_id='0.0.0.0',
            checksum=b'\x12\x34',
            auth_type=Authentication.No_Authentication,
            auth_data=b'\x00' * 8,
            payload=b'',
        )
        reader._decode_next_layer = mock.Mock(side_effect=lambda data, length: data)
        data = reader.read()
        self.assertEqual(data.auth, b'\x00' * 8)
        self.assertEqual(str(data.router_id), '192.0.2.1')

        crypto_schema = SchemaCryptoAuth(key_id=1, len=16, seq=99)
        crypto_reader = object.__new__(OSPF)
        crypto_reader.__schema__ = SchemaOSPF(
            version=2,
            type=Packet.Link_State_Request,
            length=0,
            router_id='192.0.2.2',
            area_id='0.0.0.1',
            checksum=b'\xab\xcd',
            auth_type=Authentication.Cryptographic_authentication,
            auth_data=crypto_schema,
            payload=b'payload',
        )
        crypto_reader.__cached__ = {}
        crypto_reader._data = b'\x00' * 32
        crypto_reader._decode_next_layer = mock.Mock(side_effect=lambda data, length: data)
        crypto_data = crypto_reader.read()
        self.assertEqual(crypto_data.auth.key_id, 1)
        self.assertEqual(crypto_data.auth.seq, 99)

        maker = object.__new__(OSPF)
        schema = maker.make(
            version=3,
            type=Packet.Link_State_Update,
            router_id='192.0.2.3',
            area_id='0.0.0.2',
            checksum=b'\x56\x78',
            auth_type=Authentication.No_Authentication,
            auth_data=b'\x01' * 8,
            payload=b'abcd',
        )
        self.assertEqual(schema.length, 28)
        self.assertEqual(schema.auth_data, b'\x01' * 8)

        crypto_data_model = DataCryptoAuth(key_id=2, len=20, seq=100)
        crypto_schema_from_data = maker.make(
            auth_type=Authentication.Cryptographic_authentication,
            auth_data=crypto_data_model,
        )
        self.assertEqual(crypto_schema_from_data.auth_data.key_id, 2)
        self.assertIs(maker._make_encrypt_auth(crypto_schema), crypto_schema)
        self.assertEqual(maker._make_encrypt_auth(b'\x02' * 8), b'\x02' * 8)
        self.assertEqual(maker._read_encrypt_auth(crypto_schema).len, 16)
        self.assertEqual(maker._read_id_numbers(b'\xc0\x00\x02\x04'), ip_address('192.0.2.4'))
        self.assertEqual(maker._make_id_numbers('192.0.2.5'), b'\xc0\x00\x02\x05')

        with self.assertRaises(ProtocolError):
            maker.make(auth_type=Authentication.No_Authentication, auth_data=crypto_data_model)
        with self.assertRaises(ProtocolError):
            maker._make_encrypt_auth(object())


if __name__ == '__main__':
    unittest.main()
