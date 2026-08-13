from __future__ import annotations

import importlib.util
import collections
import copy
import datetime
import decimal
import io
from ipaddress import ip_address, ip_interface
import types
import unittest
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class DummyData(dict):
    __getattr__ = dict.__getitem__

    def __update__(self, *values, **kwargs):
        for value in values:
            self.update(value)
        self.update(kwargs)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PCAPNGUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_pcapng_index_length_and_make_data(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import UnsupportedCall

        pcapng = object.__new__(PCAPNG)
        pcapng._fnum = 5
        pcapng._info = DummyData(type=BlockType.Enhanced_Packet_Block)
        data = DummyData(type=BlockType.Section_Header_Block)

        self.assertEqual(pcapng.__length_hint__(), 12)
        self.assertEqual(pcapng.__index__(), 5)
        self.assertEqual(
            PCAPNG._make_data(data),
            {'type': BlockType.Section_Header_Block, 'block': data},
        )

        pcapng._info = DummyData(type=BlockType.Section_Header_Block)
        with self.assertRaises(UnsupportedCall):
            pcapng.__index__()
        with self.assertRaises(UnsupportedCall):
            PCAPNG.__index__()

    def test_pcapng_registry_overwrites_warn(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.const.pcapng.record_type import RecordType
        from pcapkit.const.pcapng.secrets_type import SecretsType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        block_map = PCAPNG.__dict__['__block__']
        option_map = PCAPNG.__dict__['__option__']
        record_map = PCAPNG.__dict__['__record__']
        secrets_map = PCAPNG.__dict__['__secrets__']
        originals = (
            block_map[BlockType.Section_Header_Block],
            option_map[OptionType.opt_endofopt],
            record_map[RecordType.nrb_record_end],
            secrets_map[SecretsType.TLS_Key_Log],
        )
        try:
            with mock.patch('pcapkit.protocols.misc.pcapng.warn') as warn:
                PCAPNG.register_block(BlockType.Section_Header_Block, 'shb')
                PCAPNG.register_option(OptionType.opt_endofopt, 'endofopt')
                PCAPNG.register_record(RecordType.nrb_record_end, 'end')
                PCAPNG.register_secrets(SecretsType.TLS_Key_Log, 'tls')

            self.assertEqual(warn.call_count, 4)
            self.assertEqual(block_map[BlockType.Section_Header_Block], 'shb')
            self.assertEqual(option_map[OptionType.opt_endofopt], 'endofopt')
            self.assertEqual(record_map[RecordType.nrb_record_end], 'end')
            self.assertEqual(secrets_map[SecretsType.TLS_Key_Log], 'tls')
        finally:
            block_map[BlockType.Section_Header_Block] = originals[0]
            option_map[OptionType.opt_endofopt] = originals[1]
            record_map[RecordType.nrb_record_end] = originals[2]
            secrets_map[SecretsType.TLS_Key_Log] = originals[3]

    def test_pcapng_simple_packet_block_populates_default_interface_and_timestamp(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.data.misc.pcapng import SimplePacketBlock

        block = SimplePacketBlock(
            type=BlockType.Simple_Packet_Block,
            length=32,
            section_number=1,
            number=2,
            original_len=20,
            captured_len=16,
        )

        self.assertEqual(block.to_dict()['interface_id'], 0)
        self.assertEqual(block.to_dict()['timestamp_epoch'], decimal.Decimal(0))
        self.assertEqual(
            block.to_dict()['timestamp'],
            datetime.datetime.fromtimestamp(0, datetime.timezone.utc),
        )

    def test_pcapng_name_resolution_block_builds_forward_and_reverse_maps(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.const.pcapng.record_type import RecordType
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.data.misc.pcapng import (CommentOption, IPv4Record, IPv6Record,
                                                        NameResolutionBlock, UnknownRecord)

        ipv4 = IPv4Record(
            type=RecordType.nrb_record_ipv4,
            length=18,
            ip=ip_address('192.0.2.1'),
            records=('example.test', 'alias.test'),
        )
        ipv6 = IPv6Record(
            type=RecordType.nrb_record_ipv6,
            length=28,
            ip=ip_address('2001:db8::1'),
            records=('v6.example.test',),
        )
        unknown_type = RecordType.get(3)
        unknown = UnknownRecord(type=unknown_type, length=3, data=b'raw')
        records = OrderedMultiDict([
            (RecordType.nrb_record_ipv4, ipv4),
            (RecordType.nrb_record_ipv6, ipv6),
            (unknown_type, unknown),
        ])
        options = OrderedMultiDict([
            (OptionType.opt_comment, CommentOption(type=OptionType.opt_comment, length=7, comment='comment')),
        ])

        block = NameResolutionBlock(
            type=BlockType.Name_Resolution_Block,
            length=64,
            records=records,
            options=options,
        )
        mapping = block.to_dict()['mapping']
        reverse_mapping = block.to_dict()['reverse_mapping']

        self.assertEqual(mapping.getlist(ip_address('192.0.2.1')), ['example.test', 'alias.test'])
        self.assertEqual(mapping.getlist(ip_address('2001:db8::1')), ['v6.example.test'])
        self.assertEqual(reverse_mapping.getlist('example.test'), [ip_address('192.0.2.1')])
        self.assertEqual(reverse_mapping.getlist('v6.example.test'), [ip_address('2001:db8::1')])

    def test_pcapng_context_timestamp_and_address_helpers(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.data.misc.pcapng import (IF_TSOffsetOption, IF_TSResolOption,
                                                        IF_TZoneOption)
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

        pcapng = object.__new__(PCAPNG)
        pcapng._ctx = None
        pcapng._type = BlockType.Enhanced_Packet_Block

        self.assertEqual(pcapng._get_resolution(), 1_000_000)
        self.assertEqual(pcapng._get_offset(), 0)
        self.assertIsInstance(pcapng._get_timezone(), datetime.timezone)
        with self.assertRaises(UnsupportedCall):
            _ = pcapng.linktype

        tz = datetime.timezone(datetime.timedelta(hours=1))
        options = {
            OptionType.if_tsresol: IF_TSResolOption(type=OptionType.if_tsresol, length=1, resolution=1000),
            OptionType.if_tsoffset: IF_TSOffsetOption(type=OptionType.if_tsoffset, length=8, offset=10),
            OptionType.if_tzone: IF_TZoneOption(type=OptionType.if_tzone, length=4, timezone=tz),
        }
        interface = types.SimpleNamespace(options=options, linktype=LinkType.ETHERNET, snaplen=65535)
        pcapng._ctx = types.SimpleNamespace(
            interfaces=[interface],
            section=types.SimpleNamespace(byteorder='little'),
        )
        pcapng._info = DummyData(interface_id=0)

        self.assertEqual(pcapng.ts_resolution, 1000)
        self.assertEqual(pcapng.ts_offset, 10)
        self.assertEqual(pcapng.ts_timezone, tz)
        self.assertEqual(pcapng.linktype, LinkType.ETHERNET)
        self.assertEqual(pcapng._make_timestamp(decimal.Decimal(12)), (0, 2000))

        ts_datetime, ts_decimal = pcapng._read_timestamp(0, 2000)
        self.assertEqual(ts_datetime, datetime.datetime.fromtimestamp(12, tz))
        self.assertEqual(ts_decimal, decimal.Decimal(3612))

        self.assertEqual(pcapng._read_mac_addr(b'\x00\x01\x02\x03\x04\x05'), '00:01:02:03:04:05')
        self.assertEqual(pcapng._read_eui_addr(bytes.fromhex('023456fffe789abc')),
                         '02:34:56:ff:fe:78:9a:bc')
        self.assertEqual(pcapng._make_mac_addr('00:01:02:03:04:05'), b'000102030405')
        self.assertEqual(pcapng._make_mac_addr(b'00-01-02-03-04-05'), b'000102030405')
        self.assertEqual(pcapng._make_eui_addr('02:34:56:ff:fe:78:9a:bc'), b'023456fffe789abc')
        with self.assertRaises(ProtocolError):
            pcapng._make_mac_addr('bad')
        with self.assertRaises(ProtocolError):
            pcapng._make_eui_addr('bad')

    def test_pcapng_top_level_properties_registry_and_dispatch_paths(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.const.pcapng.record_type import RecordType
        from pcapkit.const.pcapng.secrets_type import SecretsType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.data.misc.pcapng import IF_TSOffsetOption, IF_TSResolOption, IF_TZoneOption
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.schema.misc.pcapng import (PCAPNG as Schema_PCAPNG,
                                                          SectionHeaderBlock,
                                                          SimplePacketBlock,
                                                          UnknownBlock)
        from pcapkit.utilities.exceptions import ProtocolError, RegistryError, UnsupportedCall

        pcapng = object.__new__(PCAPNG)
        pcapng._sect = 2
        pcapng._fnum = 7
        pcapng._type = BlockType.Section_Header_Block
        pcapng._byte = 'little'
        pcapng._ctx = None
        pcapng._info = DummyData(type=BlockType.Section_Header_Block, length=28)
        pcapng._protos = types.SimpleNamespace(index=lambda name: 33)

        self.assertEqual(pcapng.name, 'PCAP-NG <BlockType.Section_Header_Block: 168627466> - Section 2')
        self.assertEqual(pcapng.length, 28)
        self.assertEqual(pcapng.byteorder, 'little')
        self.assertEqual(pcapng.block, BlockType.Section_Header_Block)
        self.assertEqual(pcapng.index('Raw'), 33)
        with self.assertRaises(UnsupportedCall):
            _ = pcapng.context
        with mock.patch('pcapkit.protocols.misc.pcapng.warn') as warn:
            self.assertEqual(pcapng.ts_resolution, 1_000_000)
            self.assertEqual(pcapng.ts_offset, 0)
            self.assertIsInstance(pcapng.ts_timezone, datetime.timezone)
        self.assertEqual(warn.call_count, 3)

        pcapng._info = DummyData(type=BlockType.Simple_Packet_Block, length=20, interface_id=0)
        self.assertEqual(pcapng.name, 'Frame 2-7')

        tz = datetime.timezone(datetime.timedelta(hours=2))
        high_res = IF_TSResolOption(type=OptionType.if_tsresol, length=1, resolution=1_000_000_000)
        offset = IF_TSOffsetOption(type=OptionType.if_tsoffset, length=8, offset=2)
        tzone = IF_TZoneOption(type=OptionType.if_tzone, length=4, timezone=tz)
        interface = types.SimpleNamespace(
            linktype=LinkType.NULL,
            snaplen=65535,
            options={
                OptionType.if_tsresol: high_res,
                OptionType.if_tsoffset: offset,
                OptionType.if_tzone: tzone,
            },
        )
        ctx = types.SimpleNamespace(interfaces=[interface], section=types.SimpleNamespace(byteorder='big'))
        pcapng._ctx = ctx
        pcapng._type = BlockType.Enhanced_Packet_Block
        pcapng._info = DummyData(type=BlockType.Enhanced_Packet_Block, length=32, interface_id=0)
        self.assertIs(pcapng.context, ctx)
        self.assertTrue(pcapng.nanosecond)
        self.assertEqual(pcapng.linktype, LinkType.NULL)
        self.assertEqual(pcapng._get_linktype(0), LinkType.NULL)
        self.assertEqual(pcapng._get_resolution(0), 1_000_000_000)
        self.assertEqual(pcapng._get_offset(0), 2)
        self.assertEqual(pcapng._get_timezone(0), tz)

        empty_ctx = types.SimpleNamespace(
            interfaces=[types.SimpleNamespace(linktype=LinkType.ETHERNET, snaplen=65535, options={})],
            section=types.SimpleNamespace(byteorder='little'),
        )
        pcapng._ctx = empty_ctx
        self.assertEqual(pcapng._get_resolution(0), 1_000_000)
        self.assertEqual(pcapng._get_offset(0), 0)
        self.assertIsInstance(pcapng._get_timezone(0), datetime.timezone)
        pcapng._ctx = None
        with self.assertRaises(UnsupportedCall):
            pcapng._get_linktype(0)

        class NoTimezoneDateTime:
            @classmethod
            def now(cls, tz):
                return types.SimpleNamespace(
                    astimezone=lambda: types.SimpleNamespace(tzinfo=None),
                )

        with mock.patch('pcapkit.protocols.misc.pcapng.datetime.datetime', NoTimezoneDateTime):
            self.assertEqual(PCAPNG._get_local_timezone(), datetime.timezone.utc)

        real_datetime = datetime.datetime

        class FakeDateTime:
            calls = 0

            @classmethod
            def fromtimestamp(cls, *args):
                if cls.calls == 0:
                    cls.calls += 1
                    raise ValueError
                return real_datetime.fromtimestamp(*args)

        pcapng._ctx = types.SimpleNamespace(interfaces=[interface],
                                            section=types.SimpleNamespace(byteorder='little'))
        pcapng._type = BlockType.Enhanced_Packet_Block
        with mock.patch('pcapkit.protocols.misc.pcapng.datetime.datetime', FakeDateTime), \
                mock.patch('pcapkit.protocols.misc.pcapng.warn') as warn:
            timestamp, epoch = pcapng._read_timestamp(0, 1, interface_id=0)
        self.assertEqual(timestamp, real_datetime.fromtimestamp(0, datetime.timezone.utc))
        self.assertEqual(epoch, decimal.Decimal(7200) + decimal.Decimal(2) + decimal.Decimal('0.000000001'))
        warn.assert_called_once()

        with mock.patch('pcapkit.protocols.misc.pcapng.time.time_ns', return_value=3_500_000_000):
            self.assertEqual(pcapng._make_timestamp(interface_id=0), (0, 1_500_000_000))
        low_res = IF_TSResolOption(type=OptionType.if_tsresol, length=1, resolution=1_000_000)
        interface.options[OptionType.if_tsresol] = low_res
        with mock.patch('pcapkit.protocols.misc.pcapng.time.time', return_value=5.25):
            self.assertEqual(pcapng._make_timestamp(interface_id=0), (0, 3_250_000))
        instant = datetime.datetime.fromtimestamp(6, datetime.timezone.utc)
        self.assertEqual(pcapng._make_timestamp(instant, interface_id=0), (0, 4_000_000))

        with mock.patch('pcapkit.protocols.misc.pcapng.py38', False):
            self.assertEqual(pcapng._read_mac_addr(b'\x00\x01\x02\x03\x04\x05'), '00:01:02:03:04:05')
            self.assertEqual(pcapng._read_eui_addr(bytes.fromhex('023456fffe789abc')),
                             '02:34:56:ff:fe:78:9a:bc')

        proto_map = PCAPNG.__dict__['__proto__']
        block_map = PCAPNG.__dict__['__block__']
        option_map = PCAPNG.__dict__['__option__']
        record_map = PCAPNG.__dict__['__record__']
        secrets_map = PCAPNG.__dict__['__secrets__']
        proto_code = LinkType.USER0
        custom_block = 65000
        custom_option = 65000
        custom_record = 65000
        custom_secrets = 65000
        originals = {
            'proto': (proto_code in proto_map, proto_map.get(proto_code)),
            'block': (custom_block in block_map, block_map.get(custom_block)),
            'option': (custom_option in option_map, option_map.get(custom_option)),
            'record': (custom_record in record_map, record_map.get(custom_record)),
            'secrets': (custom_secrets in secrets_map, secrets_map.get(custom_secrets)),
        }

        def read_block(block, *, header):
            return DummyData(type=header.type, length=block.length, body=block.body)

        def make_block(block=None, *, body=b'custom'):
            if block is not None:
                body = block.body
            return UnknownBlock(length=12 + len(body), body=body, length2=12 + len(body))

        try:
            PCAPNG.register(proto_code, ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'))
            self.assertIs(proto_map[proto_code], Raw)
            with mock.patch('pcapkit.protocols.misc.pcapng.warn') as warn:
                PCAPNG.register(proto_code, Raw)
            warn.assert_called_once()
            with self.assertRaises(RegistryError):
                PCAPNG.register(LinkType.USER1, object)  # type: ignore[arg-type]

            with mock.patch('pcapkit.protocols.misc.pcapng.warn') as warn:
                PCAPNG.register_block(custom_block, (read_block, make_block))
                PCAPNG.register_option(custom_option, 'unknown')
                PCAPNG.register_record(custom_record, 'unknown')
                PCAPNG.register_secrets(custom_secrets, 'unknown')
            warn.assert_not_called()

            pcapng._ctx = empty_ctx
            pcapng._opt = collections.Counter()
            pcapng._file = io.BytesIO(b'\x00' * 16)
            custom_schema = Schema_PCAPNG(
                type=custom_block,
                block=UnknownBlock(length=16, body=b'abcd', length2=16),
            )
            pcapng.__header__ = custom_schema
            custom_read = pcapng.read(_read=False)
            self.assertEqual(custom_read.body, b'abcd')
            self.assertEqual(pcapng._file.tell(), 0)

            custom_make = pcapng.make(type=custom_block, block={'body': b'made'})
            self.assertEqual(custom_make.block.body, b'made')
            data_make = pcapng.make(type=custom_block, block=DummyData(body=b'data'))
            self.assertEqual(data_make.block.body, b'data')
        finally:
            for mapping, key, original in (
                (proto_map, proto_code, originals['proto']),
                (block_map, custom_block, originals['block']),
                (option_map, custom_option, originals['option']),
                (record_map, custom_record, originals['record']),
                (secrets_map, custom_secrets, originals['secrets']),
            ):
                existed, value = original
                if existed:
                    mapping[key] = value
                else:
                    mapping.pop(key, None)

        pcapng._ctx = empty_ctx
        pcapng._opt = collections.Counter()
        spb_schema = Schema_PCAPNG(
            type=BlockType.Simple_Packet_Block,
            block=SimplePacketBlock(length=20, original_len=4, packet_data=b'abcd', length2=20),
        )
        spb_data = spb_schema.pack({'byteorder': 'little'})
        reader = object.__new__(PCAPNG)
        reader.__header__ = spb_schema
        reader._sect = 1
        reader._fnum = 2
        reader._ctx = empty_ctx
        reader._opt = collections.Counter()
        reader._file = io.BytesIO(spb_data)
        reader._decode_next_layer = lambda data, proto=None, length=None, packet=None: data
        self.assertEqual(reader.read(_read=True, _seek_set=0).captured_len, 4)
        self.assertEqual(len(reader._data), 20)

        invalid = object.__new__(PCAPNG)
        invalid.__header__ = Schema_PCAPNG(
            type=BlockType.Simple_Packet_Block,
            block=SimplePacketBlock(length=10, original_len=4, packet_data=b'abcd', length2=10),
        )
        invalid._file = io.BytesIO(b'')
        with self.assertRaises(ProtocolError):
            invalid.read(_read=False)
        invalid.__header__.block.length = 14
        with self.assertRaises(ProtocolError):
            invalid.read(_read=False)

        shb_reader = object.__new__(PCAPNG)
        shb_reader.__header__ = Schema_PCAPNG(
            type=BlockType.Section_Header_Block,
            block=SectionHeaderBlock(length=28, magic=0x1A2B3C4D, major=1, minor=0,
                                     section_length=-1, options=[], length2=28),
        )
        object.__setattr__(shb_reader.__header__.block, 'byteorder', 'little')
        shb_reader._sect = 0
        shb_reader._fnum = 0
        shb_reader._ctx = empty_ctx
        shb_reader._opt = collections.Counter()
        shb_reader._file = io.BytesIO(b'\x00' * 28)
        shb_parsed = shb_reader.read(_read=False)
        self.assertEqual(shb_reader._sect, 1)
        self.assertEqual(shb_parsed.version.major, 1)
        self.assertIsNone(shb_reader._ctx)

        made_bytes = pcapng.make(type=BlockType.Simple_Packet_Block, block=b'raw')
        self.assertEqual(made_bytes.block, b'raw')
        made_schema = pcapng.make(type=BlockType.Simple_Packet_Block,
                                  block=spb_schema.block)
        self.assertIs(made_schema.block, spb_schema.block)
        with self.assertRaises(ProtocolError):
            pcapng.make(type=BlockType.Simple_Packet_Block, block=object())

        packer = object.__new__(PCAPNG)
        packer._ctx = empty_ctx
        packer._opt = collections.Counter()
        packed = packer.pack(type=BlockType.Simple_Packet_Block,
                             block={'packet_data': b'abcd'})
        self.assertEqual(packer._byte, 'little')
        self.assertTrue(packed.startswith(int(BlockType.Simple_Packet_Block).to_bytes(4, 'little')))
        packer.__header__ = types.SimpleNamespace(block=types.SimpleNamespace(get_payload=lambda: b'payload'))
        self.assertEqual(packer._get_payload(), b'payload')

        decoded = DummyData()
        chain = types.SimpleNamespace(chain='PCAPNG:Raw')
        fake_next = types.SimpleNamespace(info='payload-info', protochain=chain, info_name='Raw')
        pcapng._import_next_layer = mock.Mock(return_value=fake_next)
        self.assertIs(pcapng._decode_next_layer(decoded, LinkType.NULL, 0), decoded)
        self.assertEqual(decoded['Raw'], 'payload-info')
        self.assertEqual(decoded['protocols'], 'PCAPNG:Raw')
        self.assertIs(decoded['__next_type__'], type(fake_next))
        self.assertEqual(decoded['__next_name__'], 'Raw')
        self.assertIs(pcapng._next, fake_next)
        self.assertIs(pcapng._protos, chain)

        decoded_no_chain = DummyData()
        fake_next_no_chain = types.SimpleNamespace(info='payload-info', protochain=None, info_name='Raw')
        pcapng._import_next_layer = mock.Mock(return_value=fake_next_no_chain)
        self.assertIs(pcapng._decode_next_layer(decoded_no_chain, LinkType.NULL, 0), decoded_no_chain)
        self.assertEqual(decoded_no_chain['protocols'], '')

    def test_pcapng_interface_option_constructors_and_scope_guards(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import ProtocolError

        pcapng = object.__new__(PCAPNG)
        pcapng._type = BlockType.Interface_Description_Block
        pcapng._opt = collections.Counter()

        self.assertEqual(pcapng._make_option_unknown(OptionType.get(65000),
                                                     data=b'x').to_dict()['data'], b'x')
        self.assertEqual(pcapng._make_option_endofopt(OptionType.opt_endofopt).to_dict()['length'], 0)
        self.assertEqual(pcapng._make_option_comment(OptionType.opt_comment,
                                                     comment='hi').to_dict()['comment'], 'hi')
        self.assertEqual(pcapng._make_option_custom(OptionType.opt_custom_2988, pen=1,
                                                    data=b'data').to_dict()['length'], 8)
        self.assertEqual(pcapng._make_option_if_name(OptionType.if_name,
                                                     name='eth0').to_dict()['name'], 'eth0')
        self.assertEqual(pcapng._make_option_if_description(OptionType.if_description,
                                                            description='desc').to_dict()['description'], 'desc')
        self.assertEqual(pcapng._make_option_if_ipv4(OptionType.if_IPv4addr,
                                                     interface='192.0.2.1/24').to_dict()['length'], 8)
        self.assertEqual(pcapng._make_option_if_ipv6(OptionType.if_IPv6addr,
                                                     interface='2001:db8::1/64').to_dict()['length'], 8)
        self.assertEqual(pcapng._make_option_if_mac(OptionType.if_MACaddr,
                                                    interface='00:01:02:03:04:05').to_dict()['interface'],
                         b'000102030405')
        self.assertEqual(pcapng._make_option_if_eui(OptionType.if_EUIaddr,
                                                    interface='02:34:56:ff:fe:78:9a:bc').to_dict()['interface'],
                         b'023456fffe789abc')
        self.assertEqual(pcapng._make_option_if_speed(OptionType.if_speed,
                                                      speed=1000).to_dict()['speed'], 1000)
        self.assertEqual(pcapng._make_option_if_tsresol(OptionType.if_tsresol,
                                                        resolution=1_000_000).to_dict()['tsresol'],
                         {'flag': 0, 'resolution': 6})
        self.assertEqual(pcapng._make_option_if_tsresol(OptionType.if_tsresol,
                                                        resolution=1024).to_dict()['tsresol'],
                         {'flag': 1, 'resolution': 10})
        self.assertEqual(pcapng._make_option_if_tzone(OptionType.if_tzone,
                                                      tzone=datetime.timedelta(hours=2)).to_dict()['tzone'], 7200)
        self.assertEqual(pcapng._make_option_if_filter(OptionType.if_filter, filter=0,
                                                       expression='tcp').to_dict()['filter'], b'tcp')
        self.assertEqual(pcapng._make_option_if_os(OptionType.if_os, os='OS').to_dict()['os'], 'OS')
        self.assertEqual(pcapng._make_option_if_fcslen(OptionType.if_fcslen,
                                                       fcs_length=4).to_dict()['fcslen'], 4)
        self.assertEqual(pcapng._make_option_if_tsoffset(OptionType.if_tsoffset,
                                                         offset=9).to_dict()['tsoffset'], 9)
        self.assertEqual(pcapng._make_option_if_hardware(OptionType.if_hardware,
                                                         hardware='hw').to_dict()['hardware'], 'hw')
        self.assertEqual(pcapng._make_option_if_txspeed(OptionType.if_txspeed,
                                                        speed=10).to_dict()['tx_speed'], 10)
        self.assertEqual(pcapng._make_option_if_rxspeed(OptionType.if_rxspeed,
                                                        speed=20).to_dict()['rx_speed'], 20)

        pcapng._opt[OptionType.opt_endofopt] = 1
        with self.assertRaises(ProtocolError):
            pcapng._make_option_endofopt(OptionType.opt_endofopt)

        pcapng._opt = collections.Counter({OptionType.if_name: 1})
        with self.assertRaises(ProtocolError):
            pcapng._make_option_if_name(OptionType.if_name, name='eth1')

        pcapng._opt = collections.Counter()
        with self.assertRaises(ProtocolError):
            pcapng._make_option_if_tsresol(OptionType.if_tsresol, resolution=12)
        with self.assertRaises(ProtocolError):
            pcapng._make_option_if_tzone(OptionType.if_tzone, tzone=object())

        pcapng._type = BlockType.Section_Header_Block
        with self.assertRaises(ProtocolError):
            pcapng._make_option_if_name(OptionType.if_name, name='eth0')

    def test_pcapng_option_readers_cover_block_families_and_guards(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.filter_type import FilterType
        from pcapkit.const.pcapng.hash_algorithm import HashAlgorithm
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.const.pcapng.verdict_type import VerdictType
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.misc.pcapng import PCAPNG, PacketDirection, PacketReception
        from pcapkit.protocols.schema.misc.pcapng import (CommentOption, CustomOption, EndOfOption,
                                                          EPB_DropCountOption, EPB_FlagsOption,
                                                          EPB_HashOption, EPB_PacketIDOption,
                                                          EPB_QueueOption, EPB_VerdictOption,
                                                          IF_DescriptionOption, IF_EUIAddrOption,
                                                          IF_FCSLenOption, IF_FilterOption,
                                                          IF_HardwareOption, IF_IPv4AddrOption,
                                                          IF_IPv6AddrOption, IF_MACAddrOption,
                                                          IF_NameOption, IF_OSOption,
                                                          IF_RxSpeedOption, IF_SpeedOption,
                                                          IF_TSOffsetOption, IF_TSResolOption,
                                                          IF_TxSpeedOption, IF_TZoneOption,
                                                          ISB_EndTimeOption, ISB_FilterAcceptOption,
                                                          ISB_IFDropOption, ISB_IFRecvOption,
                                                          ISB_OSDropOption, ISB_StartTimeOption,
                                                          ISB_UsrDelivOption, NS_DNSIP4AddrOption,
                                                          NS_DNSIP6AddrOption, NS_DNSNameOption,
                                                          PACK_FlagsOption, PACK_HashOption,
                                                          UnknownOption)
        from pcapkit.utilities.exceptions import ProtocolError

        pcapng = object.__new__(PCAPNG)
        pcapng._opt = collections.Counter()

        def reset(block_type: BlockType, opt: collections.Counter | None = None) -> None:
            pcapng._type = block_type
            pcapng._opt = collections.Counter() if opt is None else opt

        def assert_protocol_error(method: str, schema: object, block_type: BlockType,
                                  opt: collections.Counter | None = None) -> None:
            reset(block_type, opt)
            with self.assertRaises(ProtocolError):
                getattr(pcapng, method)(schema, options=OrderedMultiDict())

        def with_length(schema: object, length: int) -> object:
            clone = copy.copy(schema)
            object.__setattr__(clone, 'length', length)
            return clone

        flags = {
            'direction': PacketDirection.INBOUND.value,
            'reception': PacketReception.UNICAST.value,
            'fcs_len': 4,
            'crc_error': 1,
            'too_long': 0,
            'too_short': 1,
            'gap_error': 0,
            'unaligned_error': 1,
            'delimiter_error': 0,
            'preamble_error': 1,
            'symbol_error': 0,
        }
        options = OrderedMultiDict()

        reset(BlockType.Section_Header_Block)
        self.assertEqual(
            pcapng._read_option_unknown(UnknownOption(type=OptionType.get(65000), length=3,
                                                      data=b'raw'), options=options).data,
            b'raw',
        )
        self.assertEqual(
            pcapng._read_option_comment(CommentOption(type=OptionType.opt_comment, length=7,
                                                      comment='comment'), options=options).comment,
            'comment',
        )
        self.assertEqual(
            pcapng._read_option_custom(CustomOption(type=OptionType.opt_custom_2988, length=8,
                                                    pen=42, data=b'data'), options=options).pen,
            42,
        )

        parsed_options = pcapng._read_pcapng_options([
            CommentOption(type=OptionType.opt_comment, length=5, comment='hello'),
            EndOfOption(type=OptionType.opt_endofopt, length=0),
            CommentOption(type=OptionType.opt_comment, length=7, comment='ignored'),
        ])
        self.assertEqual(len(parsed_options), 2)
        self.assertEqual(pcapng._opt[OptionType.opt_comment], 1)
        self.assertEqual(pcapng._opt[OptionType.opt_endofopt], 1)
        assert_protocol_error('_read_option_endofopt',
                              EndOfOption(type=OptionType.opt_endofopt, length=0),
                              BlockType.Section_Header_Block,
                              collections.Counter({OptionType.opt_endofopt: 1}))
        assert_protocol_error('_read_option_endofopt',
                              EndOfOption(type=OptionType.opt_endofopt, length=1),
                              BlockType.Section_Header_Block)

        reset(BlockType.Interface_Description_Block)
        self.assertEqual(pcapng._read_option_if_name(
            IF_NameOption(type=OptionType.if_name, length=4, name='eth0'),
            options=options,
        ).name, 'eth0')
        self.assertEqual(pcapng._read_option_if_description(
            IF_DescriptionOption(type=OptionType.if_description, length=4, description='desc'),
            options=options,
        ).description, 'desc')
        self.assertEqual(pcapng._read_option_if_ipv4(
            IF_IPv4AddrOption(type=OptionType.if_IPv4addr, length=8,
                              interface=ip_interface('192.0.2.1/24')),
            options=options,
        ).interface, ip_interface('192.0.2.1/24'))
        self.assertEqual(pcapng._read_option_if_ipv6(
            IF_IPv6AddrOption(type=OptionType.if_IPv6addr, length=17,
                              interface=ip_interface('2001:db8::1/64')),
            options=options,
        ).interface, ip_interface('2001:db8::1/64'))
        self.assertEqual(pcapng._read_option_if_mac(
            IF_MACAddrOption(type=OptionType.if_MACaddr, length=6,
                             interface=b'\x00\x01\x02\x03\x04\x05'),
            options=options,
        ).interface, '00:01:02:03:04:05')
        self.assertEqual(pcapng._read_option_if_eui(
            IF_EUIAddrOption(type=OptionType.if_EUIaddr, length=8,
                             interface=bytes.fromhex('023456fffe789abc')),
            options=options,
        ).interface, '02:34:56:ff:fe:78:9a:bc')
        self.assertEqual(pcapng._read_option_if_speed(
            IF_SpeedOption(type=OptionType.if_speed, length=8, speed=1000),
            options=options,
        ).speed, 1000)
        tsresol = IF_TSResolOption(type=OptionType.if_tsresol, length=1,
                                   tsresol={'flag': 0, 'resolution': 6})
        object.__setattr__(tsresol, 'resolution', 1_000_000)
        self.assertEqual(pcapng._read_option_if_tsresol(tsresol, options=options).resolution, 1_000_000)
        self.assertEqual(pcapng._read_option_if_tzone(
            IF_TZoneOption(type=OptionType.if_tzone, length=4, tzone=7200),
            options=options,
        ).timezone, datetime.timezone(datetime.timedelta(hours=2)))
        self.assertEqual(pcapng._read_option_if_filter(
            IF_FilterOption(type=OptionType.if_filter, length=4,
                            code=FilterType.Unassigned_0, filter=b'tcp'),
            options=options,
        ).expression, b'tcp')
        self.assertEqual(pcapng._read_option_if_os(
            IF_OSOption(type=OptionType.if_os, length=2, os='OS'),
            options=options,
        ).os, 'OS')
        self.assertEqual(pcapng._read_option_if_fcslen(
            IF_FCSLenOption(type=OptionType.if_fcslen, length=1, fcslen=4),
            options=options,
        ).fcs_length, 4)
        self.assertEqual(pcapng._read_option_if_tsoffset(
            IF_TSOffsetOption(type=OptionType.if_tsoffset, length=8, tsoffset=9),
            options=options,
        ).offset, 9)
        self.assertEqual(pcapng._read_option_if_hardware(
            IF_HardwareOption(type=OptionType.if_hardware, length=2, hardware='hw'),
            options=options,
        ).hardware, 'hw')
        self.assertEqual(pcapng._read_option_if_txspeed(
            IF_TxSpeedOption(type=OptionType.if_txspeed, length=8, tx_speed=10),
            options=options,
        ).speed, 10)
        self.assertEqual(pcapng._read_option_if_rxspeed(
            IF_RxSpeedOption(type=OptionType.if_rxspeed, length=8, rx_speed=20),
            options=options,
        ).speed, 20)
        assert_protocol_error('_read_option_if_name',
                              IF_NameOption(type=OptionType.if_name, length=4, name='eth1'),
                              BlockType.Section_Header_Block)
        assert_protocol_error('_read_option_if_name',
                              IF_NameOption(type=OptionType.if_name, length=4, name='eth1'),
                              BlockType.Interface_Description_Block,
                              collections.Counter({OptionType.if_name: 1}))
        assert_protocol_error('_read_option_if_ipv4',
                              IF_IPv4AddrOption(type=OptionType.if_IPv4addr, length=7,
                                                interface=ip_interface('192.0.2.1/24')),
                              BlockType.Interface_Description_Block)
        assert_protocol_error('_read_option_if_filter',
                              IF_FilterOption(type=OptionType.if_filter, length=0,
                                              code=FilterType.Unassigned_0, filter=b''),
                              BlockType.Interface_Description_Block)
        interface_error_cases = [
            ('_read_option_if_description',
             IF_DescriptionOption(type=OptionType.if_description, length=4, description='desc'),
             True, False),
            ('_read_option_if_ipv4',
             IF_IPv4AddrOption(type=OptionType.if_IPv4addr, length=8,
                               interface=ip_interface('192.0.2.1/24')),
             False, False),
            ('_read_option_if_ipv6',
             IF_IPv6AddrOption(type=OptionType.if_IPv6addr, length=17,
                               interface=ip_interface('2001:db8::1/64')),
             False, True),
            ('_read_option_if_mac',
             IF_MACAddrOption(type=OptionType.if_MACaddr, length=6,
                              interface=b'\x00\x01\x02\x03\x04\x05'),
             True, True),
            ('_read_option_if_eui',
             IF_EUIAddrOption(type=OptionType.if_EUIaddr, length=8,
                              interface=bytes.fromhex('023456fffe789abc')),
             True, True),
            ('_read_option_if_speed',
             IF_SpeedOption(type=OptionType.if_speed, length=8, speed=1000),
             True, True),
            ('_read_option_if_tsresol',
             IF_TSResolOption(type=OptionType.if_tsresol, length=1,
                              tsresol={'flag': 0, 'resolution': 6}),
             True, True),
            ('_read_option_if_tzone',
             IF_TZoneOption(type=OptionType.if_tzone, length=4, tzone=0),
             True, True),
            ('_read_option_if_filter',
             IF_FilterOption(type=OptionType.if_filter, length=4,
                             code=FilterType.Unassigned_0, filter=b'tcp'),
             True, False),
            ('_read_option_if_os',
             IF_OSOption(type=OptionType.if_os, length=2, os='OS'),
             True, False),
            ('_read_option_if_fcslen',
             IF_FCSLenOption(type=OptionType.if_fcslen, length=1, fcslen=4),
             True, True),
            ('_read_option_if_tsoffset',
             IF_TSOffsetOption(type=OptionType.if_tsoffset, length=8, tsoffset=9),
             True, True),
            ('_read_option_if_hardware',
             IF_HardwareOption(type=OptionType.if_hardware, length=2, hardware='hw'),
             True, False),
            ('_read_option_if_txspeed',
             IF_TxSpeedOption(type=OptionType.if_txspeed, length=8, tx_speed=10),
             True, True),
            ('_read_option_if_rxspeed',
             IF_RxSpeedOption(type=OptionType.if_rxspeed, length=8, rx_speed=20),
             True, True),
        ]
        for method, schema, has_duplicate_guard, has_length_guard in interface_error_cases:
            assert_protocol_error(method, schema, BlockType.Section_Header_Block)
            if has_duplicate_guard:
                assert_protocol_error(method, schema, BlockType.Interface_Description_Block,
                                      collections.Counter({schema.type: 1}))
            if has_length_guard:
                bad_schema = with_length(schema, max(schema.length - 1, 0))
                assert_protocol_error(method, bad_schema, BlockType.Interface_Description_Block)

        reset(BlockType.Enhanced_Packet_Block)
        self.assertEqual(pcapng._read_option_epb_flags(
            EPB_FlagsOption(type=OptionType.epb_flags, length=4, flags=flags),
            options=options,
        ).direction, PacketDirection.INBOUND)
        self.assertEqual(pcapng._read_option_epb_hash(
            EPB_HashOption(type=OptionType.epb_hash, length=4,
                           func=HashAlgorithm.CRC32, data=b'abc'),
            options=options,
        ).hash, b'abc')
        self.assertEqual(pcapng._read_option_epb_dropcount(
            EPB_DropCountOption(type=OptionType.epb_dropcount, length=8, drop_count=3),
            options=options,
        ).drop_count, 3)
        self.assertEqual(pcapng._read_option_epb_packetid(
            EPB_PacketIDOption(type=OptionType.epb_packetid, length=8, packet_id=4),
            options=options,
        ).packet_id, 4)
        self.assertEqual(pcapng._read_option_epb_queue(
            EPB_QueueOption(type=OptionType.epb_queue, length=4, queue_id=5),
            options=options,
        ).queue_id, 5)
        self.assertEqual(pcapng._read_option_epb_verdict(
            EPB_VerdictOption(type=OptionType.epb_verdict, length=4,
                              verdict=VerdictType.Hardware, value=b'yes'),
            options=options,
        ).value, b'yes')
        assert_protocol_error('_read_option_epb_flags',
                              EPB_FlagsOption(type=OptionType.epb_flags, length=4, flags=flags),
                              BlockType.Packet_Block)
        assert_protocol_error('_read_option_epb_flags',
                              EPB_FlagsOption(type=OptionType.epb_flags, length=5, flags=flags),
                              BlockType.Enhanced_Packet_Block)
        assert_protocol_error('_read_option_epb_verdict',
                              EPB_VerdictOption(type=OptionType.epb_verdict, length=0,
                                                verdict=VerdictType.Hardware, value=b''),
                              BlockType.Enhanced_Packet_Block)
        epb_error_cases = [
            ('_read_option_epb_flags',
             EPB_FlagsOption(type=OptionType.epb_flags, length=4, flags=flags),
             True, True),
            ('_read_option_epb_hash',
             EPB_HashOption(type=OptionType.epb_hash, length=4,
                            func=HashAlgorithm.CRC32, data=b'abc'),
             False, False),
            ('_read_option_epb_dropcount',
             EPB_DropCountOption(type=OptionType.epb_dropcount, length=8, drop_count=3),
             True, True),
            ('_read_option_epb_packetid',
             EPB_PacketIDOption(type=OptionType.epb_packetid, length=8, packet_id=4),
             True, True),
            ('_read_option_epb_queue',
             EPB_QueueOption(type=OptionType.epb_queue, length=4, queue_id=5),
             True, True),
            ('_read_option_epb_verdict',
             EPB_VerdictOption(type=OptionType.epb_verdict, length=4,
                               verdict=VerdictType.Hardware, value=b'yes'),
             False, False),
        ]
        for method, schema, has_duplicate_guard, has_length_guard in epb_error_cases:
            assert_protocol_error(method, schema, BlockType.Packet_Block)
            if has_duplicate_guard:
                assert_protocol_error(method, schema, BlockType.Enhanced_Packet_Block,
                                      collections.Counter({schema.type: 1}))
            if has_length_guard:
                assert_protocol_error(method, with_length(schema, max(schema.length - 1, 0)),
                                      BlockType.Enhanced_Packet_Block)

        reset(BlockType.Name_Resolution_Block)
        self.assertEqual(pcapng._read_option_ns_dnsname(
            NS_DNSNameOption(type=OptionType.ns_dnsname, length=3, name='dns'),
            options=options,
        ).name, 'dns')
        self.assertEqual(pcapng._read_option_ns_dnsipv4(
            NS_DNSIP4AddrOption(type=OptionType.ns_dnsIP4addr, length=4, ip=ip_address('8.8.8.8')),
            options=options,
        ).ip, ip_address('8.8.8.8'))
        self.assertEqual(pcapng._read_option_ns_dnsipv6(
            NS_DNSIP6AddrOption(type=OptionType.ns_dnsIP6addr, length=16, ip=ip_address('2001:4860::8888')),
            options=options,
        ).ip, ip_address('2001:4860::8888'))
        assert_protocol_error('_read_option_ns_dnsipv4',
                              NS_DNSIP4AddrOption(type=OptionType.ns_dnsIP4addr, length=5,
                                                  ip=ip_address('8.8.8.8')),
                              BlockType.Name_Resolution_Block)
        nrb_error_cases = [
            ('_read_option_ns_dnsname',
             NS_DNSNameOption(type=OptionType.ns_dnsname, length=3, name='dns'),
             True, False),
            ('_read_option_ns_dnsipv4',
             NS_DNSIP4AddrOption(type=OptionType.ns_dnsIP4addr, length=4, ip=ip_address('8.8.8.8')),
             True, True),
            ('_read_option_ns_dnsipv6',
             NS_DNSIP6AddrOption(type=OptionType.ns_dnsIP6addr, length=16,
                                 ip=ip_address('2001:4860::8888')),
             True, True),
        ]
        for method, schema, has_duplicate_guard, has_length_guard in nrb_error_cases:
            assert_protocol_error(method, schema, BlockType.Enhanced_Packet_Block)
            if has_duplicate_guard:
                assert_protocol_error(method, schema, BlockType.Name_Resolution_Block,
                                      collections.Counter({schema.type: 1}))
            if has_length_guard:
                assert_protocol_error(method, with_length(schema, max(schema.length - 1, 0)),
                                      BlockType.Name_Resolution_Block)

        reset(BlockType.Interface_Statistics_Block)
        pcapng._isb_interface_id = 0
        pcapng._read_timestamp = lambda high, low, interface_id=0: (
            datetime.datetime.fromtimestamp(high + low, datetime.timezone.utc),
            decimal.Decimal(high + low + interface_id),
        )
        self.assertEqual(pcapng._read_option_isb_starttime(
            ISB_StartTimeOption(type=OptionType.isb_starttime, length=8,
                                timestamp_high=1, timestamp_low=2),
            options=options,
        ).timestamp_epoch, decimal.Decimal(3))
        self.assertEqual(pcapng._read_option_isb_endtime(
            ISB_EndTimeOption(type=OptionType.isb_endtime, length=8,
                              timestamp_high=3, timestamp_low=4),
            options=options,
        ).timestamp_epoch, decimal.Decimal(7))
        for method, schema, expected in [
            ('_read_option_isb_ifrecv',
             ISB_IFRecvOption(type=OptionType.isb_ifrecv, length=8, packets=10), 10),
            ('_read_option_isb_ifdrop',
             ISB_IFDropOption(type=OptionType.isb_ifdrop, length=8, packets=11), 11),
            ('_read_option_isb_filteraccept',
             ISB_FilterAcceptOption(type=OptionType.isb_filteraccept, length=8, packets=12), 12),
            ('_read_option_isb_osdrop',
             ISB_OSDropOption(type=OptionType.isb_osdrop, length=8, packets=13), 13),
            ('_read_option_isb_usrdeliv',
             ISB_UsrDelivOption(type=OptionType.isb_usrdeliv, length=8, packets=14), 14),
        ]:
            self.assertEqual(getattr(pcapng, method)(schema, options=options).packets, expected)
        assert_protocol_error('_read_option_isb_starttime',
                              ISB_StartTimeOption(type=OptionType.isb_starttime, length=8,
                                                  timestamp_high=1, timestamp_low=2),
                              BlockType.Enhanced_Packet_Block)
        assert_protocol_error('_read_option_isb_ifrecv',
                              ISB_IFRecvOption(type=OptionType.isb_ifrecv, length=7, packets=10),
                              BlockType.Interface_Statistics_Block)
        isb_error_cases = [
            ('_read_option_isb_starttime',
             ISB_StartTimeOption(type=OptionType.isb_starttime, length=8,
                                 timestamp_high=1, timestamp_low=2)),
            ('_read_option_isb_endtime',
             ISB_EndTimeOption(type=OptionType.isb_endtime, length=8,
                               timestamp_high=3, timestamp_low=4)),
            ('_read_option_isb_ifrecv',
             ISB_IFRecvOption(type=OptionType.isb_ifrecv, length=8, packets=10)),
            ('_read_option_isb_ifdrop',
             ISB_IFDropOption(type=OptionType.isb_ifdrop, length=8, packets=11)),
            ('_read_option_isb_filteraccept',
             ISB_FilterAcceptOption(type=OptionType.isb_filteraccept, length=8, packets=12)),
            ('_read_option_isb_osdrop',
             ISB_OSDropOption(type=OptionType.isb_osdrop, length=8, packets=13)),
            ('_read_option_isb_usrdeliv',
             ISB_UsrDelivOption(type=OptionType.isb_usrdeliv, length=8, packets=14)),
        ]
        for method, schema in isb_error_cases:
            assert_protocol_error(method, schema, BlockType.Enhanced_Packet_Block)
            assert_protocol_error(method, schema, BlockType.Interface_Statistics_Block,
                                  collections.Counter({schema.type: 1}))
            assert_protocol_error(method, with_length(schema, 7),
                                  BlockType.Interface_Statistics_Block)

        reset(BlockType.Packet_Block)
        self.assertEqual(pcapng._read_option_pack_flags(
            PACK_FlagsOption(type=OptionType.pack_flags, length=4, flags=flags),
            options=options,
        ).reception, PacketReception.UNICAST)
        self.assertEqual(pcapng._read_option_pack_hash(
            PACK_HashOption(type=OptionType.pack_hash, length=4,
                            func=HashAlgorithm.SHA_1, data=b'abc'),
            options=options,
        ).algorithm, HashAlgorithm.SHA_1)
        assert_protocol_error('_read_option_pack_flags',
                              PACK_FlagsOption(type=OptionType.pack_flags, length=4, flags=flags),
                              BlockType.Enhanced_Packet_Block)
        assert_protocol_error('_read_option_pack_flags',
                              PACK_FlagsOption(type=OptionType.pack_flags, length=5, flags=flags),
                              BlockType.Packet_Block)
        assert_protocol_error('_read_option_pack_flags',
                              PACK_FlagsOption(type=OptionType.pack_flags, length=4, flags=flags),
                              BlockType.Packet_Block,
                              collections.Counter({OptionType.pack_flags: 1}))
        assert_protocol_error('_read_option_pack_hash',
                              PACK_HashOption(type=OptionType.pack_hash, length=4,
                                              func=HashAlgorithm.SHA_1, data=b'abc'),
                              BlockType.Enhanced_Packet_Block)

    def test_pcapng_record_and_secrets_readers_cover_dispatch(self) -> None:
        from pcapkit.const.pcapng.record_type import RecordType
        from pcapkit.const.pcapng.secrets_type import SecretsType
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.misc.pcapng import PCAPNG, TLSKeyLabel, WireGuardKeyLabel
        from pcapkit.protocols.schema.misc.pcapng import (EndRecord, IPv4Record, IPv6Record,
                                                          TLSKeyLog, UnknownRecord, UnknownSecrets,
                                                          WireGuardKeyLog, ZigBeeAPSKey,
                                                          ZigBeeNWKKey)
        from pcapkit.utilities.exceptions import ProtocolError

        pcapng = object.__new__(PCAPNG)
        records = OrderedMultiDict()
        unknown = UnknownRecord(type=RecordType.get(65000), length=3, data=b'raw')
        self.assertEqual(pcapng._read_record_unknown(unknown, records=records).data, b'raw')
        self.assertEqual(
            pcapng._read_record_end(EndRecord(type=RecordType.nrb_record_end, length=0),
                                    records=records).length,
            0,
        )
        with self.assertRaises(ProtocolError):
            pcapng._read_record_end(EndRecord(type=RecordType.nrb_record_end, length=1),
                                    records=records)

        ipv4 = IPv4Record(type=RecordType.nrb_record_ipv4, length=17,
                          ip=ip_address('192.0.2.1'), resol='one\x00two\x00')
        ipv6 = IPv6Record(type=RecordType.nrb_record_ipv6, length=27,
                          ip=ip_address('2001:db8::1'), resol='three\x00')
        object.__setattr__(ipv4, 'names', ['one', 'two'])
        object.__setattr__(ipv6, 'names', ['three'])
        self.assertEqual(pcapng._read_record_ipv4(ipv4, records=records).records, ('one', 'two'))
        self.assertEqual(pcapng._read_record_ipv6(ipv6, records=records).records, ('three',))

        parsed = pcapng._read_nrb_records([
            unknown,
            ipv4,
            EndRecord(type=RecordType.nrb_record_end, length=0),
            ipv6,
        ])
        self.assertEqual(len(parsed), 3)
        self.assertEqual(parsed[RecordType.nrb_record_ipv4].records, ('one', 'two'))
        self.assertNotIn(RecordType.nrb_record_ipv6, parsed)

        block = object()
        self.assertEqual(pcapng._read_secrets_unknown(
            UnknownSecrets(data=b'secret'), block=block,
        ).data, b'secret')
        tls_entries = {TLSKeyLabel.CLIENT_RANDOM: OrderedMultiDict([(b'random', b'secret')])}
        tls = TLSKeyLog(data='CLIENT_RANDOM 00 11')
        object.__setattr__(tls, 'entries', tls_entries)
        self.assertIs(pcapng._read_secrets_tls(tls, block=block).entries, tls_entries)
        wg_entries = OrderedMultiDict([(WireGuardKeyLabel.PRESHARED_KEY, b'key')])
        wireguard = WireGuardKeyLog(data='PRESHARED_KEY = a2V5')
        object.__setattr__(wireguard, 'entries', wg_entries)
        self.assertIs(pcapng._read_secrets_wireguard(wireguard, block=block).entries, wg_entries)
        self.assertEqual(pcapng._read_secrets_zigbee_nwk(
            ZigBeeNWKKey(key=b'\x01' * 16, panid=0x1234), block=block,
        ).pan_id, 0x1234)
        aps = pcapng._read_secrets_zigbee_aps(
            ZigBeeAPSKey(key=b'\x02' * 16, panid=0x5678, addr_low=0x9ABC, addr_high=0xDEF0),
            block=block,
        )
        self.assertEqual(aps.pan_id, 0x5678)
        self.assertEqual(aps.short_address, 0xDEF09ABC)

        self.assertEqual(PCAPNG.__dict__['__secrets__'][SecretsType.TLS_Key_Log], 'tls')

    def test_pcapng_schema_helpers_and_post_process_branches(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.const.pcapng.record_type import RecordType
        from pcapkit.const.pcapng.secrets_type import SecretsType
        from pcapkit.corekit.fields.numbers import UInt16Field, UInt32Field
        from pcapkit.protocols.misc.pcapng import TLSKeyLabel, WireGuardKeyLabel
        from pcapkit.protocols.schema.misc import pcapng as schema_pcapng
        from pcapkit.utilities.exceptions import FieldValueError, ProtocolError

        field = UInt16Field()
        schema_pcapng.byteorder_callback(field, {'__packet__': {'byteorder': 'little'}})
        self.assertEqual(field._byteorder, 'little')
        schema_pcapng.byteorder_callback(field, {'byteorder': 'big'})
        self.assertEqual(field._byteorder, 'big')

        shb_field = UInt32Field()
        schema_pcapng.shb_byteorder_callback(shb_field, {'match': {'byteorder': 0x1A2B3C4D}})
        self.assertEqual(shb_field._byteorder, 'big')
        schema_pcapng.shb_byteorder_callback(shb_field, {'match': {'byteorder': 0x4D3C2B1A}})
        self.assertEqual(shb_field._byteorder, 'little')
        with self.assertRaises(ProtocolError):
            schema_pcapng.shb_byteorder_callback(shb_field, {'match': {'byteorder': 0xDEADBEEF}})

        block_field = schema_pcapng.pcapng_block_selector({
            'type': BlockType.Section_Header_Block,
            '__length__': 28,
        })
        self.assertIs(block_field.schema, schema_pcapng.SectionHeaderBlock)
        self.assertEqual(block_field.length, 28)

        secrets_field = schema_pcapng.dsb_secrets_selector({
            'secrets_type': SecretsType.TLS_Key_Log,
            'secrets_length': 17,
        })
        self.assertIs(secrets_field.schema, schema_pcapng.TLSKeyLog)
        self.assertEqual(secrets_field.length, 17)

        option_field = schema_pcapng.OptionEnumField(length=2, namespace='opt')
        option_field.name = 'type'
        self.assertEqual(option_field.pack(OptionType.opt_comment, {}), b'\x00\x01')
        self.assertEqual(option_field.pack(1, {}), b'\x00\x01')
        self.assertIs(option_field.unpack(b'\x00\x01', {}), OptionType.opt_comment)

        registry = schema_pcapng.Option.registry
        saved_registry = {key: value.copy() for key, value in registry.items()}
        try:
            class LocalDefaultOption(schema_pcapng.Option, code=OptionType.opt_comment):
                pass

            class LocalIterableOption(schema_pcapng.Option,
                                      code=[OptionType.if_name],
                                      namespace='localtest'):
                pass

            self.assertIs(registry['opt'][OptionType.opt_comment], LocalDefaultOption)
            self.assertIs(registry['localtest'][OptionType.if_name], LocalIterableOption)
        finally:
            registry.clear()
            registry.update(saved_registry)

        mismatch = schema_pcapng.UnknownBlock(length=16, body=b'abcd', length2=20)
        with mock.patch('pcapkit.protocols.schema.misc.pcapng.warn') as warn:
            self.assertIs(mismatch.post_process({'__packet__': {'type': BlockType.Reserved_0x00000000}}),
                          mismatch)
        warn.assert_called_once()

        shb = schema_pcapng.SectionHeaderBlock(
            length=28,
            magic=0x1A2B3C4D,
            major=1,
            minor=0,
            section_length=0xFFFF_FFFF_FFFF_FFFF,
            options=[],
            length2=28,
        )
        packet: dict[str, object] = {}
        shb.pre_pack(packet)
        self.assertIn('match', packet)
        packet_with_match = {'match': {'byteorder': 0x12345678}}
        shb.pre_pack(packet_with_match)
        self.assertEqual(packet_with_match['match']['byteorder'], 0x12345678)

        shb.post_process({'match': {'byteorder': 0x1A2B3C4D}})
        self.assertEqual(shb.section_length, -1)
        self.assertEqual(shb.byteorder, 'big')

        shb_little = schema_pcapng.SectionHeaderBlock(
            length=28,
            magic=0x1A2B3C4D,
            major=1,
            minor=0,
            section_length=42,
            options=[],
            length2=28,
        )
        shb_little.post_process({'match': {'byteorder': 0x4D3C2B1A}})
        self.assertEqual(shb_little.byteorder, 'little')
        with self.assertRaises(ProtocolError):
            shb_little.post_process({'match': {'byteorder': 0xDEADBEEF}})

        ts_decimal = schema_pcapng.IF_TSResolOption(
            type=OptionType.if_tsresol,
            length=1,
            tsresol={'flag': 0, 'resolution': 6},
        )
        self.assertEqual(ts_decimal.post_process({}).resolution, 1_000_000)
        ts_binary = schema_pcapng.IF_TSResolOption(
            type=OptionType.if_tsresol,
            length=1,
            tsresol={'flag': 1, 'resolution': 10},
        )
        self.assertEqual(ts_binary.post_process({}).resolution, 1024)

        ipv4 = schema_pcapng.IPv4Record(
            type=RecordType.nrb_record_ipv4,
            length=16,
            ip=ip_address('192.0.2.1'),
            resol='one\x00two\x00',
        )
        ipv4.post_process({})
        self.assertEqual(ipv4.names, ['one', 'two'])
        ipv6 = schema_pcapng.IPv6Record(
            type=RecordType.nrb_record_ipv6,
            length=24,
            ip=ip_address('2001:db8::1'),
            resol='three\x00',
        )
        ipv6.post_process({})
        self.assertEqual(ipv6.names, ['three'])

        nrb = schema_pcapng.NameResolutionBlock(
            length=64,
            records=[ipv4, ipv6, schema_pcapng.UnknownRecord(
                type=RecordType.get(65000),
                length=3,
                data=b'raw',
            )],
            options=[],
            length2=64,
        )
        nrb.post_process({'__packet__': {'type': BlockType.Name_Resolution_Block}})
        self.assertEqual(nrb.mapping.getlist(ip_address('192.0.2.1')), ['one', 'two'])
        self.assertEqual(nrb.reverse_mapping.getlist('three'), [ip_address('2001:db8::1')])

        binary_payload = b'payload'
        journal = schema_pcapng.SystemdJournalExportBlock(
            length=32,
            entry=b'MESSAGE=hello\nBINARY\n' + len(binary_payload).to_bytes(8, 'little') +
                  binary_payload + b'\n\n',
            length2=32,
        )
        journal.post_process({'__packet__': {'type': BlockType.systemd_Journal_Export_Block}})
        self.assertEqual(journal.data[0]['MESSAGE'], 'hello')
        self.assertEqual(journal.data[0]['BINARY'], binary_payload)

        tls = schema_pcapng.TLSKeyLog(data='# comment\n\nCLIENT_RANDOM 00 11')
        tls.post_process({})
        self.assertEqual(tls.entries[TLSKeyLabel.CLIENT_RANDOM].getlist(b'\x00'), [b'\x11'])

        wg = schema_pcapng.WireGuardKeyLog(data='# comment\n\nPRESHARED_KEY = a2V5')
        wg.post_process({})
        self.assertEqual(wg.entries.getlist(WireGuardKeyLabel.PRESHARED_KEY), [b'key'])
        with self.assertRaises(FieldValueError):
            schema_pcapng.WireGuardKeyLog(data='PRESHARED_KEY != a2V5').post_process({})

    def test_pcapng_block_readers_cover_container_blocks(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.const.pcapng.record_type import RecordType
        from pcapkit.const.pcapng.secrets_type import SecretsType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.protocols.schema.misc.pcapng import (CommentOption, CustomBlock,
                                                          DecryptionSecretsBlock,
                                                          EnhancedPacketBlock,
                                                          InterfaceDescriptionBlock,
                                                          InterfaceStatisticsBlock, IPv4Record,
                                                          NameResolutionBlock, PCAPNG as Header,
                                                          PacketBlock, SectionHeaderBlock,
                                                          SimplePacketBlock,
                                                          SystemdJournalExportBlock, TLSKeyLog,
                                                          UnknownBlock)

        pcapng = object.__new__(PCAPNG)
        pcapng._sect = 2
        pcapng._fnum = 3
        pcapng._opt = collections.Counter()
        pcapng._get_linktype = lambda interface_id=0: LinkType.ETHERNET
        pcapng._read_timestamp = lambda high, low, interface_id=0: (
            datetime.datetime.fromtimestamp(high + low, datetime.timezone.utc),
            decimal.Decimal(high + low + interface_id),
        )
        pcapng._decode_next_layer = lambda data, proto=None, length=None, packet=None: data

        def header(block_type: BlockType) -> Header:
            return Header(type=block_type, block=b'')

        unknown = pcapng._read_block_unknown(
            UnknownBlock(length=15, body=b'abc', length2=15),
            header=header(BlockType.Reserved_0x00000000),
        )
        self.assertEqual(unknown.body, b'abc')

        shb_schema = SectionHeaderBlock(length=32, magic=0x1A2B3C4D, major=1, minor=0,
                                        section_length=-1,
                                        options=[CommentOption(type=OptionType.opt_comment,
                                                               length=2, comment='hi')],
                                        length2=32)
        object.__setattr__(shb_schema, 'byteorder', 'little')
        shb = pcapng._read_block_shb(shb_schema, header=header(BlockType.Section_Header_Block))
        self.assertEqual(shb.version.major, 1)
        self.assertEqual(shb.byteorder, 'little')

        pcapng._opt = collections.Counter()
        idb = pcapng._read_block_idb(
            InterfaceDescriptionBlock(length=20, linktype=LinkType.ETHERNET, snaplen=65535,
                                      options=[], length2=20),
            header=header(BlockType.Interface_Description_Block),
        )
        self.assertEqual(idb.linktype, LinkType.ETHERNET)
        self.assertEqual(idb.snaplen, 65535)

        pcapng._opt = collections.Counter()
        epb = pcapng._read_block_epb(
            EnhancedPacketBlock(length=36, interface_id=0, timestamp_high=1, timestamp_low=2,
                                captured_len=4, original_len=4, packet_data=b'data',
                                options=[], length2=36),
            header=header(BlockType.Enhanced_Packet_Block),
        )
        self.assertEqual(epb.section_number, 2)
        self.assertEqual(epb.timestamp_epoch, decimal.Decimal(3))

        spb = pcapng._read_block_spb(
            SimplePacketBlock(length=20, original_len=4, packet_data=b'abcd', length2=20),
            header=header(BlockType.Simple_Packet_Block),
        )
        self.assertEqual(spb.captured_len, 4)
        self.assertEqual(spb.interface_id, 0)

        nrb_record = IPv4Record(type=RecordType.nrb_record_ipv4, length=13,
                                ip=ip_address('192.0.2.1'), resol='host\x00')
        object.__setattr__(nrb_record, 'names', ['host'])
        nrb = pcapng._read_block_nrb(
            NameResolutionBlock(length=24, records=[nrb_record], options=[], length2=24),
            header=header(BlockType.Name_Resolution_Block),
        )
        self.assertEqual(nrb.mapping.getlist(ip_address('192.0.2.1')), ['host'])

        isb = pcapng._read_block_isb(
            InterfaceStatisticsBlock(length=24, interface_id=0, timestamp_high=5,
                                     timestamp_low=6, options=[], length2=24),
            header=header(BlockType.Interface_Statistics_Block),
        )
        self.assertEqual(isb.timestamp_epoch, decimal.Decimal(11))
        self.assertEqual(pcapng._isb_interface_id, 0)

        data = OrderedMultiDict([('MESSAGE', 'hello')])
        systemd_schema = SystemdJournalExportBlock(length=25, entry=b'MESSAGE=hello\n\n', length2=25)
        object.__setattr__(systemd_schema, 'data', [data])
        self.assertEqual(pcapng._read_block_systemd(
            systemd_schema,
            header=header(BlockType.systemd_Journal_Export_Block),
        ).data[0]['MESSAGE'], 'hello')

        tls = TLSKeyLog(data='')
        object.__setattr__(tls, 'entries', {})
        dsb = pcapng._read_block_dsb(
            DecryptionSecretsBlock(length=20, secrets_type=SecretsType.TLS_Key_Log,
                                   secrets_length=0, secrets_data=tls, options=[],
                                   length2=20),
            header=header(BlockType.Decryption_Secrets_Block),
        )
        self.assertEqual(dsb.secrets_type, SecretsType.TLS_Key_Log)

        cb = pcapng._read_block_cb(
            CustomBlock(length=20, pen=42, data=b'custom', length2=20),
            header=header(BlockType.Custom_Block_that_rewriters_can_copy_into_new_files),
        )
        self.assertEqual(cb.pen, 42)

        pcapng._type = BlockType.Packet_Block
        pcapng._ctx = types.SimpleNamespace()
        pcapng._info = types.SimpleNamespace(type=BlockType.Packet_Block, interface_id=0)
        packet = pcapng._read_block_packet(
            PacketBlock(length=36, interface_id=0, drop_count=1, timestamp_high=2,
                        timestamp_low=3, captured_length=4, original_length=4,
                        packet_data=b'data', options=[], length2=36),
            header=header(BlockType.Packet_Block),
        )
        self.assertEqual(packet.drop_count, 1)

    def test_pcapng_make_helpers_cover_options_records_secrets_and_blocks(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.hash_algorithm import HashAlgorithm
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.const.pcapng.record_type import RecordType
        from pcapkit.const.pcapng.secrets_type import SecretsType
        from pcapkit.const.pcapng.verdict_type import VerdictType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.corekit.version import VersionInfo
        from pcapkit.protocols.data.misc.pcapng import (CommentOption as DataCommentOption,
                                                        CustomBlock as DataCustomBlock,
                                                        DecryptionSecretsBlock as DataDecryptionSecretsBlock,
                                                        EnhancedPacketBlock as DataEnhancedPacketBlock,
                                                        IPv4Record as DataIPv4Record,
                                                        InterfaceDescriptionBlock as DataInterfaceDescriptionBlock,
                                                        InterfaceStatisticsBlock as DataInterfaceStatisticsBlock,
                                                        NameResolutionBlock as DataNameResolutionBlock,
                                                        PacketBlock as DataPacketBlock,
                                                        SectionHeaderBlock as DataSectionHeaderBlock,
                                                        SimplePacketBlock as DataSimplePacketBlock,
                                                        SystemdJournalExportBlock as DataSystemdJournalExportBlock,
                                                        TLSKeyLog as DataTLSKeyLog,
                                                        UnknownBlock as DataUnknownBlock,
                                                        UnknownOption as DataUnknownOption)
        from pcapkit.protocols.misc.pcapng import (PCAPNG, PacketDirection, PacketReception,
                                                   TLSKeyLabel, WireGuardKeyLabel)
        from pcapkit.protocols.schema.misc.pcapng import CommentOption, EndOfOption
        from pcapkit.utilities.exceptions import ProtocolError

        pcapng = object.__new__(PCAPNG)
        pcapng._byte = 'little'
        pcapng._ctx = types.SimpleNamespace(
            interfaces=[types.SimpleNamespace(snaplen=4)],
            section=types.SimpleNamespace(byteorder='little'),
        )
        pcapng._make_timestamp = lambda timestamp=None, interface_id=0: (1, 2)
        pcapng._get_local_timezone = lambda: datetime.timezone.utc

        def reset(block_type: BlockType, opt: collections.Counter | None = None) -> None:
            pcapng._type = block_type
            pcapng._opt = collections.Counter() if opt is None else opt

        reset(BlockType.Enhanced_Packet_Block)
        self.assertEqual(pcapng._make_option_epb_flags(
            OptionType.epb_flags,
            direction=PacketDirection.OUTBOUND,
            reception=PacketReception.BROADCAST,
            fcs_len=4,
            crc_error=True,
        ).flags['direction'], PacketDirection.OUTBOUND.value)
        self.assertEqual(pcapng._make_option_epb_hash(
            OptionType.epb_hash, algorithm=HashAlgorithm.MD_5, hash=b'abc',
        ).data, b'abc')
        self.assertEqual(pcapng._make_option_epb_dropcount(
            OptionType.epb_dropcount, drop_count=7,
        ).drop_count, 7)
        self.assertEqual(pcapng._make_option_epb_packetid(
            OptionType.epb_packetid, packet_id=8,
        ).packet_id, 8)
        self.assertEqual(pcapng._make_option_epb_queue(
            OptionType.epb_queue, queue_id=9,
        ).queue_id, 9)
        self.assertEqual(pcapng._make_option_epb_verdict(
            OptionType.epb_verdict, verdict=VerdictType.Linux_eBPF_XDP, value=b'ok',
        ).value, b'ok')
        pcapng._opt = collections.Counter({OptionType.epb_queue: 1})
        with self.assertRaises(ProtocolError):
            pcapng._make_option_epb_queue(OptionType.epb_queue, queue_id=9)

        reset(BlockType.Name_Resolution_Block)
        self.assertEqual(pcapng._make_option_ns_dnsname(OptionType.ns_dnsname,
                                                        name='dns').name, 'dns')
        self.assertEqual(pcapng._make_option_ns_dnsipv4(OptionType.ns_dnsIP4addr,
                                                        ip='8.8.8.8').length, 4)
        self.assertEqual(pcapng._make_option_ns_dnsipv6(OptionType.ns_dnsIP6addr,
                                                        ip='2001:4860::8888').length, 16)

        reset(BlockType.Interface_Statistics_Block)
        pcapng._isb_interface_id = 0
        self.assertEqual(pcapng._make_option_isb_starttime(OptionType.isb_starttime,
                                                           timestamp=1).timestamp_high, 1)
        self.assertEqual(pcapng._make_option_isb_endtime(OptionType.isb_endtime,
                                                         timestamp=1).timestamp_low, 2)
        self.assertEqual(pcapng._make_option_isb_ifrecv(OptionType.isb_ifrecv,
                                                        packets=1).packets, 1)
        self.assertEqual(pcapng._make_option_isb_ifdrop(OptionType.isb_ifdrop,
                                                        packets=2).packets, 2)
        self.assertEqual(pcapng._make_option_isb_filteraccept(OptionType.isb_filteraccept,
                                                              packets=3).packets, 3)
        self.assertEqual(pcapng._make_option_isb_osdrop(OptionType.isb_osdrop,
                                                        packets=4).packets, 4)
        self.assertEqual(pcapng._make_option_isb_usrdeliv(OptionType.isb_usrdeliv,
                                                          packets=5).packets, 5)

        reset(BlockType.Packet_Block)
        self.assertEqual(pcapng._make_option_pack_flags(
            OptionType.pack_flags,
            direction=PacketDirection.INBOUND,
            reception=PacketReception.MULTICAST,
        ).flags['reception'], PacketReception.MULTICAST.value)
        self.assertEqual(pcapng._make_option_pack_hash(
            OptionType.pack_hash, algorithm=HashAlgorithm.SHA_1, hash=b'abc',
        ).func, HashAlgorithm.SHA_1)

        reset(BlockType.Section_Header_Block)
        opts, opt_len = pcapng._make_pcapng_options([
            (OptionType.opt_comment, {'comment': 'hi'}),
            EndOfOption(type=OptionType.opt_endofopt, length=0),
            CommentOption(type=OptionType.opt_comment, length=5, comment='again'),
            b'\x88\x13\x03\x00raw\x00',
        ], namespace='shb')
        self.assertEqual(opts[-1].type, OptionType.opt_endofopt)
        self.assertGreater(opt_len, 0)

        data_options = OrderedMultiDict([
            (OptionType.opt_comment,
             DataCommentOption(type=OptionType.opt_comment, length=4, comment='data')),
            (OptionType.get(65000),
             DataUnknownOption(type=OptionType.get(65000), length=1, data=b'x')),
            (OptionType.opt_endofopt, object()),
        ])
        pcapng._opt = collections.Counter()
        opts_from_data, data_opt_len = pcapng._make_pcapng_options(data_options, namespace='shb')
        self.assertEqual(opts_from_data[-1].type, OptionType.opt_endofopt)
        self.assertGreater(data_opt_len, 0)

        records, records_len = pcapng._make_nrb_records([
            (RecordType.nrb_record_ipv4, {'ip': '192.0.2.1', 'names': ['one', 'two']}),
            RecordType.nrb_record_end.value.to_bytes(4, 'little'),
            b'\xfe\xff\x03\x00raw\x00',
        ])
        self.assertEqual(records[-1].type, RecordType.nrb_record_end)
        self.assertGreater(records_len, 0)
        record_data = OrderedMultiDict([
            (RecordType.nrb_record_ipv4,
             DataIPv4Record(type=RecordType.nrb_record_ipv4, length=8,
                            ip=ip_address('192.0.2.2'), records=('host',))),
            (RecordType.nrb_record_end, object()),
        ])
        records_from_data, _ = pcapng._make_nrb_records(record_data)
        self.assertEqual(records_from_data[0].resol, 'host\x00')
        self.assertEqual(pcapng._make_record_unknown(RecordType.get(65000), None,
                                                     data=b'raw').data, b'raw')
        self.assertEqual(pcapng._make_record_end(RecordType.nrb_record_end).length, 0)
        self.assertEqual(pcapng._make_record_ipv6(RecordType.nrb_record_ipv6,
                                                  None, ip='2001:db8::1',
                                                  names=['v6']).resol, 'v6\x00')

        tls_entries = {TLSKeyLabel.CLIENT_RANDOM: OrderedMultiDict([(b'\x00', b'\x01')])}
        tls_schema = pcapng._make_secrets_tls(SecretsType.TLS_Key_Log, entries=tls_entries)
        self.assertIn('CLIENT_RANDOM', tls_schema.data)
        wg_entries = OrderedMultiDict([(WireGuardKeyLabel.PRESHARED_KEY, b'key')])
        self.assertIn('PRESHARED_KEY', pcapng._make_secrets_wireguard(
            SecretsType.WireGuard_Key_Log, entries=wg_entries,
        ).data)
        self.assertEqual(pcapng._make_secrets_unknown(SecretsType.get(65000),
                                                      data=b'raw').data, b'raw')
        self.assertEqual(pcapng._make_secrets_zigbee_nwk(
            SecretsType.ZigBee_NWK_Key, nwk_key=b'\x01' * 16, pan_id=1,
        ).panid, 1)
        self.assertEqual(pcapng._make_secrets_zigbee_aps(
            SecretsType.ZigBee_APS_Key, aps_key=b'\x02' * 16, pan_id=2,
            short_address=0x12345678,
        ).addr_high, 0x1234)

        self.assertEqual(pcapng._make_block_unknown(data=b'abc').body, b'abc')
        shb = pcapng._make_block_shb(version=(1, 0), section_length=-1)
        self.assertEqual(shb.major, 1)
        idb = pcapng._make_block_idb(linktype=LinkType.ETHERNET, snaplen=65535)
        self.assertEqual(idb.linktype, LinkType.ETHERNET)
        epb = pcapng._make_block_epb(packet_data=b'abcdef', interface_id=0)
        self.assertEqual(epb.captured_len, 4)
        self.assertEqual(epb.original_len, 6)
        self.assertEqual(pcapng._make_block_spb(packet_data=b'abc').original_len, 3)
        self.assertEqual(pcapng._make_block_nrb(records=[
            (RecordType.nrb_record_ipv4, {'ip': '192.0.2.1', 'names': ['host']}),
        ]).records[0].type, RecordType.nrb_record_ipv4)
        self.assertEqual(pcapng._make_block_isb(interface_id=0).timestamp_high, 1)
        journal = OrderedMultiDict([('MESSAGE', 'hello'), ('BINARY', b'\x01\x02')])
        self.assertIn(b'MESSAGE=hello', pcapng._make_block_systemd(entries=[journal]).entry)
        dsb = pcapng._make_block_dsb(secrets_type=SecretsType.TLS_Key_Log,
                                     secrets_data=DataTLSKeyLog(entries=tls_entries))
        self.assertEqual(dsb.secrets_type, SecretsType.TLS_Key_Log)
        with self.assertRaises(ProtocolError):
            pcapng._make_block_dsb(secrets_type=SecretsType.TLS_Key_Log, secrets_data=object())
        self.assertEqual(pcapng._make_block_cb(pen=1, data=b'custom').pen, 1)
        self.assertEqual(pcapng._make_block_packet(interface_id=0, packet_data=b'abcdef',
                                                   drop_count=2).captured_length, 4)

        option_data = OrderedMultiDict([
            (OptionType.opt_comment,
             DataCommentOption(type=OptionType.opt_comment, length=4, comment='data')),
        ])

        reset(BlockType.Reserved_0x00000000)
        unknown_data = DataUnknownBlock(type=BlockType.Reserved_0x00000000, length=3, body=b'raw')
        self.assertEqual(pcapng._make_block_unknown(unknown_data).body, b'raw')

        reset(BlockType.Section_Header_Block)
        shb_data = DataSectionHeaderBlock(
            type=BlockType.Section_Header_Block,
            length=28,
            byteorder='little',
            version=VersionInfo(1, 2),
            section_length=99,
            options=option_data,
        )
        shb_from_data = pcapng._make_block_shb(shb_data)
        self.assertEqual(shb_from_data.major, 1)
        self.assertEqual(shb_from_data.minor, 2)
        self.assertGreater(shb_from_data.length, 28)

        reset(BlockType.Interface_Description_Block)
        idb_data = DataInterfaceDescriptionBlock(
            type=BlockType.Interface_Description_Block,
            length=20,
            linktype=LinkType.ETHERNET,
            snaplen=128,
            options=option_data,
        )
        idb_from_data = pcapng._make_block_idb(idb_data)
        self.assertEqual(idb_from_data.linktype, LinkType.ETHERNET)
        self.assertEqual(idb_from_data.snaplen, 128)
        self.assertGreater(idb_from_data.length, 20)

        reset(BlockType.Enhanced_Packet_Block)
        epb_data = DataEnhancedPacketBlock(
            type=BlockType.Enhanced_Packet_Block,
            length=32,
            section_number=1,
            number=2,
            interface_id=0,
            timestamp=datetime.datetime.fromtimestamp(3, datetime.timezone.utc),
            timestamp_epoch=decimal.Decimal(3),
            captured_len=2,
            original_len=5,
            options=option_data,
        )
        epb_from_data = pcapng._make_block_epb(epb_data)
        self.assertEqual(epb_from_data.captured_len, 2)
        self.assertEqual(epb_from_data.original_len, 5)

        spb_data = DataSimplePacketBlock(
            type=BlockType.Simple_Packet_Block,
            length=16,
            section_number=1,
            number=2,
            original_len=5,
            captured_len=3,
        )
        self.assertEqual(pcapng._make_block_spb(spb_data).original_len, 5)
        self.assertEqual(pcapng.make(type=BlockType.Simple_Packet_Block, block=spb_data).block.original_len, 5)

        reset(BlockType.Name_Resolution_Block)
        nrb_data = DataNameResolutionBlock(
            type=BlockType.Name_Resolution_Block,
            length=12,
            records=record_data,
            options=option_data,
        )
        nrb_from_data = pcapng._make_block_nrb(nrb_data)
        self.assertGreaterEqual(len(nrb_from_data.records), 1)
        self.assertGreater(nrb_from_data.length, 12)

        reset(BlockType.Interface_Statistics_Block)
        isb_data = DataInterfaceStatisticsBlock(
            type=BlockType.Interface_Statistics_Block,
            length=24,
            interface_id=0,
            timestamp=datetime.datetime.fromtimestamp(4, datetime.timezone.utc),
            timestamp_epoch=decimal.Decimal(4),
            options=option_data,
        )
        isb_from_data = pcapng._make_block_isb(isb_data)
        self.assertEqual(isb_from_data.interface_id, 0)
        self.assertGreater(isb_from_data.length, 24)

        systemd_data = DataSystemdJournalExportBlock(
            type=BlockType.systemd_Journal_Export_Block,
            length=12,
            data=(journal,),
        )
        self.assertIn(b'MESSAGE=hello', pcapng._make_block_systemd(systemd_data).entry)

        reset(BlockType.Decryption_Secrets_Block)
        dsb_data = DataDecryptionSecretsBlock(
            type=BlockType.Decryption_Secrets_Block,
            length=20,
            secrets_type=SecretsType.TLS_Key_Log,
            secrets_length=0,
            secrets_data=DataTLSKeyLog(entries=tls_entries),
            options=option_data,
        )
        dsb_from_data = pcapng._make_block_dsb(dsb_data)
        self.assertEqual(dsb_from_data.secrets_type, SecretsType.TLS_Key_Log)
        self.assertGreater(dsb_from_data.length, 20)

        custom_data = DataCustomBlock(
            type=BlockType.Custom_Block_that_rewriters_can_copy_into_new_files,
            length=16,
            pen=99,
            data=b'data',
        )
        self.assertEqual(pcapng._make_block_cb(custom_data).pen, 99)
        custom_with_options = DummyData(pen=100, data=b'data', options=option_data)
        self.assertGreater(pcapng._make_block_cb(custom_with_options).length, 20)

        packet_data = DataPacketBlock(
            type=BlockType.Packet_Block,
            length=32,
            section_number=1,
            number=2,
            interface_id=0,
            drop_count=7,
            timestamp=datetime.datetime.fromtimestamp(5, datetime.timezone.utc),
            timestamp_epoch=decimal.Decimal(5),
            captured_len=2,
            original_len=5,
            options=option_data,
        )
        packet_from_data = pcapng._make_block_packet(packet_data)
        self.assertEqual(packet_from_data.drop_count, 7)
        self.assertEqual(packet_from_data.captured_length, 2)

    def test_pcapng_remaining_constructor_branches_and_custom_dispatch(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.filter_type import FilterType
        from pcapkit.const.pcapng.hash_algorithm import HashAlgorithm
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.const.pcapng.record_type import RecordType
        from pcapkit.const.pcapng.secrets_type import SecretsType
        from pcapkit.const.pcapng.verdict_type import VerdictType
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.misc.pcapng import (PCAPNG, PacketDirection, PacketReception,
                                                   TLSKeyLabel, WireGuardKeyLabel)
        from pcapkit.protocols.schema.misc.pcapng import (CommentOption, DecryptionSecretsBlock,
                                                          EndRecord, IPv4Record as SchemaIPv4Record,
                                                          IPv6Record as SchemaIPv6Record,
                                                          UnknownOption as SchemaUnknownOption,
                                                          UnknownRecord as SchemaUnknownRecord,
                                                          UnknownSecrets as SchemaUnknownSecrets)
        from pcapkit.utilities.exceptions import ProtocolError

        pcapng = object.__new__(PCAPNG)
        pcapng._byte = 'little'
        pcapng._ctx = None
        pcapng._type = BlockType.Section_Header_Block
        pcapng._opt = collections.Counter()
        pcapng._make_timestamp = lambda timestamp=None, interface_id=0: (1, 2)
        pcapng._get_local_timezone = lambda: datetime.timezone.utc

        init = object.__new__(PCAPNG)
        init.pack = mock.Mock(return_value=b'header')
        init.unpack = mock.Mock(return_value=DummyData(length=6))
        PCAPNG.__post_init__(init, None, num=1, sct=2, ctx=None)
        self.assertEqual(init._sect, 2)
        self.assertEqual(init._fnum, 1)
        self.assertEqual(init._data, b'header')
        self.assertIsInstance(init._file, io.BytesIO)

        parsed_init = object.__new__(PCAPNG)
        parsed_init.unpack = mock.Mock(return_value=DummyData(length=4))
        PCAPNG.__post_init__(parsed_init, b'abcd', 4, num=3, sct=4, ctx=types.SimpleNamespace())
        self.assertEqual(parsed_init._file.getvalue(), b'abcd')
        parsed_init.unpack.assert_called_once()

        packer = object.__new__(PCAPNG)
        packer._ctx = None
        packer._byte = 'little'
        packer._opt = collections.Counter()
        packed = packer.pack(type=BlockType.Simple_Packet_Block,
                             block={'packet_data': b'abcd'},
                             __packet__={'byteorder': 'little'})
        self.assertEqual(len(packed), 20)

        unpacker = object.__new__(PCAPNG)
        unpacker.__header__ = None
        unpacker.__schema__ = types.SimpleNamespace(unpack=mock.Mock(return_value=types.SimpleNamespace()))
        unpacker._file = io.BytesIO(b'0123456789ab')
        unpacker._ctx = types.SimpleNamespace(section=types.SimpleNamespace(byteorder='little'))
        unpacker._byte = 'big'
        unpacker.read = mock.Mock(return_value=DummyData(length=12))
        unpacker.__dict__['packet'] = types.SimpleNamespace(payload=b'payload')
        data = unpacker.unpack(12, __packet__={})
        self.assertEqual(data['packet'], b'payload')
        self.assertEqual(unpacker._byte, 'little')

        unpacker.__header__ = types.SimpleNamespace()
        unpacker.read = mock.Mock(return_value=DummyData(length=12))
        unpacker.__dict__['packet'] = types.SimpleNamespace(payload=b'cached')
        self.assertEqual(unpacker.unpack(12)['packet'], b'cached')
        unpacker.__schema__.unpack.assert_called_once()

        no_ctx_unpacker = object.__new__(PCAPNG)
        no_ctx_unpacker.__header__ = None
        no_ctx_unpacker.__schema__ = types.SimpleNamespace(unpack=mock.Mock(return_value=types.SimpleNamespace()))
        no_ctx_unpacker._file = io.BytesIO(b'0123456789ab')
        no_ctx_unpacker._ctx = None
        no_ctx_unpacker._byte = 'big'
        no_ctx_unpacker.read = mock.Mock(return_value=DummyData(length=12))
        no_ctx_unpacker.__dict__['packet'] = types.SimpleNamespace(payload=b'no-context')
        self.assertEqual(no_ctx_unpacker.unpack(12)['packet'], b'no-context')
        self.assertEqual(no_ctx_unpacker._byte, 'big')

        self.assertEqual(pcapng._make_block_shb(major_version=2, section_length=-1).minor, 0)
        self.assertEqual(pcapng._make_block_shb(major_version=1, minor_version=5,
                                                section_length=-1).minor, 5)
        pcapng._ctx = None
        self.assertEqual(pcapng._make_block_epb(packet_data=b'abcdef').captured_len, 6)
        self.assertEqual(pcapng._make_block_nrb().records, [])
        self.assertEqual(pcapng._make_block_systemd().entry, b'')
        self.assertEqual(pcapng._make_block_systemd(entries=b'raw').entry, b'raw')
        self.assertEqual(pcapng._make_block_packet(packet_data=b'abcdef').captured_length, 6)

        def assert_wrong_block(method: str, code: OptionType, correct: BlockType, **kwargs: object) -> None:
            pcapng._type = BlockType.Section_Header_Block
            pcapng._opt = collections.Counter()
            with self.assertRaises(ProtocolError):
                getattr(pcapng, method)(code, **kwargs)
            pcapng._type = correct

        def assert_duplicate(method: str, code: OptionType, block: BlockType, **kwargs: object) -> None:
            pcapng._type = block
            pcapng._opt = collections.Counter({code: 1})
            with self.assertRaises(ProtocolError):
                getattr(pcapng, method)(code, **kwargs)
            pcapng._opt = collections.Counter()

        pcapng._type = BlockType.Interface_Description_Block
        interface_cases = [
            ('_make_option_if_name', OptionType.if_name, DummyData(name='eth-data'), 'name', 'eth-data'),
            ('_make_option_if_description', OptionType.if_description,
             DummyData(description='desc-data'), 'description', 'desc-data'),
            ('_make_option_if_ipv4', OptionType.if_IPv4addr,
             DummyData(interface='192.0.2.9/24'), 'length', 8),
            ('_make_option_if_ipv6', OptionType.if_IPv6addr,
             DummyData(interface='2001:db8::9/64'), 'length', 8),
            ('_make_option_if_mac', OptionType.if_MACaddr,
             DummyData(interface='00:01:02:03:04:06'), 'interface', b'000102030406'),
            ('_make_option_if_eui', OptionType.if_EUIaddr,
             DummyData(interface='02:34:56:ff:fe:78:9a:bd'), 'interface', b'023456fffe789abd'),
            ('_make_option_if_speed', OptionType.if_speed, DummyData(speed=2000), 'speed', 2000),
            ('_make_option_if_tsresol', OptionType.if_tsresol, DummyData(resolution=1000),
             'tsresol', {'flag': 0, 'resolution': 3}),
            ('_make_option_if_tzone', OptionType.if_tzone,
             DummyData(timezone=datetime.timezone(datetime.timedelta(hours=3))), 'tzone', 10800),
            ('_make_option_if_filter', OptionType.if_filter,
             DummyData(code=FilterType.Unassigned_0, expression=b'udp'), 'filter', b'udp'),
            ('_make_option_if_os', OptionType.if_os, DummyData(os='data-os'), 'os', 'data-os'),
            ('_make_option_if_fcslen', OptionType.if_fcslen, DummyData(fcs_length=8), 'fcslen', 8),
            ('_make_option_if_tsoffset', OptionType.if_tsoffset, DummyData(offset=11), 'tsoffset', 11),
            ('_make_option_if_hardware', OptionType.if_hardware,
             DummyData(hardware='data-hw'), 'hardware', 'data-hw'),
            ('_make_option_if_txspeed', OptionType.if_txspeed, DummyData(speed=30), 'tx_speed', 30),
            ('_make_option_if_rxspeed', OptionType.if_rxspeed, DummyData(speed=40), 'rx_speed', 40),
        ]
        for method, code, option, field, expected in interface_cases:
            pcapng._opt = collections.Counter()
            value = getattr(pcapng, method)(code, option).to_dict()[field]
            self.assertEqual(value, expected)
            assert_wrong_block(method, code, BlockType.Interface_Description_Block)

        for method, code in [
            ('_make_option_if_description', OptionType.if_description),
            ('_make_option_if_mac', OptionType.if_MACaddr),
            ('_make_option_if_eui', OptionType.if_EUIaddr),
            ('_make_option_if_speed', OptionType.if_speed),
            ('_make_option_if_tsresol', OptionType.if_tsresol),
            ('_make_option_if_tzone', OptionType.if_tzone),
            ('_make_option_if_filter', OptionType.if_filter),
            ('_make_option_if_os', OptionType.if_os),
            ('_make_option_if_fcslen', OptionType.if_fcslen),
            ('_make_option_if_tsoffset', OptionType.if_tsoffset),
            ('_make_option_if_hardware', OptionType.if_hardware),
            ('_make_option_if_txspeed', OptionType.if_txspeed),
            ('_make_option_if_rxspeed', OptionType.if_rxspeed),
        ]:
            assert_duplicate(method, code, BlockType.Interface_Description_Block)
        self.assertEqual(pcapng._make_option_if_tzone(OptionType.if_tzone, tzone=90).tzone, 90)
        self.assertEqual(pcapng._make_option_if_tzone(
            OptionType.if_tzone,
            tzone=datetime.timezone(datetime.timedelta(hours=1)),
        ).tzone, 3600)
        self.assertEqual(pcapng._make_option_custom(
            OptionType.opt_custom_2988,
            DummyData(pen=7, data=b'custom-data'),
        ).pen, 7)

        pcapng._type = BlockType.Enhanced_Packet_Block
        epb_flags = DummyData(
            direction=PacketDirection.INBOUND,
            reception=PacketReception.MULTICAST,
            fcs_len=3,
            crc_error=True,
            too_long=True,
            too_short=False,
            gap_error=True,
            unaligned_error=False,
            delimiter_error=True,
            preamble_error=False,
            symbol_error=True,
        )
        self.assertEqual(pcapng._make_option_epb_flags(
            OptionType.epb_flags, epb_flags,
        ).flags['fcs_len'], 3)
        self.assertEqual(pcapng._make_option_epb_hash(
            OptionType.epb_hash, DummyData(algorithm=HashAlgorithm.SHA_1, hash=b'hash'),
        ).data, b'hash')
        self.assertEqual(pcapng._make_option_epb_dropcount(
            OptionType.epb_dropcount, DummyData(drop_count=8),
        ).drop_count, 8)
        self.assertEqual(pcapng._make_option_epb_packetid(
            OptionType.epb_packetid, DummyData(packet_id=9),
        ).packet_id, 9)
        self.assertEqual(pcapng._make_option_epb_queue(
            OptionType.epb_queue, DummyData(queue_id=10),
        ).queue_id, 10)
        self.assertEqual(pcapng._make_option_epb_verdict(
            OptionType.epb_verdict, DummyData(verdict=VerdictType.Linux_eBPF_TC, value=b'pass'),
        ).value, b'pass')
        for method, code in [
            ('_make_option_epb_flags', OptionType.epb_flags),
            ('_make_option_epb_hash', OptionType.epb_hash),
            ('_make_option_epb_dropcount', OptionType.epb_dropcount),
            ('_make_option_epb_packetid', OptionType.epb_packetid),
            ('_make_option_epb_queue', OptionType.epb_queue),
            ('_make_option_epb_verdict', OptionType.epb_verdict),
        ]:
            assert_wrong_block(method, code, BlockType.Enhanced_Packet_Block)
        for method, code in [
            ('_make_option_epb_flags', OptionType.epb_flags),
            ('_make_option_epb_dropcount', OptionType.epb_dropcount),
            ('_make_option_epb_packetid', OptionType.epb_packetid),
            ('_make_option_epb_verdict', OptionType.epb_verdict),
        ]:
            assert_duplicate(method, code, BlockType.Enhanced_Packet_Block)

        pcapng._type = BlockType.Name_Resolution_Block
        self.assertEqual(pcapng._make_option_ns_dnsname(
            OptionType.ns_dnsname, DummyData(name='dns-data'),
        ).name, 'dns-data')
        self.assertEqual(pcapng._make_option_ns_dnsipv4(
            OptionType.ns_dnsIP4addr, DummyData(ip='1.1.1.1'),
        ).ip, '1.1.1.1')
        self.assertEqual(pcapng._make_option_ns_dnsipv6(
            OptionType.ns_dnsIP6addr, DummyData(ip='2001:4860::8844'),
        ).ip, '2001:4860::8844')
        for method, code in [
            ('_make_option_ns_dnsname', OptionType.ns_dnsname),
            ('_make_option_ns_dnsipv4', OptionType.ns_dnsIP4addr),
            ('_make_option_ns_dnsipv6', OptionType.ns_dnsIP6addr),
        ]:
            assert_wrong_block(method, code, BlockType.Name_Resolution_Block)
            assert_duplicate(method, code, BlockType.Name_Resolution_Block)

        pcapng._type = BlockType.Interface_Statistics_Block
        pcapng._isb_interface_id = 0
        isb_cases = [
            ('_make_option_isb_starttime', OptionType.isb_starttime,
             DummyData(timestamp_epoch=decimal.Decimal(12)), 'timestamp_high', 1),
            ('_make_option_isb_endtime', OptionType.isb_endtime,
             DummyData(timestamp_epoch=decimal.Decimal(13)), 'timestamp_low', 2),
            ('_make_option_isb_ifrecv', OptionType.isb_ifrecv, DummyData(packets=11), 'packets', 11),
            ('_make_option_isb_ifdrop', OptionType.isb_ifdrop, DummyData(packets=12), 'packets', 12),
            ('_make_option_isb_filteraccept', OptionType.isb_filteraccept,
             DummyData(packets=13), 'packets', 13),
            ('_make_option_isb_osdrop', OptionType.isb_osdrop, DummyData(packets=14), 'packets', 14),
            ('_make_option_isb_usrdeliv', OptionType.isb_usrdeliv, DummyData(packets=15), 'packets', 15),
        ]
        for method, code, option, field, expected in isb_cases:
            pcapng._opt = collections.Counter()
            self.assertEqual(getattr(pcapng, method)(code, option).to_dict()[field], expected)
            assert_wrong_block(method, code, BlockType.Interface_Statistics_Block)
            assert_duplicate(method, code, BlockType.Interface_Statistics_Block)

        pcapng._type = BlockType.Packet_Block
        pack_flags = DummyData(
            direction=PacketDirection.OUTBOUND,
            reception=PacketReception.BROADCAST,
            fcs_len=1,
            crc_error=True,
            too_long=False,
            too_short=True,
            gap_error=False,
            unaligned_error=True,
            delimiter_error=False,
            preamble_error=True,
            symbol_error=False,
        )
        self.assertEqual(pcapng._make_option_pack_flags(
            OptionType.pack_flags, pack_flags,
        ).flags['direction'], PacketDirection.OUTBOUND.value)
        self.assertEqual(pcapng._make_option_pack_hash(
            OptionType.pack_hash, DummyData(algorithm=HashAlgorithm.MD_5, hash=b'pack'),
        ).data, b'pack')
        for method, code in [
            ('_make_option_pack_flags', OptionType.pack_flags),
            ('_make_option_pack_hash', OptionType.pack_hash),
        ]:
            assert_wrong_block(method, code, BlockType.Packet_Block)
        assert_duplicate('_make_option_pack_flags', OptionType.pack_flags, BlockType.Packet_Block)

        option_code = OptionType.get(65001)
        record_code = RecordType.get(65001)
        secrets_code = SecretsType.get(65001)
        option_map = PCAPNG.__dict__['__option__']
        record_map = PCAPNG.__dict__['__record__']
        secrets_map = PCAPNG.__dict__['__secrets__']
        missing = object()
        originals = (
            option_map.get(option_code, missing),
            record_map.get(record_code, missing),
            secrets_map.get(secrets_code, missing),
        )

        def restore(mapping, code, original):
            if original is missing:
                mapping.pop(code, None)
            else:
                mapping[code] = original

        def custom_option_parser(schema, *, options):
            return DummyData(type=schema.type, length=schema.length, data=schema.data)

        def custom_option_constructor(code, option=None, *, data=b'x', **kwargs):
            if option is not None:
                data = option.data
            return SchemaUnknownOption(type=code, length=len(data), data=data)

        def custom_record_parser(schema, *, records):
            return DummyData(type=schema.type, length=schema.length, data=schema.data)

        def custom_record_constructor(code, record=None, *, data=b'r', **kwargs):
            if record is not None:
                data = record.data
            return SchemaUnknownRecord(type=code, length=len(data), data=data)

        def custom_secrets_parser(schema, *, block):
            return DummyData(data=schema.data)

        def custom_secrets_constructor(code, secrets=None, *, data=b's', **kwargs):
            if secrets is not None:
                data = secrets.data
            return SchemaUnknownSecrets(data=data)

        try:
            option_map[option_code] = (custom_option_parser, custom_option_constructor)
            record_map[record_code] = (custom_record_parser, custom_record_constructor)
            secrets_map[secrets_code] = (custom_secrets_parser, custom_secrets_constructor)

            pcapng._type = BlockType.Section_Header_Block
            pcapng._opt = collections.Counter()
            options = pcapng._read_pcapng_options([
                SchemaUnknownOption(type=option_code, length=1, data=b'o'),
            ])
            self.assertEqual(options[option_code].data, b'o')

            pcapng._opt = collections.Counter()
            list_options, _ = pcapng._make_pcapng_options([
                b'\x00\x00\x00\x00',
                (option_code, {'data': b'list'}),
                (OptionType.opt_endofopt, {}),
            ], namespace='shb')
            self.assertEqual(list_options[-1].type, OptionType.opt_endofopt)
            self.assertEqual(list_options[0].data, b'list')

            pcapng._opt = collections.Counter()
            no_end_options, _ = pcapng._make_pcapng_options([
                (OptionType.opt_comment, {'comment': 'no-end'}),
            ], namespace='shb')
            self.assertNotEqual(no_end_options[-1].type, OptionType.opt_endofopt)

            pcapng._opt = collections.Counter()
            dict_options, _ = pcapng._make_pcapng_options(OrderedMultiDict([
                (option_code, DummyData(data=b'dict')),
                (OptionType.opt_endofopt, object()),
            ]), namespace='shb')
            self.assertEqual(dict_options[0].data, b'dict')
            self.assertEqual(dict_options[-1].type, OptionType.opt_endofopt)

            pcapng._opt = collections.Counter()
            dict_options_no_end, _ = pcapng._make_pcapng_options(OrderedMultiDict([
                (OptionType.opt_comment, DummyData(comment='dict-no-end')),
            ]), namespace='shb')
            self.assertNotEqual(dict_options_no_end[-1].type, OptionType.opt_endofopt)

            records = pcapng._read_nrb_records([
                SchemaUnknownRecord(type=record_code, length=1, data=b'r'),
            ])
            self.assertEqual(records[record_code].data, b'r')

            schema_records, _ = pcapng._make_nrb_records([
                SchemaIPv4Record(type=RecordType.nrb_record_ipv4, length=6,
                                 ip='192.0.2.1', resol='a\x00'),
                EndRecord(type=RecordType.nrb_record_end, length=0),
            ])
            self.assertEqual(schema_records[-1].type, RecordType.nrb_record_end)

            list_records, _ = pcapng._make_nrb_records([
                (record_code, {'data': b'list-record'}),
                (RecordType.nrb_record_end, {}),
            ])
            self.assertEqual(list_records[0].data, b'list-record')
            self.assertEqual(list_records[-1].type, RecordType.nrb_record_end)

            dict_records, _ = pcapng._make_nrb_records(OrderedMultiDict([
                (record_code, DummyData(data=b'dict-record')),
                (RecordType.nrb_record_end, object()),
            ]))
            self.assertEqual(dict_records[0].data, b'dict-record')
            self.assertEqual(dict_records[-1].type, RecordType.nrb_record_end)

            dict_records_no_end, _ = pcapng._make_nrb_records(OrderedMultiDict([
                (RecordType.nrb_record_ipv4,
                 DummyData(ip=ip_address('192.0.2.5'), records=('host',))),
            ]))
            self.assertNotEqual(dict_records_no_end[-1].type, RecordType.nrb_record_end)

            self.assertEqual(pcapng._make_record_unknown(
                record_code, DummyData(data=b'data-record'),
            ).data, b'data-record')
            self.assertEqual(pcapng._make_record_ipv4(
                RecordType.nrb_record_ipv4, ip='192.0.2.6',
            ).resol, '\x00')
            self.assertEqual(pcapng._make_record_ipv6(
                RecordType.nrb_record_ipv6,
                DummyData(ip=ip_address('2001:db8::6'), records=('v6',)),
            ).resol, 'v6\x00')
            self.assertEqual(pcapng._make_record_ipv6(
                RecordType.nrb_record_ipv6, ip='2001:db8::7',
            ).resol, '\x00')

            dsb_schema = DecryptionSecretsBlock(
                length=24,
                secrets_type=secrets_code,
                secrets_length=4,
                secrets_data=SchemaUnknownSecrets(data=b'secr'),
                options=[],
                length2=24,
            )
            header = types.SimpleNamespace(type=BlockType.Decryption_Secrets_Block)
            self.assertEqual(pcapng._read_block_dsb(dsb_schema, header=header).secrets_data.data, b'secr')

            self.assertEqual(pcapng._make_block_dsb(
                secrets_type=secrets_code,
                secrets_data=b'bytes',
            ).secrets_length, 5)
            self.assertEqual(pcapng._make_block_dsb(
                secrets_type=secrets_code,
                secrets_data={'data': b'dict'},
            ).secrets_length, 4)
            self.assertEqual(pcapng._make_block_dsb(
                secrets_type=secrets_code,
                secrets_data=SchemaUnknownSecrets(data=b'schema'),
            ).secrets_length, 6)
        finally:
            restore(option_map, option_code, originals[0])
            restore(record_map, record_code, originals[1])
            restore(secrets_map, secrets_code, originals[2])

        tls_entries = {TLSKeyLabel.CLIENT_RANDOM: OrderedMultiDict([(b'\x00', b'\x01')])}
        wireguard_entries = OrderedMultiDict([(WireGuardKeyLabel.PRESHARED_KEY, b'key')])
        self.assertEqual(pcapng._make_secrets_unknown(
            secrets_code, DummyData(data=b'unknown'),
        ).data, b'unknown')
        self.assertIn('generated by PyPCAPKit', pcapng._make_secrets_tls(SecretsType.TLS_Key_Log).data)
        self.assertIn('CLIENT_RANDOM', pcapng._make_secrets_tls(
            SecretsType.TLS_Key_Log, DummyData(entries=tls_entries),
        ).data)
        self.assertIn('generated by PyPCAPKit',
                      pcapng._make_secrets_wireguard(SecretsType.WireGuard_Key_Log).data)
        self.assertIn('PRESHARED_KEY', pcapng._make_secrets_wireguard(
            SecretsType.WireGuard_Key_Log,
            DummyData(entries=wireguard_entries),
        ).data)
        self.assertEqual(pcapng._make_secrets_zigbee_nwk(
            SecretsType.ZigBee_NWK_Key,
            DummyData(nwk_key=b'\x03' * 16, pan_id=3),
        ).panid, 3)
        self.assertEqual(pcapng._make_secrets_zigbee_aps(
            SecretsType.ZigBee_APS_Key,
            DummyData(aps_key=b'\x04' * 16, pan_id=4, short_address=0x56789ABC),
        ).addr_low, 0x9ABC)


if __name__ == '__main__':
    unittest.main()
