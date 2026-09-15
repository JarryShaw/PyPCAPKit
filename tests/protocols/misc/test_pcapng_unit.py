from __future__ import annotations

import importlib.util
import collections
import copy
import datetime
import decimal
import io
from ipaddress import ip_address, ip_interface
import os
import struct
import sys
import time
import types
import unittest
from unittest import mock

from tests._support import purge_modules, sample_path

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class DummyData(dict):
    __getattr__ = dict.__getitem__

    def __update__(self, *values, **kwargs):
        for value in values:
            self.update(value)
        self.update(kwargs)


def pad32(value: bytes) -> bytes:
    """Pad ``value`` with zeroes up to the next 32-bit boundary."""
    return value + bytes(-len(value) % 4)


def tlv(code: int, value: bytes) -> bytes:
    """Build a little-endian PCAP-NG option or NRB record, padded to 32 bits."""
    return struct.pack('<HH', code, len(value)) + pad32(value)


def block_body(body: bytes) -> bytes:
    """Wrap ``body`` in the two block total length fields of a PCAP-NG block.

    The returned buffer is what a block schema is handed by
    :class:`~pcapkit.protocols.schema.misc.pcapng.PCAPNG`, i.e. the block
    without its leading 4-octet block type, but *with* the block total length
    at either end. The length itself counts the block type as well, so it is
    the length of the returned buffer plus four.

    """
    length = len(body) + 12
    return struct.pack('<I', length) + body + struct.pack('<I', length)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PCAPNGUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_pcapng_index_length_and_make_data(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.misc.pcapng import PCAPNG, _option_key
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
        unscoped_option = types.SimpleNamespace(opt_name='', opt_value=42)
        self.assertIs(_option_key(unscoped_option), unscoped_option)

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
        from pcapkit.protocols.misc.pcapng import PCAPNG, _option_key

        block_map = PCAPNG.__dict__['__block__']
        option_map = PCAPNG.__dict__['__option__']
        record_map = PCAPNG.__dict__['__record__']
        secrets_map = PCAPNG.__dict__['__secrets__']
        originals = (
            block_map[BlockType.Section_Header_Block],
            option_map[_option_key(OptionType.opt_endofopt)],
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
            self.assertEqual(option_map[_option_key(OptionType.opt_endofopt)], 'endofopt')
            self.assertEqual(record_map[RecordType.nrb_record_end], 'end')
            self.assertEqual(secrets_map[SecretsType.TLS_Key_Log], 'tls')
        finally:
            block_map[BlockType.Section_Header_Block] = originals[0]
            option_map[_option_key(OptionType.opt_endofopt)] = originals[1]
            record_map[RecordType.nrb_record_end] = originals[2]
            secrets_map[SecretsType.TLS_Key_Log] = originals[3]

    def test_pcapng_option_registry_preserves_duplicate_numeric_codes(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.misc.pcapng import PCAPNG, _option_key

        option_map = PCAPNG.__dict__['__option__']

        self.assertEqual(option_map[_option_key(OptionType.if_name)], 'if_name')
        self.assertEqual(option_map[_option_key(OptionType.epb_flags)], 'epb_flags')
        self.assertEqual(option_map[_option_key(OptionType.pack_flags)], 'pack_flags')
        self.assertEqual(option_map.get(_option_key(OptionType.get(2, namespace='opt')), 'unknown'), 'unknown')

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

        # GH-361: the epoch is 2000 units at if_tsresol=1000, i.e. 2s, plus the
        # 10s if_tsoffset -- 12s, and nothing else. It used to come back as 3612,
        # the same instant with this interface's if_tzone (+01:00) *added* to it,
        # which is 3600s of pure error: a PCAP-NG timestamp is an offset from the
        # UNIX epoch and so carries no timezone. The datetime is the one place
        # ``tz`` still shows, as the zone the instant is rendered in, and it
        # names the very same instant -- which the two returns did not before.
        ts_datetime, ts_decimal = pcapng._read_timestamp(0, 2000)
        self.assertEqual(ts_datetime, datetime.datetime.fromtimestamp(12, tz))
        self.assertEqual(ts_decimal, decimal.Decimal(12))
        self.assertEqual(ts_datetime.timestamp(), float(ts_decimal))
        # and the round trip closes, which it could not while the two disagreed
        self.assertEqual(pcapng._make_timestamp(ts_decimal), (0, 2000))

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
            # GH-361: UTC, not the reading host's zone -- the format's own
            # default, to match the two above
            self.assertEqual(pcapng.ts_timezone, datetime.timezone.utc)
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
        # GH-361: an interface that names no if_tzone gets UTC, not the reading
        # host's zone -- which is what made one file parse to different instants
        # on different machines
        self.assertEqual(pcapng._get_timezone(0), datetime.timezone.utc)
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
        # GH-361: 1 unit at if_tsresol=1e9 plus the 2s if_tsoffset. The leading
        # ``Decimal(7200)`` this used to carry was this interface's if_tzone
        # (+02:00) leaking into the epoch; the fallback datetime above is aware
        # UTC either way, so the two used to name different instants.
        self.assertEqual(epoch, decimal.Decimal(2) + decimal.Decimal('0.000000001'))
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
        custom_option = OptionType.get(65000)
        from pcapkit.protocols.misc.pcapng import _option_key

        custom_option_key = _option_key(custom_option)
        custom_record = 65000
        custom_secrets = 65000
        originals = {
            'proto': (proto_code in proto_map, proto_map.get(proto_code)),
            'block': (custom_block in block_map, block_map.get(custom_block)),
            'option': (custom_option_key in option_map, option_map.get(custom_option_key)),
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
                (option_map, custom_option_key, originals['option']),
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
        isb_block_field = schema_pcapng.pcapng_block_selector({
            'type': BlockType.Interface_Statistics_Block,
            '__length__': 28,
        })
        self.assertIs(isb_block_field.schema, schema_pcapng.InterfaceStatisticsBlock)

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
        ], namespace='opt')
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
        opts_from_data, data_opt_len = pcapng._make_pcapng_options(data_options, namespace='opt')
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
        payload_block = types.SimpleNamespace(
            __payload__='packet_data',
            __fields__={'packet_data': object()},
            get_payload=mock.Mock(return_value=b'payload'),
        )
        unpacker.__schema__ = types.SimpleNamespace(
            unpack=mock.Mock(return_value=types.SimpleNamespace(block=payload_block)))
        unpacker._file = io.BytesIO(b'0123456789ab')
        unpacker._ctx = types.SimpleNamespace(section=types.SimpleNamespace(byteorder='little'))
        unpacker._byte = 'big'
        unpacker.read = mock.Mock(return_value=DummyData(length=12))
        data = unpacker.unpack(12, __packet__={})
        self.assertEqual(data['packet'], b'payload')
        self.assertEqual(unpacker._byte, 'little')
        payload_block.get_payload.assert_called_once_with()

        cached_block = types.SimpleNamespace(
            __payload__='packet_data',
            __fields__={'packet_data': object()},
            get_payload=mock.Mock(return_value=b'cached'),
        )
        unpacker.__header__ = types.SimpleNamespace(block=cached_block)
        unpacker.read = mock.Mock(return_value=DummyData(length=12))
        self.assertEqual(unpacker.unpack(12)['packet'], b'cached')
        unpacker.__schema__.unpack.assert_called_once()
        cached_block.get_payload.assert_called_once_with()

        no_ctx_unpacker = object.__new__(PCAPNG)
        no_ctx_unpacker.__header__ = None
        no_payload_block = types.SimpleNamespace(
            __payload__='payload',
            __fields__={},
            get_payload=mock.Mock(return_value=b'unused'),
        )
        no_ctx_unpacker.__schema__ = types.SimpleNamespace(
            unpack=mock.Mock(return_value=types.SimpleNamespace(block=no_payload_block)))
        no_ctx_unpacker._file = io.BytesIO(b'0123456789ab')
        no_ctx_unpacker._ctx = None
        no_ctx_unpacker._byte = 'big'
        no_ctx_unpacker.read = mock.Mock(return_value=DummyData(length=12))
        self.assertEqual(no_ctx_unpacker.unpack(12)['packet'], b'')
        self.assertEqual(no_ctx_unpacker._byte, 'big')
        no_payload_block.get_payload.assert_not_called()

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
        from pcapkit.protocols.misc.pcapng import _option_key

        option_key = _option_key(option_code)
        record_code = RecordType.get(65001)
        secrets_code = SecretsType.get(65001)
        option_map = PCAPNG.__dict__['__option__']
        record_map = PCAPNG.__dict__['__record__']
        secrets_map = PCAPNG.__dict__['__secrets__']
        missing = object()
        originals = (
            option_map.get(option_key, missing),
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
            option_map[option_key] = (custom_option_parser, custom_option_constructor)
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
            ], namespace='opt')
            self.assertEqual(list_options[-1].type, OptionType.opt_endofopt)
            self.assertEqual(list_options[0].data, b'list')

            pcapng._opt = collections.Counter()
            no_end_options, _ = pcapng._make_pcapng_options([
                (OptionType.opt_comment, {'comment': 'no-end'}),
            ], namespace='opt')
            self.assertNotEqual(no_end_options[-1].type, OptionType.opt_endofopt)

            pcapng._opt = collections.Counter()
            dict_options, _ = pcapng._make_pcapng_options(OrderedMultiDict([
                (option_code, DummyData(data=b'dict')),
                (OptionType.opt_endofopt, object()),
            ]), namespace='opt')
            self.assertEqual(dict_options[0].data, b'dict')
            self.assertEqual(dict_options[-1].type, OptionType.opt_endofopt)

            pcapng._opt = collections.Counter()
            dict_options_no_end, _ = pcapng._make_pcapng_options(OrderedMultiDict([
                (OptionType.opt_comment, DummyData(comment='dict-no-end')),
            ]), namespace='opt')
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
            restore(option_map, option_key, originals[0])
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

    def test_pcapng_custom_block_data_spans_padding_and_options(self) -> None:
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.protocols.schema.misc.pcapng import CustomBlock

        # A Custom Block carries no length for its custom data, so everything
        # between the private enterprise number and the trailing block total
        # length -- the custom data, its padding, and the block options -- is
        # ``data``, and there is no separate padding field to size.
        custom = pad32(b'hello')
        options = tlv(0, b'')  # opt_endofopt
        raw = block_body(struct.pack('<I', 0x00FFFFFF) + custom + options)

        schema = CustomBlock.unpack(raw, len(raw), {'byteorder': 'little'})

        self.assertEqual(schema.length, schema.length2)
        self.assertEqual(schema.length, len(raw) + 4)
        self.assertEqual(schema.pen, 0x00FFFFFF)
        self.assertEqual(schema.data, custom + options)
        self.assertEqual(len(schema), len(raw))
        self.assertFalse(hasattr(schema, 'padding'))

        # ... and the maker keeps the block total length a multiple of four
        # even when the custom data is not aligned.
        pcapng = object.__new__(PCAPNG)
        made = pcapng._make_block_cb(pen=1, data=b'odd')
        self.assertEqual(made.length, made.length2)
        self.assertEqual(made.length % 4, 0)
        self.assertEqual(made.data, pad32(b'odd'))

    def test_pcapng_isb_option_area_excludes_trailing_block_length(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.schema.misc.pcapng import InterfaceStatisticsBlock

        # The ISB's fixed fields occupy 24 octets: block type, block total
        # length, interface ID, the 64-bit timestamp, and the trailing block
        # total length. Sizing the option area as ``length - 20`` lets the
        # options field read the trailing block total length as if it were an
        # option, so the block is consumed 8 octets past its end.
        options = tlv(2, struct.pack('<II', 1, 2)) + tlv(0, b'')  # isb_starttime, opt_endofopt
        raw = block_body(struct.pack('<III', 0, 3, 4) + options)

        schema = InterfaceStatisticsBlock.unpack(raw, len(raw), {'byteorder': 'little'})

        self.assertEqual(schema.length, schema.length2)
        self.assertEqual(schema.length, len(raw) + 4)
        self.assertEqual(schema.interface_id, 0)
        self.assertEqual(schema.timestamp_high, 3)
        self.assertEqual(schema.timestamp_low, 4)
        self.assertEqual([option.type for option in schema.options],
                         [OptionType.isb_starttime, OptionType.opt_endofopt])
        self.assertEqual(schema.options[0].timestamp_high, 1)
        self.assertEqual(schema.options[0].timestamp_low, 2)
        self.assertEqual(schema.padding, b'')
        self.assertEqual(len(schema), len(raw))

    def test_pcapng_option_field_hands_unconsumed_remainder_to_next_field(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.schema.misc.pcapng import InterfaceStatisticsBlock

        # An option list that ends at ``opt_endofopt`` before the option area
        # does leaves a remainder, reported through ``__option_padding__``.
        # The padding field which sizes itself from it has to read *that*
        # remainder, not the same number of octets from beyond the options.
        options = tlv(2, struct.pack('<II', 1, 2)) + tlv(0, b'') + bytes(8)
        raw = block_body(struct.pack('<III', 0, 3, 4) + options)

        schema = InterfaceStatisticsBlock.unpack(raw, len(raw), {'byteorder': 'little'})

        self.assertEqual(schema.length, schema.length2)
        self.assertEqual(schema.length, len(raw) + 4)
        self.assertEqual([option.type for option in schema.options],
                         [OptionType.isb_starttime, OptionType.opt_endofopt])
        self.assertEqual(schema.padding, bytes(8))
        self.assertEqual(len(schema), len(raw))

    def test_pcapng_nrb_ipv6_record_name_follows_sixteen_octet_address(self) -> None:
        from pcapkit.const.pcapng.record_type import RecordType
        from pcapkit.protocols.schema.misc.pcapng import NameResolutionBlock

        # An ``nrb_record_ipv6`` record value is a 16-octet address followed by
        # zero-terminated names, so the names span ``length - 16``. Sizing them
        # as ``length - 4`` -- the IPv4 record's arithmetic -- over-reads by 12
        # octets and swallows whatever record follows.
        v6_value = ip_address('2001:db8::1').packed + b'host6.example\x00'
        v4_value = ip_address('192.0.2.1').packed + b'host4.example\x00'
        records = tlv(2, v6_value) + tlv(1, v4_value) + tlv(0, b'')
        raw = block_body(records)

        schema = NameResolutionBlock.unpack(raw, len(raw), {'byteorder': 'little'})

        self.assertEqual(schema.length, schema.length2)
        self.assertEqual([record.type for record in schema.records],
                         [RecordType.nrb_record_ipv6,
                          RecordType.nrb_record_ipv4,
                          RecordType.nrb_record_end])
        self.assertEqual(len(schema.records[0]), 4 + len(pad32(v6_value)))
        self.assertEqual(schema.records[0].ip, ip_address('2001:db8::1'))
        self.assertEqual(schema.records[0].names, ['host6.example'])
        self.assertEqual(schema.records[1].ip, ip_address('192.0.2.1'))
        self.assertEqual(schema.records[1].names, ['host4.example'])
        self.assertEqual(schema.mapping.getlist(ip_address('2001:db8::1')), ['host6.example'])
        self.assertEqual(len(schema), len(raw))

    def test_pcapng_nrb_options_read_from_inside_the_block(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.const.pcapng.record_type import RecordType
        from pcapkit.protocols.schema.misc.pcapng import NameResolutionBlock

        # The NRB is the only block with two consecutive option fields: the
        # record area's size is known only once its records have been parsed,
        # so ``records`` is declared over the record *and* option areas and the
        # options have to be read from the remainder it did not consume.
        v4_value = ip_address('192.0.2.1').packed + b'host4.example\x00'
        records = tlv(1, v4_value) + tlv(0, b'')

        for name in ('dns.example.', 'dns.example'):
            with self.subTest(dnsname=name):
                options = tlv(2, name.encode()) + tlv(0, b'')  # ns_dnsname, opt_endofopt
                raw = block_body(records + options)

                schema = NameResolutionBlock.unpack(raw, len(raw), {'byteorder': 'little'})

                self.assertEqual(schema.length, schema.length2)
                self.assertEqual(schema.length, len(raw) + 4)
                self.assertEqual([record.type for record in schema.records],
                                 [RecordType.nrb_record_ipv4, RecordType.nrb_record_end])
                self.assertEqual([option.type for option in schema.options],
                                 [OptionType.ns_dnsname, OptionType.opt_endofopt])
                self.assertEqual(schema.options[0].name, name)
                # the option is padded to a 32-bit boundary whether or not its
                # value length happens to be a multiple of four
                self.assertEqual(len(schema.options[0]), 4 + len(pad32(name.encode())))
                self.assertEqual(schema.padding, b'')
                self.assertEqual(len(schema), len(raw))

    def test_pcapng_obsolete_packet_block_uses_sixteen_bit_ids(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.schema.misc.pcapng import PacketBlock

        # The obsolete Packet Block packs Interface ID and Drops Count into one
        # 32-bit word, which is what the option area's ``length - 32`` overhead
        # assumes; declaring them as 32-bit fields reads every later field from
        # four octets too far in.
        packet_data = bytes.fromhex('ffffffffffff001122334455') + b'\x08\x06' + bytes(28)
        options = tlv(2, struct.pack('<I', 0)) + tlv(0, b'')  # pack_flags, opt_endofopt
        raw = block_body(struct.pack('<HHIIII', 0, 7, 1, 2, len(packet_data), len(packet_data)) +
                         pad32(packet_data) + options)

        schema = PacketBlock.unpack(raw, len(raw), {'byteorder': 'little'})

        self.assertEqual(schema.length, schema.length2)
        self.assertEqual(schema.length, len(raw) + 4)
        self.assertEqual(schema.interface_id, 0)
        self.assertEqual(schema.drop_count, 7)
        self.assertEqual(schema.timestamp_high, 1)
        self.assertEqual(schema.timestamp_low, 2)
        self.assertEqual(schema.captured_length, len(packet_data))
        self.assertEqual(schema.original_length, len(packet_data))
        self.assertEqual(schema.packet_data, packet_data)
        self.assertEqual(schema.padding_data, bytes(2))
        self.assertEqual([option.type for option in schema.options],
                         [OptionType.pack_flags, OptionType.opt_endofopt])
        self.assertEqual(len(schema), len(raw))

    def test_pcapng_read_block_packet_resolves_linktype_without_info(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.protocols.schema.misc.pcapng import PacketBlock, PCAPNG as Header

        # ``_read_block_packet`` runs before ``self._info`` exists, so it has to
        # resolve the link type from the schema's interface ID the way the EPB
        # and SPB readers do, rather than through the ``linktype`` property.
        pcapng = object.__new__(PCAPNG)
        pcapng._sect = 1
        pcapng._fnum = 2
        pcapng._opt = collections.Counter()
        pcapng._type = BlockType.Packet_Block
        pcapng._ctx = types.SimpleNamespace(
            interfaces=[types.SimpleNamespace(linktype=LinkType.ETHERNET)],
        )
        pcapng._read_timestamp = lambda high, low, interface_id=0: (
            datetime.datetime.fromtimestamp(0, datetime.timezone.utc),
            decimal.Decimal(0),
        )
        decoded = []
        pcapng._decode_next_layer = lambda data, proto=None, length=None, packet=None: (
            decoded.append((proto, length)) or data
        )
        self.assertFalse(hasattr(pcapng, '_info'))

        with mock.patch('pcapkit.protocols.misc.pcapng.warn'):
            block = pcapng._read_block_packet(
                PacketBlock(length=36, interface_id=0, drop_count=1, timestamp_high=0,
                            timestamp_low=0, captured_length=4, original_length=4,
                            packet_data=b'data', options=[], length2=36),
                header=Header(type=BlockType.Packet_Block, block=b''),
            )

        self.assertEqual(block.drop_count, 1)
        self.assertEqual(decoded, [(LinkType.ETHERNET, 4)])

    ##########################################################################
    # Write path: packing block schemas (#366).
    ##########################################################################

    @staticmethod
    def _all_block_schemas():
        """Every PCAP-NG block schema, populated well enough to be packed.

        Returns a list of ``(label, block type, schema)`` triples covering all
        eleven block schemas of
        :mod:`pcapkit.protocols.schema.misc.pcapng`, each with the block total
        length its own fields imply.

        """
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.secrets_type import SecretsType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.schema.misc.pcapng import (CustomBlock, DecryptionSecretsBlock,
                                                          EnhancedPacketBlock,
                                                          InterfaceDescriptionBlock,
                                                          InterfaceStatisticsBlock,
                                                          NameResolutionBlock, PacketBlock,
                                                          SectionHeaderBlock, SimplePacketBlock,
                                                          SystemdJournalExportBlock, UnknownBlock)

        payload = b'\xde\xad\xbe\xef'
        return [
            ('UnknownBlock', BlockType.get(0xFFFF_0000),
             UnknownBlock(length=12, body=b'', length2=12)),
            ('SectionHeaderBlock', BlockType.Section_Header_Block,
             SectionHeaderBlock(length=28, magic=0x1A2B3C4D, major=1, minor=0,
                                section_length=-1, options=[], length2=28)),
            ('InterfaceDescriptionBlock', BlockType.Interface_Description_Block,
             InterfaceDescriptionBlock(length=20, linktype=LinkType.ETHERNET, snaplen=0,
                                       options=[], length2=20)),
            ('EnhancedPacketBlock', BlockType.Enhanced_Packet_Block,
             EnhancedPacketBlock(length=36, interface_id=0, timestamp_high=0, timestamp_low=0,
                                 captured_len=len(payload), original_len=len(payload),
                                 packet_data=payload, options=[], length2=36)),
            # captured_len=5 needs three genuine padding octets, unlike the
            # 32-bit aligned case above
            ('EnhancedPacketBlock, captured_len=5', BlockType.Enhanced_Packet_Block,
             EnhancedPacketBlock(length=40, interface_id=0, timestamp_high=0, timestamp_low=0,
                                 captured_len=5, original_len=5, packet_data=payload + b'\x00',
                                 options=[], length2=40)),
            ('SimplePacketBlock', BlockType.Simple_Packet_Block,
             SimplePacketBlock(length=20, original_len=len(payload), packet_data=payload,
                               length2=20)),
            ('NameResolutionBlock', BlockType.Name_Resolution_Block,
             NameResolutionBlock(length=12, records=[], options=[], length2=12)),
            ('InterfaceStatisticsBlock', BlockType.Interface_Statistics_Block,
             InterfaceStatisticsBlock(length=24, interface_id=0, timestamp_high=0,
                                      timestamp_low=0, options=[], length2=24)),
            ('SystemdJournalExportBlock', BlockType.systemd_Journal_Export_Block,
             SystemdJournalExportBlock(length=12, entry=b'', length2=12)),
            ('DecryptionSecretsBlock', BlockType.Decryption_Secrets_Block,
             DecryptionSecretsBlock(length=24, secrets_type=SecretsType.TLS_Key_Log,
                                    secrets_length=len(payload), secrets_data=payload,
                                    options=[], length2=24)),
            ('CustomBlock', BlockType.Custom_Block_that_rewriters_can_copy_into_new_files,
             CustomBlock(length=16, pen=0, data=b'', length2=16)),
            ('PacketBlock', BlockType.Packet_Block,
             PacketBlock(length=36, interface_id=0, drop_count=0, timestamp_high=0,
                         timestamp_low=0, captured_length=len(payload),
                         original_length=len(payload), packet_data=payload, options=[],
                         length2=36)),
        ]

    def test_pcapng_every_block_schema_packs(self) -> None:
        # Regression for #366: seven of the eleven block schemas could not be
        # packed at all, from four independent causes -- a ``BytesField``
        # standing in for a ``PaddingField``, an option length callback reading
        # a ``PaddingField``'s value, ``Schema.pre_pack`` never being called,
        # and ``packet['__option_padding__']`` being subscripted on the packing
        # path where only the unpacking path sets it. Since the SHB was among
        # them, no valid PCAP-NG file could be written at all.
        for label, _, schema in self._all_block_schemas():
            with self.subTest(schema=label):
                packed = bytes(schema)
                # every block schema packs the block without its 4-octet block
                # type, so it is four short of the block total length it declares
                self.assertEqual(len(packed) + 4, schema.length)

    def test_pcapng_padding_fields_are_padding_fields(self) -> None:
        # Regression for #366, cause 1: ``PacketBlock.padding_data`` and
        # ``DecryptionSecretsBlock.padding_data`` were declared ``BytesField``,
        # which ``Schema.pack`` does not fill in, so packing them handed
        # ``struct.pack`` the ``NoValue`` sentinel.
        from pcapkit.corekit.fields.strings import PaddingField
        from pcapkit.protocols.schema.misc.pcapng import (DecryptionSecretsBlock,
                                                          EnhancedPacketBlock, PacketBlock)

        for schema in (EnhancedPacketBlock, PacketBlock, DecryptionSecretsBlock):
            with self.subTest(schema=schema.__name__):
                self.assertIsInstance(schema.__fields__['padding_data'], PaddingField)
                self.assertIsInstance(schema.__fields__['padding_opts'], PaddingField)

    def test_pcapng_option_length_callbacks_survive_missing_pack_keys(self) -> None:
        # Regression for #366, causes 2 and 4: the option length callbacks read
        # ``pkt['padding_data']`` and ``pkt['__option_padding__']``, neither of
        # which is a key in the packet data while packing.
        from pcapkit.protocols.schema.misc.pcapng import (DecryptionSecretsBlock,
                                                          EnhancedPacketBlock,
                                                          InterfaceDescriptionBlock,
                                                          InterfaceStatisticsBlock,
                                                          NameResolutionBlock, PacketBlock,
                                                          SectionHeaderBlock)

        cases = {
            'EnhancedPacketBlock': (EnhancedPacketBlock, {'length': 36, 'captured_len': 4}),
            'PacketBlock': (PacketBlock, {'length': 44, 'captured_length': 4}),
            'DecryptionSecretsBlock': (DecryptionSecretsBlock, {'length': 24,
                                                                'secrets_length': 4}),
            'SectionHeaderBlock': (SectionHeaderBlock, {'length': 28}),
            'InterfaceDescriptionBlock': (InterfaceDescriptionBlock, {'length': 20}),
            'NameResolutionBlock': (NameResolutionBlock, {'length': 12}),
            'InterfaceStatisticsBlock': (InterfaceStatisticsBlock, {'length': 24}),
        }
        for label, (schema, packet) in cases.items():
            with self.subTest(schema=label):
                for name, field in schema.__fields__.items():
                    if field.__class__.__name__ not in ('OptionField', 'PaddingField'):
                        continue
                    with self.subTest(field=name):
                        # the callback must not raise on a packet dict that
                        # carries no padding field values and no
                        # ``__option_padding__`` key, i.e. the packing case
                        self.assertGreaterEqual(field(dict(packet)).length, 0)

    def test_pcapng_section_header_block_packs_byteorder_magic(self) -> None:
        # Regression for #366, cause 3: nothing in the package called
        # ``Schema.pre_pack``, so ``SectionHeaderBlock.pre_pack`` never got to
        # seed ``packet['match']`` and packing an SHB raised ``KeyError``.
        from pcapkit.protocols.schema.misc.pcapng import SectionHeaderBlock

        for byteorder, endian in (('big', '>'), ('little', '<')):
            with self.subTest(byteorder=byteorder):
                schema = SectionHeaderBlock(length=28, magic=0x1A2B3C4D, major=1, minor=0,
                                            section_length=-1, options=[], length2=28)
                packed = schema.pack({'byteorder': byteorder})

                length, magic, major, minor, section_length, length2 = struct.unpack(
                    f'{endian}IIHHqI', packed)
                self.assertEqual(length, 28)
                self.assertEqual(length2, 28)
                self.assertEqual(magic, 0x1A2B3C4D)
                self.assertEqual((major, minor), (1, 0))
                # section length not specified, i.e. all ones on the wire
                self.assertEqual(section_length, -1)
                self.assertEqual(packed[12:20], b'\xff' * 8)

    def test_pcapng_section_header_block_round_trips_through_bytes(self) -> None:
        # Regression for #366: the point of the write path is that what it
        # writes can be read back. Build a whole capture out of ``bytes()`` on
        # the block schemas, then dissect it with the public reader and check
        # the fields survived.
        import tempfile

        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.interface import extract
        from pcapkit.protocols.schema.misc.pcapng import PCAPNG as Header
        from pcapkit.protocols.schema.misc.pcapng import (CommentOption, EndOfOption,
                                                          EnhancedPacketBlock,
                                                          InterfaceDescriptionBlock,
                                                          InterfaceStatisticsBlock,
                                                          SectionHeaderBlock, SimplePacketBlock)

        frame = (b'\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x08\x00'
                 b'\x45\x00\x00\x1c\x00\x01\x00\x00\x40\x11\x00\x00'
                 b'\x0a\x00\x00\x01\x0a\x00\x00\x02'
                 b'\x04\xd2\x16\x2e\x00\x08\x00\x00')      # eth / ipv4 / udp, 42 octets
        self.assertEqual(len(frame), 42)

        comment = CommentOption(type=OptionType.opt_comment, length=6, comment='hello!')
        endofopt = EndOfOption(type=OptionType.opt_endofopt, length=0)
        options = [comment, endofopt]
        # 4 octets of option header plus a 32-bit aligned 6-octet comment, then
        # the 4 octets of the end-of-option-list marker
        options_length = 4 + 8 + 4

        shb = SectionHeaderBlock(length=28 + options_length, magic=0x1A2B3C4D, major=1,
                                 minor=0, section_length=-1, options=options,
                                 length2=28 + options_length)
        idb = InterfaceDescriptionBlock(length=20, linktype=LinkType.ETHERNET, snaplen=0xFFFF,
                                        options=[], length2=20)
        epb = EnhancedPacketBlock(length=32 + 44, interface_id=0, timestamp_high=0,
                                  timestamp_low=1_000_000, captured_len=len(frame),
                                  original_len=len(frame), packet_data=frame, options=[],
                                  length2=32 + 44)
        spb = SimplePacketBlock(length=16 + 44, original_len=len(frame),
                                packet_data=frame + bytes(-len(frame) % 4), length2=16 + 44)
        isb = InterfaceStatisticsBlock(length=24, interface_id=0, timestamp_high=0,
                                       timestamp_low=0, options=[], length2=24)

        capture = b''.join(bytes(Header(type=block_type, block=block)) for block_type, block in (
            (BlockType.Section_Header_Block, shb),
            (BlockType.Interface_Description_Block, idb),
            (BlockType.Enhanced_Packet_Block, epb),
            (BlockType.Simple_Packet_Block, spb),
            (BlockType.Interface_Statistics_Block, isb),
        ))

        handle, path = tempfile.mkstemp(suffix='.pcapng')
        try:
            with os.fdopen(handle, 'wb') as file:
                file.write(capture)
            extractor = extract(fin=path, store=True, nofile=True)
        finally:
            os.unlink(path)

        # the two packet blocks are the frames; the SHB, IDB and ISB are context
        self.assertEqual(len(extractor.frame), 2)

        section = extractor.engine._ctx_list[0].section
        self.assertEqual(section.byteorder, sys.byteorder)
        self.assertEqual(section.version.major, 1)
        self.assertEqual(section.version.minor, 0)
        self.assertEqual(section.section_length, -1)
        self.assertEqual(section.options[OptionType.opt_comment].comment, 'hello!')

        interfaces = extractor.engine._ctx_list[0].interfaces
        self.assertEqual(len(interfaces), 1)
        self.assertEqual(interfaces[0].linktype, LinkType.ETHERNET)
        self.assertEqual(interfaces[0].snaplen, 0xFFFF)

        epb_read = extractor.frame[0]
        self.assertEqual(epb_read.info.type, BlockType.Enhanced_Packet_Block)
        self.assertEqual(epb_read.info.interface_id, 0)
        self.assertEqual(epb_read.info.captured_len, len(frame))
        self.assertEqual(epb_read.info.original_len, len(frame))
        self.assertEqual(str(epb_read.protochain), 'Ethernet:IPv4:UDP')
        ipv4 = epb_read.info.ethernet.ipv4
        self.assertEqual((str(ipv4.src), str(ipv4.dst)), ('10.0.0.1', '10.0.0.2'))
        self.assertEqual((int(ipv4.udp.srcport), int(ipv4.udp.dstport)), (1234, 5678))

        spb_read = extractor.frame[1]
        self.assertEqual(spb_read.info.type, BlockType.Simple_Packet_Block)
        self.assertEqual(spb_read.info.original_len, len(frame))
        self.assertEqual(str(spb_read.protochain), 'Ethernet:IPv4:UDP')

        statistics = extractor.engine._ctx_list[0].statistics
        self.assertEqual(len(statistics), 1)
        self.assertEqual(statistics[0].interface_id, 0)

    ##########################################################################
    # Signed numeric fields (#366, uncovered by the SHB repro).
    ##########################################################################

    def test_signed_number_fields_pack_negative_values(self) -> None:
        # Uncovered while fixing #366: ``NumberField.pre_process`` masks the
        # value against the *unsigned* bit mask, which turns any negative value
        # into a pattern ``struct.pack`` rejects for a signed template. No
        # signed field in the library could write a negative value, which is
        # what a PCAP-NG section length of -1 (not specified) needs.
        from pcapkit.corekit.fields.numbers import (Int8Field, Int16Field, Int32Field, Int64Field,
                                                    UInt32Field)

        cases = {
            Int8Field: ('b', 1),
            Int16Field: ('h', 2),
            Int32Field: ('i', 4),
            Int64Field: ('q', 8),
        }
        for field_type, (code, size) in cases.items():
            for value in (-1, -8, 0, 7):
                with self.subTest(field=field_type.__name__, value=value):
                    field = field_type()({})
                    self.assertEqual(field.pack(value, {}),
                                     struct.pack(f'>{code}', value))
                    self.assertEqual(len(field.pack(value, {})), size)

        # unsigned fields keep truncating, i.e. -1 stays all ones
        self.assertEqual(UInt32Field()({}).pack(-1, {}), b'\xff\xff\xff\xff')

    ##########################################################################
    # Option namespaces per block (#365).
    ##########################################################################

    def test_pcapng_make_block_uses_its_own_option_namespace(self) -> None:
        # Regression for #365: all eight ``_make_block_*`` methods passed
        # ``namespace='shb'``, which is not a namespace anywhere -- neither on
        # ``OptionType`` nor in the schema option registry -- so every raw-bytes
        # option was misclassified as ``shb_unknown_*`` and ``OptionType`` was
        # permanently extended with a member per unrecognised code.
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.const.pcapng.secrets_type import SecretsType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.protocols.schema.misc.pcapng import Option

        # ``'shb'`` names no namespace on either side of the wire
        namespaces = set(dict(OptionType.__members_ns__)) | set(dict(Option.registry))
        self.assertNotIn('shb', namespaces)

        recorded = []

        pcapng = object.__new__(PCAPNG)
        pcapng._byte = 'little'
        pcapng._opt = collections.Counter()
        pcapng._ctx = None
        pcapng._make_pcapng_options = lambda options, namespace: (
            recorded.append(namespace) or ([], 0)
        )

        raw = [b'\x00\x00\x00\x00']       # opt_endofopt, valid in every namespace
        calls = [
            ('shb', BlockType.Section_Header_Block, 'opt',
             lambda: pcapng._make_block_shb(options=raw)),
            ('idb', BlockType.Interface_Description_Block, 'if',
             lambda: pcapng._make_block_idb(linktype=LinkType.ETHERNET, options=raw)),
            ('epb', BlockType.Enhanced_Packet_Block, 'epb',
             lambda: pcapng._make_block_epb(interface_id=0, timestamp=0,
                                            packet_data=b'data', options=raw)),
            ('nrb', BlockType.Name_Resolution_Block, 'ns',
             lambda: pcapng._make_block_nrb(records=[], options=raw)),
            ('isb', BlockType.Interface_Statistics_Block, 'isb',
             lambda: pcapng._make_block_isb(interface_id=0, timestamp=0, options=raw)),
            ('dsb', BlockType.Decryption_Secrets_Block, 'dsb',
             lambda: pcapng._make_block_dsb(secrets_type=SecretsType.get(0xDEAD_BEEF),
                                            secrets_data=b'data', options=raw)),
            ('cb', BlockType.Custom_Block_that_rewriters_can_copy_into_new_files, 'opt',
             lambda: pcapng._make_block_cb(pen=0, data=b'data', options=raw)),
            ('packet', BlockType.Packet_Block, 'pack',
             lambda: pcapng._make_block_packet(interface_id=0, timestamp=0,
                                               packet_data=b'data', options=raw)),
        ]

        for name, block_type, expected, call in calls:
            with self.subTest(block=name):
                recorded.clear()
                pcapng._type = block_type
                with mock.patch('pcapkit.protocols.misc.pcapng.warn'):
                    call()
                self.assertEqual(recorded, [expected])
                # the namespace has to be a real one, otherwise every code in
                # it resolves as unknown
                self.assertIn(expected, namespaces)

        # ... and nothing minted a bogus ``shb_*`` member along the way
        self.assertNotIn('shb', set(dict(OptionType.__members_ns__)))
        self.assertEqual([name for name in OptionType.__members__ if name.startswith('shb_')], [])

    def test_pcapng_make_block_namespace_matches_read_side_registry(self) -> None:
        # The read side is the authority on which registry a block's options
        # come from: each block schema's ``OptionField`` names it explicitly.
        # #365's fix has to agree with it, block for block.
        from pcapkit.protocols.schema.misc.pcapng import (DecryptionSecretsBlock,
                                                          EnhancedPacketBlock,
                                                          InterfaceDescriptionBlock,
                                                          InterfaceStatisticsBlock,
                                                          NameResolutionBlock, Option, PacketBlock,
                                                          SectionHeaderBlock)

        expected = {
            SectionHeaderBlock: 'opt',
            InterfaceDescriptionBlock: 'if',
            EnhancedPacketBlock: 'epb',
            NameResolutionBlock: 'ns',
            InterfaceStatisticsBlock: 'isb',
            DecryptionSecretsBlock: 'dsb',
            PacketBlock: 'pack',
        }
        for schema, namespace in expected.items():
            with self.subTest(schema=schema.__name__):
                self.assertIs(schema.__fields__['options'].registry,
                              dict(Option.registry)[namespace])

    ##########################################################################
    # Interface ID bounds (#367).
    ##########################################################################

    def test_pcapng_out_of_range_interface_id_is_a_format_error(self) -> None:
        # Regression for #367: the engine's bounds guards ran after the block
        # had been parsed, and the parse itself indexed the section's interface
        # list, so an out-of-range interface ID escaped as a bare ``IndexError``
        # from ``_get_timezone`` instead of the intended ``FormatError``.
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import FormatError

        tags = {
            BlockType.Enhanced_Packet_Block: 'EPB',
            BlockType.Simple_Packet_Block: 'SPB',
            BlockType.Packet_Block: 'Packet',
            BlockType.Interface_Statistics_Block: 'ISB',
        }
        getters = ('_get_resolution', '_get_offset', '_get_timezone', '_get_linktype')

        pcapng = object.__new__(PCAPNG)
        # a section that describes two interfaces, as #367's capture does
        pcapng._ctx = types.SimpleNamespace(interfaces=[object(), object()])

        for block_type, tag in tags.items():
            pcapng._type = block_type
            for getter in getters:
                if getter == '_get_linktype' and block_type not in PCAPNG.PACKET_TYPES:
                    continue        # documented to be unavailable off a packet block
                for interface_id in (2, 7, -1):
                    with self.subTest(block=tag, getter=getter, interface_id=interface_id):
                        with self.assertRaises(FormatError) as context:
                            getattr(pcapng, getter)(interface_id)
                        message = str(context.exception)
                        self.assertIn(f'PCAP-NG: [{tag}]', message)
                        self.assertIn(f'invalid interface ID: {interface_id}', message)

        # an in-range ID still resolves, i.e. the guard is a bound and not a ban
        pcapng._type = BlockType.Enhanced_Packet_Block
        self.assertIs(pcapng._get_interface(1), pcapng._ctx.interfaces[1])

    def test_pcapng_interface_id_bounds_reported_for_unlisted_blocks(self) -> None:
        # A block that is not in ``INTERFACE_ID_BLOCK_TAGS`` still has to report
        # a ``FormatError`` rather than an ``IndexError``, naming the block type.
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import FormatError

        pcapng = object.__new__(PCAPNG)
        pcapng._ctx = types.SimpleNamespace(interfaces=[])
        pcapng._type = BlockType.Name_Resolution_Block

        with self.assertRaises(FormatError) as context:
            pcapng._get_interface(0)
        self.assertIn('invalid interface ID: 0', str(context.exception))
        self.assertIn(str(BlockType.Name_Resolution_Block), str(context.exception))

    ##########################################################################
    # Section header block options and the section byte order (#368).
    ##########################################################################

    @staticmethod
    def _section_header_bytes(byteorder: str) -> bytes:
        """A Section Header Block, options and all, in the given byte order.

        The buffer starts at the block total length, i.e. it is what a
        :class:`~pcapkit.protocols.schema.misc.pcapng.SectionHeaderBlock` is
        handed, without the leading 4-octet block type.

        """
        endian = '>' if byteorder == 'big' else '<'

        def option(code: int, value: bytes) -> bytes:
            return (struct.pack(f'{endian}HH', code, len(value))
                    + value + bytes(-len(value) % 4))

        options = (option(2, b'Apple MBP')            # shb_hardware
                   + option(3, b'OS-X 10.10.5')       # shb_os
                   + option(4, b'pcap_writer.lua')    # shb_userappl
                   + option(1, b'test001')            # opt_comment
                   + option(0, b''))                  # opt_endofopt
        length = 28 + len(options)
        return (struct.pack(f'{endian}IIHHq', length, 0x1A2B3C4D, 1, 0, -1)
                + options + struct.pack(f'{endian}I', length))

    def test_pcapng_section_header_options_use_the_section_byteorder(self) -> None:
        # Regression for #368: an SHB's own options were read with the host byte
        # order rather than the one its Byte-Order Magic declares, because
        # ``packet['byteorder']`` is only seeded from an existing section
        # context and the first SHB of a file has none by construction. In a
        # big-endian section every option was replaced by one bogus
        # ``opt_unknown`` whose byte-swapped length swallowed the option area.
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.protocols.schema.misc.pcapng import SectionHeaderBlock

        expected = [
            (2, 9, b'Apple MBP'),
            (3, 12, b'OS-X 10.10.5'),
            (4, 15, b'pcap_writer.lua'),
            (OptionType.opt_comment, 7, 'test001'),
            (OptionType.opt_endofopt, 0, None),
        ]

        for byteorder in ('big', 'little'):
            with self.subTest(byteorder=byteorder):
                buffer = self._section_header_bytes(byteorder)
                schema = SectionHeaderBlock.unpack(buffer, len(buffer), {})

                self.assertEqual(schema.byteorder, byteorder)
                self.assertEqual(schema.length, len(buffer) + 4)
                self.assertEqual(schema.section_length, -1)

                parsed = [(option.type, option.length,
                           getattr(option, 'data', getattr(option, 'comment', None)))
                          for option in schema.options]
                self.assertEqual(parsed, expected)

    def test_pcapng_section_header_options_ignore_the_previous_section(self) -> None:
        # #368's multi-section case: for a second SHB ``self._ctx`` is not
        # ``None``, it is the *previous* section's context, so seeding the byte
        # order from it is wrong even when a context exists. An SHB has to read
        # its own options through its own magic whatever the packet data says.
        from pcapkit.protocols.schema.misc.pcapng import SectionHeaderBlock

        for byteorder in ('big', 'little'):
            other = 'little' if byteorder == 'big' else 'big'
            for declared in (byteorder, other):
                with self.subTest(section=byteorder, declared=declared):
                    buffer = self._section_header_bytes(byteorder)
                    schema = SectionHeaderBlock.unpack(buffer, len(buffer),
                                                       {'byteorder': declared})

                    self.assertEqual(schema.byteorder, byteorder)
                    self.assertEqual([option.length for option in schema.options],
                                     [9, 12, 15, 7, 0])

    def test_pcapng_big_endian_sample_section_options_are_intact(self) -> None:
        # The same defect, on the sample capture #368 reports it against. Skipped
        # unless the samples have been generated, since they are not tracked.
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.interface import extract

        path = os.path.join('examples', 'captures', 'dhcp_big_endian.pcapng')
        if not os.path.isfile(path):
            self.skipTest('run examples/generators/make_samples.py first')

        extractor = extract(fin=path, store=True, nofile=True)
        section = extractor.engine._ctx_list[0].section

        self.assertEqual(section.byteorder, 'big')
        self.assertEqual([option.length for _, option in section.options.items(multi=True)],
                         [9, 12, 15, 7, 0])
        self.assertEqual(section.options[OptionType.opt_comment].comment, 'test001')

    def _under_timezone(self, zone: 'str') -> 'datetime.timedelta':
        """Install ``zone`` as the process timezone and return its UTC offset.

        Restored on teardown. :mod:`pcapkit` reads the host zone at parse time
        rather than at import time, so this takes effect without reimporting it.

        """
        previous = os.environ.get('TZ')

        def restore() -> 'None':
            if previous is None:
                os.environ.pop('TZ', None)
            else:
                os.environ['TZ'] = previous
            time.tzset()

        self.addCleanup(restore)
        os.environ['TZ'] = zone
        time.tzset()
        offset = datetime.datetime.now().astimezone().utcoffset()
        assert offset is not None
        return offset

    def test_read_timestamp_is_utc_whatever_the_host_timezone_is(self) -> None:
        """A block timestamp names one instant, on every machine that reads it.

        GH-361: ``_read_timestamp`` added ``tzone.utcoffset(None)`` to the epoch
        it returned, and ``_get_timezone`` fell back to the *reading host's* zone
        whenever the capture named no ``if_tzone`` -- which
        draft-ietf-opsawg-pcapng-02 §4.2 says should be the normal case, since
        the option "SHOULD NOT be used". So the same file parsed to a different
        absolute time on every host, by that host's UTC offset.

        The defect is invisible on a UTC machine, which is why it survived, so
        this drives several zones explicitly and asserts they were really
        installed -- a run that silently stayed on UTC would prove nothing and
        is skipped rather than passed.

        """
        from pcapkit.protocols.misc.pcapng import PCAPNG

        if not hasattr(time, 'tzset'):  # pragma: no cover
            self.skipTest('time.tzset() is unavailable on this platform')

        # A synthetic interface naming no if_tzone: 2_000_000 units at the
        # default if_tsresol of 1e6, i.e. 2s since the UNIX epoch, full stop.
        interface = types.SimpleNamespace(linktype=0, snaplen=65535, options={})
        pcapng = object.__new__(PCAPNG)
        pcapng._ctx = types.SimpleNamespace(
            interfaces=[interface],
            section=types.SimpleNamespace(byteorder='little'),
        )
        pcapng._type = 6  # Enhanced Packet Block

        offsets = set()
        for zone in ('UTC', 'Asia/Shanghai', 'America/New_York', 'Asia/Kolkata'):
            with self.subTest(TZ=zone):
                offsets.add(self._under_timezone(zone))

                ts_datetime, ts_epoch = pcapng._read_timestamp(0, 2_000_000)

                self.assertEqual(ts_epoch, decimal.Decimal(2))
                self.assertEqual(ts_datetime,
                                 datetime.datetime.fromtimestamp(2, datetime.timezone.utc))
                self.assertEqual(ts_datetime.utcoffset(), datetime.timedelta(0))
                # the two returns must name the same instant
                self.assertEqual(ts_datetime.timestamp(), float(ts_epoch))
                # and a read followed by a write must not drift
                self.assertEqual(pcapng._make_timestamp(ts_epoch), (0, 2_000_000))

        # Guard against the whole test having run on UTC four times over, which
        # is exactly the condition under which the defect was undetectable.
        if len(offsets) < 2:  # pragma: no cover
            self.skipTest(f'the host resolved every zone to the same offset {offsets}; '
                          'no tzdata installed, so this test proves nothing')
        self.assertTrue(any(offset for offset in offsets),
                        f'expected at least one non-zero UTC offset, got {offsets}')

    def test_sample_capture_timestamp_matches_its_own_raw_bytes(self) -> None:
        """The same property on a real capture, against the bytes in the file.

        ``dhcp.pcapng`` is committed, and its interface carries ``if_tsresol=6``
        with neither ``if_tsoffset`` nor ``if_tzone`` -- the shape GH-361 is
        about, where the epoch used to be shifted by whatever zone the reading
        machine sat in.

        """
        from pcapkit.interface import extract

        if not hasattr(time, 'tzset'):  # pragma: no cover
            self.skipTest('time.tzset() is unavailable on this platform')

        path = sample_path('dhcp.pcapng')
        with open(path, 'rb') as stream:
            raw = stream.read()

        # independent ground truth, straight out of the block chain
        self.assertEqual(raw[8:12], b'\x4d\x3c\x2b\x1a')  # little-endian section
        shb_len, = struct.unpack_from('<I', raw, 4)
        idb_len, = struct.unpack_from('<I', raw, shb_len + 4)
        epb = shb_len + idb_len
        self.assertEqual(struct.unpack_from('<I', raw, epb)[0], 6)  # EPB
        high, low = struct.unpack_from('<II', raw, epb + 12)
        expected = decimal.Decimal((high << 32) | low) / 1_000_000
        self.assertEqual(expected, decimal.Decimal('1102274184.317453'))

        offsets = set()
        for zone in ('UTC', 'Asia/Shanghai', 'America/New_York', 'Asia/Kolkata'):
            with self.subTest(TZ=zone):
                offsets.add(self._under_timezone(zone))

                block = extract(fin=path, store=True, nofile=True).frame[0].info

                self.assertEqual(block.timestamp_epoch, expected)
                self.assertEqual(block.timestamp,
                                 datetime.datetime.fromtimestamp(float(expected),
                                                                 datetime.timezone.utc))
                self.assertEqual(block.timestamp.utcoffset(), datetime.timedelta(0))

        if len(offsets) < 2:  # pragma: no cover
            self.skipTest(f'the host resolved every zone to the same offset {offsets}; '
                          'no tzdata installed, so this test proves nothing')


if __name__ == '__main__':
    unittest.main()
