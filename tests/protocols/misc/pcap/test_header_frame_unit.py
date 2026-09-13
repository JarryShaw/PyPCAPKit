from __future__ import annotations

import datetime
import io
import importlib.util
import unittest
from decimal import Decimal
from types import SimpleNamespace
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class DummyData(dict):
    __getattr__ = dict.__getitem__

    def __update__(self, values):
        self.update(values)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PCAPHeaderFrameUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_header_make_length_index_and_make_data(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.corekit.version import VersionInfo
        from pcapkit.protocols.misc.pcap.header import Header
        from pcapkit.protocols.schema.misc.pcap.header import Header as Schema_Header
        from pcapkit.utilities.exceptions import EndianError, FileError
        from pcapkit.utilities.exceptions import UnsupportedCall

        header = object.__new__(Header)
        schema = header.make(
            byteorder='big',
            nanosecond=True,
            version=(2, 4),
            snaplen=65535,
            network=LinkType.ETHERNET,
        )
        override_schema = header.make(
            byteorder='little',
            version=VersionInfo(2, 4),
            version_major=3,
            version_minor=9,
            network=LinkType.ETHERNET,
        )
        data = DummyData(
            magic_number=DummyData(data=b'\xa1\xb2\x3c\x4d'),
            version=SimpleNamespace(major=2, minor=4),
            thiszone=0,
            sigfigs=0,
            snaplen=65535,
            network=LinkType.ETHERNET,
        )

        self.assertEqual(len(header), 24)
        self.assertEqual(header.__length_hint__(), 24)
        self.assertEqual(header.length, 24)
        self.assertEqual(schema.magic_number, b'\xa1\xb2\x3c\x4d')
        self.assertEqual(schema.version_major, 2)
        self.assertEqual(schema.version_minor, 4)
        self.assertEqual(schema.snaplen, 65535)
        self.assertEqual(schema.network, LinkType.ETHERNET)
        self.assertEqual(override_schema.version_major, 3)
        self.assertEqual(override_schema.version_minor, 9)
        self.assertEqual(override_schema.network, LinkType.ETHERNET)
        self.assertEqual(Header._make_data(data)['network'], LinkType.ETHERNET)
        with self.assertRaises(UnsupportedCall):
            Header.__index__()

        for magic, byteorder, nanosecond in (
            (b'\xd4\xc3\xb2\xa1', 'little', False),
            (b'\xa1\xb2\xc3\xd4', 'big', False),
            (b'\x4d\x3c\xb2\xa1', 'little', True),
            (b'\xa1\xb2\x3c\x4d', 'big', True),
        ):
            reader = object.__new__(Header)
            reader.__header__ = Schema_Header(
                magic_number=magic,
                version_major=2,
                version_minor=4,
                thiszone=0,
                sigfigs=0,
                snaplen=65535,
                network=LinkType.NULL,
            )
            reader._file = SimpleNamespace(name='sample.pcap')
            parsed = reader.read()
            reader._info = parsed
            self.assertEqual(parsed.magic_number.byteorder, byteorder)
            self.assertEqual(parsed.magic_number.nanosecond, nanosecond)
            self.assertEqual(reader.name, 'Global Header')
            self.assertEqual(reader.byteorder, byteorder)
            self.assertEqual(reader.nanosecond, nanosecond)
            self.assertEqual(reader.protocol, LinkType.NULL)

        invalid = object.__new__(Header)
        invalid.__header__ = Schema_Header(
            magic_number=b'bad!',
            version_major=2,
            version_minor=4,
            thiszone=0,
            sigfigs=0,
            snaplen=65535,
            network=LinkType.NULL,
        )
        invalid._file = SimpleNamespace(name='bad.pcap')
        with self.assertRaises(FileError):
            invalid.read()

        Header.__post_init__(header, byteorder='big', nanosecond=True,
                             snaplen=128, network=LinkType.ETHERNET)
        self.assertEqual(header._data[:4], b'\xa1\xb2\x3c\x4d')
        self.assertEqual(header.version, VersionInfo(2, 4))
        self.assertEqual(header.byteorder, 'big')
        self.assertTrue(header.nanosecond)
        with self.assertRaises(UnsupportedCall):
            _ = header.payload
        with self.assertRaises(UnsupportedCall):
            _ = header.protochain

        class NamedBytesIO(io.BytesIO):
            pass

        stream = NamedBytesIO(header._data)
        stream.name = 'named.pcap'
        parsed_header = object.__new__(Header)
        parsed_header.__header__ = None
        Header.__post_init__(parsed_header, stream)
        self.assertEqual(parsed_header._file.name, 'named.pcap')
        self.assertEqual(parsed_header._info.snaplen, 128)

        proto_reader = object.__new__(Header)
        proto_reader._file = io.BytesIO(int(LinkType.ETHERNET).to_bytes(4, 'little'))
        self.assertEqual(proto_reader._read_protos(4), LinkType.ETHERNET)

        self.assertEqual(header._make_magic(lilendian=False, bigendian=True),
                         (b'\xa1\xb2\xc3\xd4', False))
        self.assertEqual(header._make_magic(lilendian=True, bigendian=False),
                         (b'\x4d\x3c\xb2\xa1', True))
        self.assertEqual(header._make_magic(byteorder='big', lilendian='', bigendian=False),  # type: ignore[arg-type]
                         (b'\xa1\xb2\xc3\xd4', False))
        with self.assertRaises(EndianError):
            header._make_magic(lilendian=True, bigendian=True)
        with self.assertRaises(EndianError):
            header._make_magic(byteorder='middle')  # type: ignore[arg-type]

    def test_frame_make_index_length_and_make_data(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.schema.misc.pcap.frame import Frame as Schema_Frame
        from pcapkit.utilities.exceptions import RegistryError, UnsupportedCall

        frame = object.__new__(Frame)
        frame._ghdr = SimpleNamespace(
            snaplen=4,
            network=LinkType.NULL,
            magic_number=SimpleNamespace(byteorder='little', nanosecond=False),
        )
        schema = frame.make(timestamp=Decimal('1.25'), packet=b'abcdef')
        explicit_schema = frame.make(ts_sec=10, ts_usec=20, incl_len=2,
                                     orig_len=3, packet=b'abcd')
        data = DummyData(
            frame_info=SimpleNamespace(ts_sec=1, ts_usec=250000, incl_len=4, orig_len=6),
            __next_type__=None,
        )

        self.assertEqual(frame.__length_hint__(), 16)
        self.assertEqual(schema.ts_sec, 1)
        self.assertEqual(schema.ts_usec, 250000)
        self.assertEqual(schema.incl_len, 4)
        self.assertEqual(schema.orig_len, 6)
        self.assertEqual(explicit_schema.ts_sec, 10)
        self.assertEqual(explicit_schema.ts_usec, 20)
        self.assertEqual(explicit_schema.incl_len, 2)
        self.assertEqual(explicit_schema.orig_len, 3)
        values = Frame._make_data(data)
        self.assertEqual(values['ts_src'], 1)
        self.assertEqual(values['ts_usec'], 250000)
        self.assertEqual(values['incl_len'], 4)
        self.assertEqual(values['orig_len'], 6)
        self.assertIn('packet', values)
        with self.assertRaises(UnsupportedCall):
            Frame.__index__()

        frame._fnum = 7
        self.assertEqual(frame.__index__(), 7)
        frame._protos = SimpleNamespace(index=lambda name: 12)
        self.assertEqual(frame.index('Raw'), 12)

        self.assertEqual(frame.name, 'Frame 7')
        self.assertEqual(frame.length, 16)
        self.assertIs(frame.header, frame._ghdr)

        registry = Frame.__dict__['__proto__']
        code = LinkType.USER0
        had_original = code in registry
        original = registry.get(code)
        try:
            Frame.register(code, ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'))
            self.assertIs(registry[code], Raw)
            with mock.patch('pcapkit.protocols.misc.pcap.frame.warn') as warn:
                Frame.register(code, Raw)
            warn.assert_called_once()
            with self.assertRaises(RegistryError):
                Frame.register(LinkType.USER1, object)  # type: ignore[arg-type]
        finally:
            if had_original:
                registry[code] = original
            else:
                registry.pop(code, None)

        with mock.patch('pcapkit.protocols.misc.pcap.frame.time.time', return_value=1.5):
            self.assertEqual(frame._make_timestamp(), (1, 500000))
        with mock.patch('pcapkit.protocols.misc.pcap.frame.time.time_ns', return_value=1_234_567_890):
            self.assertEqual(frame._make_timestamp(nanosecond=True), (1, 234567890))
        instant = datetime.datetime(1970, 1, 1, 0, 0, 2, 500000,
                                    tzinfo=datetime.timezone.utc)
        self.assertEqual(frame._make_timestamp(timestamp=instant), (2, 500000))
        self.assertEqual(frame._make_timestamp(timestamp=Decimal('3.75'),
                                               ts_sec=10, ts_usec=11), (10, 11))

        with mock.patch.object(Frame, '_decode_next_layer',
                               lambda self, info, proto=None, length=None, packet=None: info):
            made = object.__new__(Frame)
            Frame.__post_init__(made, num=1, header=frame._ghdr,
                                timestamp=Decimal('1.25'), packet=b'abcd')
            self.assertEqual(made._info.number, 1)
            self.assertEqual(made._info.len, 4)

            parsed = object.__new__(Frame)
            parsed.__header__ = None
            Frame.__post_init__(parsed, made._data, num=2, header=frame._ghdr)
            self.assertEqual(parsed._info.number, 2)
            self.assertEqual(parsed._info.len, 4)

            unpacked = object.__new__(Frame)
            unpacked._ghdr = frame._ghdr
            unpacked._nsec = False
            unpacked._fnum = 3
            unpacked._file = io.BytesIO(made._data)
            unpacked.__header__ = None
            self.assertEqual(Frame.unpack(unpacked, length=16, _read=False).number, 3)

            reader = object.__new__(Frame)
            reader.__header__ = Schema_Frame(ts_sec=1, ts_usec=250000,
                                             incl_len=4, orig_len=4, packet=b'abcd')
            reader._ghdr = frame._ghdr
            reader._nsec = False
            reader._fnum = 4
            reader._file = io.BytesIO(made._data)
            reader._file.seek(16)
            self.assertEqual(Frame.read(reader, _read=True).number, 4)
            self.assertEqual(len(reader._data), 20)

            no_read = object.__new__(Frame)
            no_read.__header__ = Schema_Frame(ts_sec=1, ts_usec=250000,
                                              incl_len=4, orig_len=4, packet=b'abcd')
            no_read._ghdr = frame._ghdr
            no_read._nsec = True
            no_read._fnum = 5
            no_read._file = io.BytesIO(made._data)
            no_read._file.seek(8)
            self.assertEqual(Frame.read(no_read, _read=False).number, 5)
            self.assertEqual(no_read._file.tell(), 0)

        real_datetime = datetime.datetime

        class FakeDateTime:
            calls = 0

            @classmethod
            def fromtimestamp(cls, *args):
                if cls.calls == 0:
                    cls.calls += 1
                    raise ValueError
                return real_datetime.fromtimestamp(*args)

        bad_time = object.__new__(Frame)
        bad_time.__header__ = Schema_Frame(ts_sec=1, ts_usec=0,
                                           incl_len=0, orig_len=0, packet=b'')
        bad_time._ghdr = frame._ghdr
        bad_time._nsec = False
        bad_time._fnum = 6
        bad_time._file = io.BytesIO(b'')
        with mock.patch('pcapkit.protocols.misc.pcap.frame.datetime.datetime', FakeDateTime), \
                mock.patch.object(Frame, '_decode_next_layer',
                                  lambda self, info, proto=None, length=None, packet=None: info), \
                mock.patch('pcapkit.protocols.misc.pcap.frame.warn') as warn:
            self.assertEqual(Frame.read(bad_time, _read=False).number, 6)
        warn.assert_called_once()

        decoded = DummyData()
        chain = SimpleNamespace(chain='Frame:Raw')
        fake_next = SimpleNamespace(info='payload-info', protochain=chain, info_name='Raw')
        frame._import_next_layer = mock.Mock(return_value=fake_next)
        self.assertIs(frame._decode_next_layer(decoded, LinkType.NULL, 0), decoded)
        self.assertEqual(decoded['Raw'], 'payload-info')
        self.assertEqual(decoded['protocols'], 'Frame:Raw')
        self.assertIs(decoded['__next_type__'], type(fake_next))
        self.assertEqual(decoded['__next_name__'], 'Raw')
        self.assertIs(frame._next, fake_next)
        self.assertIs(frame._protos, chain)

        decoded_no_chain = DummyData()
        fake_next_no_chain = SimpleNamespace(info='payload-info', protochain=None, info_name='Raw')
        frame._import_next_layer = mock.Mock(return_value=fake_next_no_chain)
        self.assertIs(frame._decode_next_layer(decoded_no_chain, LinkType.NULL, 0), decoded_no_chain)
        self.assertEqual(decoded_no_chain['protocols'], '')


if __name__ == '__main__':
    unittest.main()
