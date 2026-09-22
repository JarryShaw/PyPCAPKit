from __future__ import annotations

import datetime
import io
import importlib.util
import struct
import unittest
from decimal import Decimal
from types import SimpleNamespace
from unittest import mock

from tests._support import purge_modules, sample_path

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

    def test_frame_data_holds_its_own_record_not_the_next(self) -> None:
        """A frame's raw data must be the record it parsed, at its own offset.

        #357: :meth:`Frame.read <pcapkit.protocols.misc.pcap.frame.Frame.read>`
        rewound by ``self.length`` (16) to find the start of the record, but the
        schema unpack has by then consumed the record header *and* the
        ``incl_len`` octets of packet data. So the rewind landed ``incl_len``
        octets too late: every frame captured its own tail followed by the head
        of the next record, and the final frame came back truncated because the
        read ran past EOF.

        Checked against the record chain walked straight out of the file, so the
        assertion does not depend on any of the code under test, and checked for
        *every* record rather than the first -- the last one is the truncating
        case.

        """
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header

        path = sample_path('in.pcap')
        with open(path, 'rb') as stream:
            raw = stream.read()

        # in.pcap is little-endian (magic d4c3b2a1) with a 24-octet global header
        self.assertEqual(raw[:4], b'\xd4\xc3\xb2\xa1')
        records = []
        offset = 24
        while offset < len(raw):
            incl_len, = struct.unpack_from('<I', raw, offset + 8)
            records.append((offset, 16 + incl_len))
            offset += 16 + incl_len
        self.assertEqual(records, [(24, 102), (126, 94), (220, 70),
                                   (290, 70), (360, 70), (430, 175)])

        with open(path, 'rb') as stream:
            header = Header(stream)
            for number, (start, total) in enumerate(records, start=1):
                # the engine reads frames off one shared handle, so each frame
                # must leave the cursor on the next record's first octet
                self.assertEqual(stream.tell(), start)

                frame = Frame(stream, num=number, header=header.info)
                expected = raw[start:start + total]

                self.assertEqual(bytes(frame), expected)
                self.assertEqual(len(frame), total)
                self.assertEqual(frame.packet.header, expected[:16])
                self.assertEqual(frame.packet.payload, expected[16:])
                self.assertEqual(frame.info.packet, expected[16:])
                self.assertEqual(stream.tell(), start + total)

    def test_frame_time_is_timezone_aware_utc(self) -> None:
        """``Frame.info.time`` names an instant, so it must not be host-local.

        #361 is about the PCAP-NG epoch, but the same family of defect sat
        here: ``ts_sec`` is an offset from the UNIX epoch, and rendering it with
        a bare :meth:`datetime.datetime.fromtimestamp` produced a *naive*
        datetime in whatever zone the reading machine sat in. The instant was
        right; the object could not be compared with an aware one, and read back
        as a different wall-clock time on every host.

        """
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header

        path = sample_path('in.pcap')
        with open(path, 'rb') as stream:
            raw = stream.read()
        ts_sec, ts_usec = struct.unpack_from('<II', raw, 24)

        with open(path, 'rb') as stream:
            header = Header(stream)
            frame = Frame(stream, num=1, header=header.info)

        self.assertEqual(frame.info.time_epoch,
                         ts_sec + Decimal(ts_usec) / 1_000_000)
        self.assertIsNotNone(frame.info.time.tzinfo)
        self.assertEqual(frame.info.time.utcoffset(), datetime.timedelta(0))
        self.assertEqual(frame.info.time,
                         datetime.datetime.fromtimestamp(float(frame.info.time_epoch),
                                                         datetime.timezone.utc))

    def test_frame_header_is_read_in_the_files_byte_order(self) -> None:
        """#605: a big-endian record header, read on a little-endian host.

        :meth:`Frame.unpack <pcapkit.protocols.misc.pcap.frame.Frame.unpack>`
        seeded the file's byte order under the key ``bytesorder``, where
        ``byteorder_callback`` in
        :file:`pcapkit/protocols/schema/misc/pcap/frame.py` reads ``byteorder``,
        so the lookup always missed and always fell back to
        :data:`sys.byteorder`. On a little-endian host reading a little-endian
        capture that is the right answer by coincidence, which is why every
        fixture here passed; on a big-endian capture all four record-header
        fields came back byte-swapped.

        The capture is built here rather than read from
        :file:`examples/captures/`, so this stays in the unit tier and runs in
        the selection :file:`.github/workflows/unit-tests.yml` uses -- the
        fixture-backed counterpart, which goes through
        :func:`pcapkit.interface.extract` against
        :file:`examples/generators/endian.py`'s captures, is
        :file:`tests/protocols/misc/pcap/test_frame_endian_runtime.py` and runs
        only once the fixtures exist.

        Two records, because the swap is a wrong answer *and* a crash: frame 1's
        ``incl_len`` of 60 reads as 1006632960, which consumes the rest of the
        file, and frame 2 is then asked to read a negative payload length --
        ``ValueError: read length must be non-negative or -1`` out of
        :file:`pcapkit/protocols/schema/schema.py`.

        """
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header

        records = (
            (1500000000, 123456, b'\x02\x00\x00\x00' + bytes(range(56))),
            (1500000001, 654321, b'\x02\x00\x00\x00' + bytes(range(40))),
        )

        # magic a1b2c3d4: big-endian, microsecond timestamps
        raw = b'\xa1\xb2\xc3\xd4' + struct.pack('>HHiIII', 2, 4, 0, 0, 65535,
                                                int(LinkType.NULL))
        for ts_sec, ts_usec, packet in records:
            raw += struct.pack('>IIII', ts_sec, ts_usec, len(packet), len(packet))
            raw += packet

        stream = io.BytesIO(raw)
        header = Header(stream)
        self.assertEqual(header.byteorder, 'big')
        self.assertFalse(header.nanosecond)

        offset = 24
        for number, (ts_sec, ts_usec, packet) in enumerate(records, start=1):
            # the engine reads every frame off one handle, so a record whose
            # length was read in the wrong order desynchronises the ones after it
            self.assertEqual(stream.tell(), offset)

            frame = Frame(stream, num=number, header=header.info)
            info = frame.info.frame_info

            self.assertEqual(info.ts_sec, ts_sec)
            self.assertEqual(info.ts_usec, ts_usec)
            self.assertEqual(info.incl_len, len(packet))
            self.assertEqual(info.orig_len, len(packet))
            self.assertEqual(frame.info.time_epoch,
                             ts_sec + Decimal(ts_usec) / 1_000_000)
            self.assertEqual(frame.info.packet, packet)

            offset += 16 + len(packet)
            self.assertEqual(stream.tell(), offset)

        self.assertEqual(offset, len(raw))


if __name__ == '__main__':
    unittest.main()
