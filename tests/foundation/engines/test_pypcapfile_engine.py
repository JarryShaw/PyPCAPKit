"""Unit tests for :mod:`pcapkit.foundation.engines.pypcapfile`.

The engine is exercised against stand-ins for :func:`pcapfile.savefile.load_savefile`
and :func:`pcapfile.linklayer.clookup`, so that the routing decisions -- format
gating, the IPv6 capability gap, per-frame decoding and its failure path, output,
reassembly, tracing, storage -- are covered whether or not `pypcapfile`_ is
installed. One test runs the real `pypcapfile`_ where it imports, over savefiles
built in memory, to pin the engine's record reader to the ``default`` engine's
reading in both byte orders (#1512, #1571). End-to-end agreement with the ``default`` engine lives in
:mod:`tests.foundation.engines.test_new_engine_parity`.

.. _pypcapfile: https://github.com/kisom/pypcapfile

"""
from __future__ import annotations

import binascii
import ctypes
import importlib
import importlib.util
import io
import itertools
import struct
import sys
import types
import unittest
from unittest import mock

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Magic number of a little-endian, microsecond-resolution PCAP savefile.
PCAP_MAGIC = b'\xd4\xc3\xb2\xa1'
#: Magic number of a PCAP-NG section header block.
PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'

#: Raw bytes of a not-yet-decoded frame.
RAW_FRAME = b'payload'
#: The hex-ASCII form :func:`pcapfile.savefile._read_a_packet` actually hands
#: back as ``packet.packet`` for a savefile loaded with ``layers=0`` -- see
#: :meth:`~pcapkit.foundation.engines.pypcapfile.PyPCAPFile.run`. Stand-in
#: packets below carry this, not :data:`RAW_FRAME` itself, so that a decoder
#: fixture receiving :data:`RAW_FRAME` is proof that :meth:`~pcapkit.foundation
#: .engines.pypcapfile.PyPCAPFile._decode` un-hexlified it first (see #746).
HEXLIFIED_FRAME = binascii.hexlify(RAW_FRAME)


class OutputSink:
    """Stand-in for a :class:`dictdumper.dumper.Dumper`, recording what it is handed."""

    kind = 'unit'

    def __init__(self) -> None:
        self.paths: list[str] = []
        self.records: list[tuple[object, str | None]] = []

    def __call__(self, *args, **kwargs):
        if len(args) == 1 and isinstance(args[0], str) and not kwargs:
            self.paths.append(args[0])
            return self
        self.records.append((args[0] if args else None, kwargs.get('name')))
        return self


class FakePacket:
    """Stand-in for :class:`pcapfile.structs.pcap_packet`."""

    def __init__(self, header, timestamp, timestamp_us, capture_len, packet_len, packet) -> None:
        self.header = header
        self.timestamp = timestamp
        self.timestamp_us = timestamp_us
        self.capture_len = capture_len
        self.packet_len = packet_len
        self.packet = packet


class FakeHeader(ctypes.Structure):
    """Stand-in for :class:`pcapfile.structs.__pcap_header__`.

    A :mod:`ctypes` structure, like the real one, so that a packet can point at
    it and its ``byteorder`` reads back as :class:`bytes`, as the real one does.

    """

    _fields_ = [('ll_type', ctypes.c_uint), ('byteorder', ctypes.c_char_p),
                ('ns_resolution', ctypes.c_bool)]


class UnreadPackets:
    """Stand-in for the packet generator :func:`pcapfile.savefile.load_savefile`
    returns, which pypcapfile 0.12.0 drops records from (#1512, #1571): the engine
    reads the records itself, so taking this is a failure."""

    def __iter__(self):
        raise AssertionError("the engine took pcapfile's packet generator, which drops records")


class FakeSaveFile:
    """Stand-in for :class:`pcapfile.savefile.pcap_savefile`."""

    def __init__(self, ll_type: int = 1, ns_resolution: bool = False,
                 byteorder: bytes = b'little') -> None:
        self.header = FakeHeader(ll_type=ll_type, byteorder=byteorder, ns_resolution=ns_resolution)
        self.packets = UnreadPackets()


#: Savefile magic numbers, by ``(byte order, nanosecond)``.
MAGIC = {('little', False): b'\xd4\xc3\xb2\xa1', ('big', False): b'\xa1\xb2\xc3\xd4',
         ('little', True): b'\x4d\x3c\xb2\xa1', ('big', True): b'\xa1\xb2\x3c\x4d'}


def build_savefile(records, *, byteorder: str, nanosecond: bool = False,
                   tail: bytes = b'') -> bytes:
    """A PCAP savefile of ``(seconds, fraction, frame, original length)`` records,
    then ``tail``. A distinct original length makes a swapped field show."""
    order = '<' if byteorder == 'little' else '>'
    out = [MAGIC[byteorder, nanosecond] + struct.pack(f'{order}HHiIII', 2, 4, 0, 0, 0xFFFF, 1)]
    for seconds, fraction, frame, length in records:
        out.append(struct.pack(f'{order}IIII', seconds, fraction, len(frame), length) + frame)
    return b''.join(out) + tail


def reference_records(data: bytes) -> list:
    """Every record of a savefile, read with :mod:`struct` alone, as the ``default``
    engine reads them: to a tail too short for a record header, keeping a record
    whose capture length runs past the data as ``(seconds, fraction, captured
    length, original length, the octets present)``."""
    byteorder, _ = next(key for key, magic in MAGIC.items() if magic == data[:4])
    order = '<' if byteorder == 'little' else '>'
    records, offset = [], 24
    while len(data) - offset >= 16:
        seconds, fraction, incl, orig = struct.unpack_from(f'{order}IIII', data, offset)
        records.append((seconds, fraction, incl, orig, data[offset + 16:offset + 16 + incl]))
        offset += 16 + incl
    return records


def _importable(*modules: str) -> bool:
    for module in modules:
        try:
            importlib.import_module(module)
        except ImportError:
            return False
    return True


#: ``pypcapfile`` 0.12.0 installs on Python 3.12 and newer but cannot import
#: there (see :class:`PyPCAPFilePythonCeilingTests`), hence an import test.
HAS_PYPCAPFILE = _importable('pcapfile.savefile', 'pcapfile.linklayer', 'pcapfile.structs')


class FakeDecoded:
    """Stand-in for a decoded link layer frame."""

    def __init__(self, packet, layers=0) -> None:
        self.raw = packet
        self.layers = layers
        self.payload = b'decoded-payload'


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PyPCAPFileEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def make_extractor(self, **overrides):
        sink = OutputSink()
        reasm = types.SimpleNamespace(ipv4=mock.Mock(), ipv6=mock.Mock(), tcp=mock.Mock())
        trace = types.SimpleNamespace(tcp=mock.Mock())
        values = {
            '_ifile': io.BytesIO(b'capture'),
            '_ifnm': 'capture.pcap',
            '_ofile': sink,
            '_ofnm': 'out',
            '_fext': 'json',
            '_offmt': None,
            '_flag_q': False,
            '_flag_f': False,
            '_flag_v': False,
            '_flag_r': False,
            '_flag_t': False,
            '_flag_d': True,
            '_ipv4': False,
            '_ipv6': False,
            '_tcp': False,
            '_reasm': reasm,
            '_trace': trace,
            '_frame': [],
            '_frnum': 0,
            '_exlyr': 'none',
            '_exptl': 'null',
            '_vfunc': mock.Mock(),
            'magic_number': PCAP_MAGIC,
        }
        values.update(overrides)
        return types.SimpleNamespace(**values), sink

    def engine(self, extractor, savefile=None, decoder=FakeDecoded):
        from pcapkit.foundation.engines.pypcapfile import PyPCAPFile

        if savefile is None:
            savefile = FakeSaveFile()

        engine = PyPCAPFile.__new__(PyPCAPFile)
        engine._expkg = types.SimpleNamespace(
            savefile=types.SimpleNamespace(load_savefile=mock.Mock(return_value=savefile)),
            linklayer=types.SimpleNamespace(clookup=mock.Mock(return_value=decoder)),
            structs=types.SimpleNamespace(pcap_packet=FakePacket),
        )
        engine._extmp = None
        engine._dlink = None
        engine._declf = None
        engine._extractor = extractor
        return engine

    ##########################################################################
    # run()
    ##########################################################################

    def test_run_loads_savefile_undecoded_and_records_link_type(self) -> None:
        from pcapkit.const.reg.linktype import LinkType

        extractor, _ = self.make_extractor()
        engine = self.engine(extractor)
        engine.run()

        load = engine._expkg.savefile.load_savefile
        load.assert_called_once()
        self.assertEqual(load.call_args.kwargs, {'layers': 0, 'lazy': True})
        stream = load.call_args.args[0]
        self.assertEqual(stream.name, 'capture.pcap')
        self.assertEqual(stream.read(3), b'cap')

        self.assertEqual(engine.dlink, LinkType.ETHERNET)
        self.assertIs(engine._declf, FakeDecoded)

    def test_run_warns_on_layer_and_protocol_threshold(self) -> None:
        from pcapkit.utilities.warnings import AttributeWarning

        # NOTE: ``BaseWarning.__init__`` installs an ``ignore`` filter for its own
        # category outside development mode, so the warning never reaches
        # ``assertWarns``; the ``warn`` call itself is what can be observed.
        for overrides in ({'_exlyr': 'transport'}, {'_exptl': 'udp'}):
            with self.subTest(overrides=overrides):
                extractor, _ = self.make_extractor(**overrides)
                engine = self.engine(extractor)
                with mock.patch('pcapkit.foundation.engines.pypcapfile.warn') as warn:
                    engine.run()
                self.assertEqual(warn.call_count, 1)
                self.assertIn('protocol and layer threshold', warn.call_args.args[0])
                self.assertIs(warn.call_args.args[1], AttributeWarning)

    def test_run_rejects_pcapng(self) -> None:
        from pcapkit.utilities.exceptions import FormatError

        extractor, _ = self.make_extractor(magic_number=PCAPNG_MAGIC)
        engine = self.engine(extractor)
        with self.assertRaises(FormatError):
            engine.run()
        engine._expkg.savefile.load_savefile.assert_not_called()

    def test_run_disables_ipv6_reassembly_but_keeps_ipv4_and_tcp(self) -> None:
        from pcapkit.utilities.warnings import AttributeWarning

        extractor, _ = self.make_extractor(_flag_r=True, _ipv4=True, _ipv6=True, _tcp=True)
        ipv4, tcp = extractor._reasm.ipv4, extractor._reasm.tcp
        engine = self.engine(extractor)
        with mock.patch('pcapkit.foundation.engines.pypcapfile.warn') as warn:
            engine.run()

        messages = [call.args[0] for call in warn.call_args_list
                    if call.args[1] is AttributeWarning]
        self.assertTrue(any('IPv6 reassembly' in message for message in messages), messages)

        self.assertTrue(extractor._flag_r)
        self.assertFalse(extractor._ipv6)
        self.assertTrue(extractor._ipv4)
        self.assertIs(extractor._reasm.ipv4, ipv4)
        self.assertIs(extractor._reasm.tcp, tcp)
        self.assertIsNone(extractor._reasm.ipv6)

    def test_run_leaves_reassembly_alone_when_ipv6_was_not_requested(self) -> None:
        extractor, _ = self.make_extractor(_flag_r=True, _ipv4=True, _tcp=True)
        original = extractor._reasm
        engine = self.engine(extractor)
        engine.run()
        self.assertIs(extractor._reasm, original)

    def test_run_warns_and_gives_up_decoding_for_an_unknown_link_layer(self) -> None:
        from pcapkit.utilities.warnings import AttributeWarning

        for decoder in (None, 'not-callable'):
            with self.subTest(decoder=decoder):
                extractor, _ = self.make_extractor()
                engine = self.engine(extractor, decoder=decoder)
                with mock.patch('pcapkit.foundation.engines.pypcapfile.warn') as warn:
                    engine.run()
                self.assertIsNone(engine._declf)
                self.assertIn('unrecognised link layer protocol', warn.call_args.args[0])
                self.assertIs(warn.call_args.args[1], AttributeWarning)

    def test_run_survives_the_malformed_upstream_link_layer_table(self) -> None:
        # ``pcapfile.linklayer.__LL_TYPES__`` carries a three-element entry for
        # LINKTYPE_IEEE802_11_RADIOTAP, so ``clookup`` raises IndexError for it.
        extractor, _ = self.make_extractor()
        engine = self.engine(extractor)
        engine._expkg.linklayer.clookup = mock.Mock(side_effect=IndexError('tuple index'))
        with mock.patch('pcapkit.foundation.engines.pypcapfile.warn'):
            engine.run()
        self.assertIsNone(engine._declf)

    def test_run_installs_verbose_handler_reporting_the_chain(self) -> None:
        extractor, _ = self.make_extractor(_flag_v=True)
        engine = self.engine(extractor)
        engine.run()

        packet = FakePacket(types.SimpleNamespace(ns_resolution=False), 1, 0, 7, 7, b'raw')
        with mock.patch('builtins.print') as printer:
            extractor._frnum = 4
            extractor._vfunc(extractor, packet)
        printer.assert_called_once()
        self.assertIn('ETHERNET:Raw', printer.call_args.args[0])

    ##########################################################################
    # Records (#1512, #1571).
    ##########################################################################

    def reading(self, data: bytes, decoder=FakeDecoded):
        """An engine run over the savefile ``data``, its header loaded as
        :func:`pcapfile.savefile.load_savefile` loads it: the first 24 octets
        read, and the byte order and resolution recorded."""
        (byteorder, nanosecond), = (key for key, magic in MAGIC.items() if magic == data[:4])
        savefile = FakeSaveFile(byteorder=byteorder.encode(), ns_resolution=nanosecond)
        extractor, _ = self.make_extractor(_ifile=io.BytesIO(data), _flag_q=True,
                                           magic_number=data[:4])
        engine = self.engine(extractor, savefile=savefile, decoder=decoder)

        def load_savefile(stream, layers, lazy):
            stream.read(24)
            return savefile

        engine._expkg.savefile.load_savefile = mock.Mock(side_effect=load_savefile)
        engine.run()
        return engine, savefile.header

    def frames(self, engine) -> 'tuple[list, list]':
        """Every frame ``engine`` reads, and the warnings it gives on the way."""
        frames = []
        with mock.patch('pcapkit.foundation.engines.pypcapfile.warn') as warn:
            while True:
                try:
                    frames.append(engine.read_frame())
                except StopIteration:
                    return frames, [call.args for call in warn.call_args_list]

    @staticmethod
    def octets(frame) -> bytes:
        """The frame octets a packet carries, decoded or not."""
        if isinstance(frame.packet, FakeDecoded):
            return frame.packet.raw
        return binascii.unhexlify(frame.packet)

    def test_records_are_read_in_the_header_byte_order(self) -> None:
        records = [(1500000000, 123456, b'first-frame', 11),
                   (1500000001, 654321, b'second', 1200)]
        for byteorder in ('little', 'big'):
            with self.subTest(byteorder=byteorder):
                engine, header = self.reading(build_savefile(records, byteorder=byteorder))
                frames, warned = self.frames(engine)

                self.assertEqual(warned, [])
                self.assertEqual(len(frames), 2)
                self.assertEqual(engine._extractor._frnum, 2)
                for frame, (seconds, fraction, raw, length) in zip(frames, records):
                    self.assertEqual((frame.timestamp, frame.timestamp_us), (seconds, fraction))
                    self.assertEqual((frame.capture_len, frame.packet_len), (len(raw), length))
                    # handed to the decoder as pcapfile hands over a frame:
                    # hexlified, then un-hexlified by _decode
                    self.assertIsInstance(frame.packet, FakeDecoded)
                    self.assertEqual(frame.packet.raw, raw)
                    # and pointing at the savefile's own header, as pcapfile's do
                    self.assertEqual(ctypes.addressof(frame.header.contents),
                                     ctypes.addressof(header))

    def test_a_nanosecond_savefile_keeps_its_resolution(self) -> None:
        from pcapkit.toolkit.pypcapfile import packet2timestamp

        for byteorder in ('little', 'big'):
            with self.subTest(byteorder=byteorder):
                engine, _ = self.reading(build_savefile([(1500000000, 123456789, b'frame', 5)],
                                                        byteorder=byteorder, nanosecond=True))
                (frame,), _ = self.frames(engine)
                self.assertEqual(frame.timestamp_us, 123456789)
                self.assertEqual(packet2timestamp(frame),
                                 1500000000 + 123456789 / 1_000_000_000)

    def test_a_zero_length_record_is_read_and_left_undecoded(self) -> None:
        """pcapfile ends the savefile at a zero-length record (#1571); the ``default``
        engine reads it, and every record after it, without a warning."""
        cases = {
            'middle': [(1, 0, b'first', 5), (2, 0, b'', 0), (3, 0, b'third', 5)],
            'first': [(1, 0, b'', 0), (2, 0, b'second', 6), (3, 0, b'third', 5)],
        }
        for (case, records), byteorder in itertools.product(cases.items(), ('little', 'big')):
            with self.subTest(case=case, byteorder=byteorder):
                decoder = mock.Mock(side_effect=FakeDecoded)
                engine, _ = self.reading(build_savefile(records, byteorder=byteorder),
                                         decoder=decoder)
                frames, warned = self.frames(engine)

                self.assertEqual([self.octets(frame) for frame in frames],
                                 [raw for _, _, raw, _ in records])
                self.assertEqual([frame.timestamp for frame in frames], [1, 2, 3])
                self.assertEqual(warned, [])
                # nothing to decode, so the decoder never sees the empty frame
                self.assertEqual(decoder.call_count, 2)
                self.assertNotIn(b'', [call.args[0] for call in decoder.call_args_list])

    def test_a_truncated_final_record_is_kept_as_captured(self) -> None:
        """pcapfile drops a final record whose capture length runs past the data
        (#1571); the ``default`` engine keeps it, as declared, with the octets that
        are there, and warns."""
        from pcapkit.utilities.warnings import ProtocolWarning

        for byteorder in ('little', 'big'):
            with self.subTest(byteorder=byteorder):
                order = '<' if byteorder == 'little' else '>'
                tail = struct.pack(f'{order}IIII', 3, 4, 50, 60) + b'only-ten..'
                engine, _ = self.reading(build_savefile([(1, 2, b'whole', 5)],
                                                        byteorder=byteorder, tail=tail))
                frames, warned = self.frames(engine)

                self.assertEqual([self.octets(frame) for frame in frames],
                                 [b'whole', b'only-ten..'])
                self.assertEqual((frames[1].capture_len, frames[1].packet_len), (50, 60))
                self.assertEqual(len(warned), 1)
                message, category = warned[0][:2]
                self.assertIs(category, ProtocolWarning)
                self.assertIn('[Frame 2] captured length 50 runs past the data, '
                              'which holds 10 octet(s)', message)

    def test_a_tail_too_short_for_a_record_header_ends_the_savefile(self) -> None:
        for byteorder in ('little', 'big'):
            with self.subTest(byteorder=byteorder):
                engine, _ = self.reading(build_savefile([(1, 2, b'whole', 5)],
                                                        byteorder=byteorder, tail=b'\x00' * 15))
                frames, warned = self.frames(engine)
                self.assertEqual([self.octets(frame) for frame in frames], [b'whole'])
                self.assertEqual(warned, [])

    @unittest.skipUnless(HAS_PYPCAPFILE, 'pypcapfile not installed, or not importable here')
    def test_records_agree_with_the_default_engine_against_the_real_pcapfile(self) -> None:
        """Against the real :mod:`pcapfile`, in both byte orders and resolutions:
        the engine reads every record :func:`reference_records` reads, field for
        field and octet for octet, into :mod:`pcapfile`'s own packet objects --
        including the records pypcapfile 0.12.0 drops (#1512, #1571)."""
        import pcapfile.linklayer
        import pcapfile.savefile
        import pcapfile.structs

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.corekit.io import NamedStream
        from pcapkit.foundation.engines.pypcapfile import PyPCAPFile
        from tests.foundation import _roundtrip as wire

        def frame(n: int) -> bytes:
            return wire.ethernet(wire.ipv4(wire.udp(wire.payload_pattern(9 + n, n))), 0x0800)

        def fields(packet) -> tuple:
            return (packet.timestamp, packet.timestamp_us, packet.capture_len,
                    packet.packet_len, binascii.unhexlify(packet.packet))

        whole = [(1500000000 + n, 1000 * n + 7, frame(n), len(frame(n))) for n in range(3)]
        cases = {
            'whole': (whole, b''),
            'zero-length middle record': ([whole[0], (1500000001, 0, b'', 0), whole[2]], b''),
            'zero-length first record': ([(1500000000, 0, b'', 0)] + whole[1:], b''),
            'truncated final record': (whole[:2], None),
        }
        for (case, (records, tail)), byteorder, nanosecond in itertools.product(
                cases.items(), ('little', 'big'), (False, True)):
            with self.subTest(case=case, byteorder=byteorder, nanosecond=nanosecond):
                if tail is None:  # the last record's header promises 4 octets more than follow
                    order = '<' if byteorder == 'little' else '>'
                    length = len(frame(2)) + 4
                    tail = struct.pack(f'{order}IIII', 1500000002, 9, length, length) + frame(2)
                data = build_savefile(records, byteorder=byteorder, nanosecond=nanosecond,
                                      tail=tail)
                extractor, _ = self.make_extractor(_ifile=io.BytesIO(data), _flag_q=True,
                                                   magic_number=data[:4])
                engine = PyPCAPFile.__new__(PyPCAPFile)
                engine._expkg = pcapfile
                engine._extmp = None
                engine._extractor = extractor
                engine.run()
                self.assertEqual(engine.dlink, LinkType.ETHERNET)
                with mock.patch('pcapkit.foundation.engines.pypcapfile.warn'):
                    packets = list(engine._extmp)

                self.assertEqual([fields(packet) for packet in packets], reference_records(data))
                for packet in packets:
                    self.assertIsInstance(packet, pcapfile.structs.pcap_packet)
                    self.assertIs(packet.header[0].ns_resolution, nanosecond)

        # where pcapfile reads a savefile whole, its packets are the engine's
        data = build_savefile(whole, byteorder='little')
        expected = pcapfile.savefile.load_savefile(NamedStream(io.BytesIO(data), 'whole.pcap'),
                                                   layers=0).packets
        self.assertEqual([fields(packet) for packet in expected], reference_records(data))

    ##########################################################################
    # read_frame()
    ##########################################################################

    def prepared(self, packets=None, decoder=FakeDecoded, **overrides):
        if packets is None:
            packets = [FakePacket(types.SimpleNamespace(ns_resolution=False),
                                  1, 500000, 7, 7, HEXLIFIED_FRAME)]
        extractor, sink = self.make_extractor(**overrides)
        engine = self.engine(extractor, decoder=decoder)
        with mock.patch('pcapkit.foundation.engines.pypcapfile.warn'):
            engine.run()
        # read_frame() is under test here, not the record reader, so it is
        # handed these packets as if read from the savefile
        engine._extmp = iter(packets)
        return extractor, sink, engine

    def test_read_frame_decodes_to_layers_depth_and_routes_output(self) -> None:
        extractor, sink, engine = self.prepared()

        with mock.patch('pcapkit.toolkit.pypcapfile.packet2dict', return_value={'ok': True}):
            frame = engine.read_frame()

        self.assertIsInstance(frame.packet, FakeDecoded)
        # the decoder must see the un-hexlified raw bytes, not the hex-ASCII
        # ``packet.packet`` a ``layers=0`` load actually hands back -- #746
        self.assertEqual(frame.packet.raw, RAW_FRAME)
        self.assertEqual(frame.packet.layers, engine.LAYERS - 1)
        self.assertEqual((frame.timestamp, frame.timestamp_us), (1, 500000))
        self.assertEqual((frame.capture_len, frame.packet_len), (7, 7))

        self.assertEqual(extractor._frnum, 1)
        extractor._vfunc.assert_called_once_with(extractor, frame)
        self.assertEqual(sink.records[-1], ({'ok': True}, 'Frame 1'))
        self.assertEqual(extractor._offmt, 'unit')
        self.assertEqual(extractor._frame, [frame])

        with self.assertRaises(StopIteration):
            engine.read_frame()

    def test_decode_unhexlifies_the_savefile_bytes_before_calling_the_decoder(self) -> None:
        """``_decode()`` must undo the ``layers=0`` load's hexlifying (#746).

        :func:`pcapfile.savefile._read_a_packet` hexlifies the whole frame into
        ASCII text when ``layers=0`` (see :meth:`PyPCAPFile.run`), so
        ``packet.packet`` is :data:`HEXLIFIED_FRAME`, never :data:`RAW_FRAME`.
        Handing that straight to the link layer decoder -- which unpacks its own
        header with :func:`struct.unpack` -- makes every field it decodes
        garbage without raising anything, so this has to be asserted on the
        decoder's actual input rather than on some raised error.
        """
        from pcapkit.foundation.engines.pypcapfile import PyPCAPFile

        engine = PyPCAPFile.__new__(PyPCAPFile)
        engine._declf = mock.Mock(return_value=FakeDecoded(RAW_FRAME))
        engine._expkg = types.SimpleNamespace(
            structs=types.SimpleNamespace(pcap_packet=FakePacket),
        )
        engine._dlink = None

        packet = FakePacket(types.SimpleNamespace(ns_resolution=False),
                            1, 0, 7, 7, HEXLIFIED_FRAME)
        decoded = engine._decode(packet, frnum=1)

        engine._declf.assert_called_once_with(RAW_FRAME, layers=engine.LAYERS - 1)
        self.assertIsInstance(decoded.packet, FakeDecoded)

    def test_read_frame_leaves_the_frame_alone_with_no_decoder(self) -> None:
        extractor, _, engine = self.prepared(decoder=None, _flag_q=True)
        frame = engine.read_frame()
        self.assertEqual(frame.packet, HEXLIFIED_FRAME)

    def test_read_frame_warns_and_falls_back_when_decoding_fails(self) -> None:
        from pcapkit.utilities.warnings import AttributeWarning

        for error in (struct.error('unpack'), AssertionError('not ipv4'),
                      ValueError('bad'), IndexError('short'), KeyError('missing')):
            with self.subTest(error=type(error).__name__):
                extractor, _, engine = self.prepared(
                    decoder=mock.Mock(side_effect=error), _flag_q=True,
                )
                with mock.patch('pcapkit.foundation.engines.pypcapfile.warn') as warn:
                    frame = engine.read_frame()
                self.assertEqual(frame.packet, HEXLIFIED_FRAME)
                self.assertIn('decoding failed', warn.call_args.args[0])
                self.assertIn('Frame 1', warn.call_args.args[0])
                self.assertIs(warn.call_args.args[1], AttributeWarning)

    def test_read_frame_warns_and_falls_back_when_unhexlifying_fails(self) -> None:
        """The un-hexlifying itself, not just the decoder, must stay inside the
        ``try`` (#746).

        A ``packet.packet`` that is not valid hex can never reach a real
        savefile -- :func:`pcapfile.savefile._read_a_packet` produced it with
        :func:`binascii.hexlify` -- but nothing stops a future refactor from
        hoisting :func:`binascii.unhexlify` out of :meth:`PyPCAPFile._decode`'s
        ``try``, which would turn this per-frame :class:`AttributeWarning` into
        an uncaught :exc:`binascii.Error` instead. The decoder must never be
        reached: un-hexlifying fails before it is called.
        """
        from pcapkit.utilities.warnings import AttributeWarning

        # non-hex characters, and valid hex digits at an odd length
        for bad in (b'not-hex-at-all', b'abc'):
            with self.subTest(bad=bad):
                decoder = mock.Mock()
                extractor, _, engine = self.prepared(
                    packets=[FakePacket(types.SimpleNamespace(ns_resolution=False),
                                        1, 0, len(bad), len(bad), bad)],
                    decoder=decoder, _flag_q=True,
                )
                with mock.patch('pcapkit.foundation.engines.pypcapfile.warn') as warn:
                    frame = engine.read_frame()
                decoder.assert_not_called()
                self.assertEqual(frame.packet, bad)
                self.assertIn('decoding failed', warn.call_args.args[0])
                self.assertIn('Frame 1', warn.call_args.args[0])
                self.assertIs(warn.call_args.args[1], AttributeWarning)

    def test_read_frame_splits_files_when_asked(self) -> None:
        extractor, sink, engine = self.prepared(_flag_f=True)
        with mock.patch('pcapkit.toolkit.pypcapfile.packet2dict', return_value={}):
            engine.read_frame()
        self.assertEqual(sink.paths[-1], 'out/Frame 1.json')

    def test_read_frame_routes_reassembly_and_tracing(self) -> None:
        extractor, _, engine = self.prepared(_flag_q=True, _flag_r=True, _flag_t=True,
                                             _ipv4=True, _tcp=True, _flag_d=False)
        with mock.patch('pcapkit.toolkit.pypcapfile.ipv4_reassembly', return_value='ipv4') as v4:
            with mock.patch('pcapkit.toolkit.pypcapfile.tcp_reassembly', return_value='tcp'):
                with mock.patch('pcapkit.toolkit.pypcapfile.tcp_traceflow',
                                return_value='trace') as trace:
                    frame = engine.read_frame()

        v4.assert_called_once_with(frame, count=1)
        trace.assert_called_once_with(frame, data_link=engine.dlink, count=1)
        extractor._reasm.ipv4.assert_called_once_with('ipv4')
        extractor._reasm.tcp.assert_called_once_with('tcp')
        extractor._trace.tcp.assert_called_once_with('trace')
        # IPv6 is unreachable for this engine, so it must never be consulted
        extractor._reasm.ipv6.assert_not_called()
        self.assertEqual(extractor._frame, [])

    def test_read_frame_skips_reassembly_and_tracing_when_adapters_decline(self) -> None:
        extractor, _, engine = self.prepared(_flag_q=True, _flag_r=True, _flag_t=True,
                                             _ipv4=True, _tcp=True)
        with mock.patch('pcapkit.toolkit.pypcapfile.ipv4_reassembly', return_value=None):
            with mock.patch('pcapkit.toolkit.pypcapfile.tcp_reassembly', return_value=None):
                with mock.patch('pcapkit.toolkit.pypcapfile.tcp_traceflow', return_value=None):
                    engine.read_frame()

        extractor._reasm.ipv4.assert_not_called()
        extractor._reasm.tcp.assert_not_called()
        extractor._trace.tcp.assert_not_called()

    def test_read_frame_ignores_reassembly_and_tracing_when_flags_are_off(self) -> None:
        extractor, _, engine = self.prepared(_flag_q=True, _flag_r=False, _flag_t=False,
                                             _ipv4=True, _tcp=True)
        with mock.patch('pcapkit.toolkit.pypcapfile.ipv4_reassembly', return_value='unused'):
            with mock.patch('pcapkit.toolkit.pypcapfile.tcp_reassembly', return_value='unused'):
                with mock.patch('pcapkit.toolkit.pypcapfile.tcp_traceflow', return_value='unused'):
                    engine.read_frame()

        extractor._reasm.ipv4.assert_not_called()
        extractor._trace.tcp.assert_not_called()

    def test_read_frame_ignores_protocols_that_were_not_requested(self) -> None:
        extractor, _, engine = self.prepared(_flag_q=True, _flag_r=True, _flag_t=True,
                                             _ipv4=False, _tcp=False)
        with mock.patch('pcapkit.toolkit.pypcapfile.ipv4_reassembly', return_value='unused'):
            with mock.patch('pcapkit.toolkit.pypcapfile.tcp_reassembly', return_value='unused'):
                with mock.patch('pcapkit.toolkit.pypcapfile.tcp_traceflow', return_value='unused'):
                    engine.read_frame()

        extractor._reasm.ipv4.assert_not_called()
        extractor._reasm.tcp.assert_not_called()
        extractor._trace.tcp.assert_not_called()


class PyPCAPFilePythonCeilingTests(unittest.TestCase):
    """The engine rules itself out above its dependency's Python ceiling.

    ``pypcapfile`` 0.12.0 installs cleanly on Python 3.12 and newer and *then*
    fails, because :mod:`pcapfile.linklayer` imports :mod:`imp`, which 3.12
    removed, and :mod:`pcapfile.savefile` imports ``linklayer``. An import guard
    that only tries ``import pcapfile`` is therefore satisfied, and the
    :exc:`ModuleNotFoundError` escapes from the engine's constructor as a hard
    error rather than degrading to the default engine.

    """

    def test_the_ceiling_is_declared_and_matches_the_imp_removal(self) -> None:
        from pcapkit.foundation.engines.pypcapfile import PyPCAPFile

        # 3.12 is where :mod:`imp` went, so that is the first unsupported version
        self.assertEqual(PyPCAPFile.PYTHON_CEILING, (3, 12))

    def test_unsupported_reason_tracks_the_running_interpreter(self) -> None:
        from pcapkit.foundation.engines.pypcapfile import PyPCAPFile

        reason = PyPCAPFile.unsupported_reason()
        if sys.version_info[:2] >= PyPCAPFile.PYTHON_CEILING:
            self.assertIsNotNone(reason)
            # the message has to name the cause, not merely refuse: a bare
            # "unsupported" sends the reader to the wrong place
            self.assertIn('imp', reason)  # type: ignore[arg-type]
            self.assertIn(f'{sys.version_info[0]}.{sys.version_info[1]}',
                          reason)  # type: ignore[arg-type]
        else:
            self.assertIsNone(reason)

    def test_the_reason_is_decided_by_version_not_by_the_import(self) -> None:
        """The verdict must not depend on whether ``pcapfile`` is installed.

        Otherwise the answer differs between a machine that has the package and
        one that does not, and the engine would report itself usable on 3.12+
        purely because the failing submodule had not been reached yet.

        """
        from pcapkit.foundation.engines.pypcapfile import PyPCAPFile

        for version, expected in (((3, 11), False), ((3, 12), True), ((3, 14), True)):
            with self.subTest(python=version):
                with mock.patch.object(sys, 'version_info',
                                       (*version, 0, 'final', 0)):
                    self.assertEqual(PyPCAPFile.unsupported_reason() is not None,
                                     expected)


if __name__ == '__main__':
    unittest.main()
