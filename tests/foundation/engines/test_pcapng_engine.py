from __future__ import annotations

import importlib.util
import os
import struct
import tempfile
import unittest
from unittest import mock

from tests._support import purge_modules
from tests.foundation.engines.test_runtime_engines import FakeInfo, make_extractor

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Link layer type 1, i.e. ``LinkType.ETHERNET``. Spelled as a literal because the
#: captures below are assembled without importing :mod:`pcapkit`, which
#: :meth:`setUp` purges from :data:`sys.modules` before every test.
LINKTYPE_ETHERNET = 1
#: Link layer type 101, i.e. ``LinkType.RAW``. Only used as a *second* interface,
#: to tell which interface a Simple Packet Block was decoded against.
LINKTYPE_RAW = 101

#: A minimal Ethernet frame carrying an (all-zero) ARP payload, used as the packet
#: data of every packet block below. Its only job is to decode differently under
#: :data:`LINKTYPE_ETHERNET` than under :data:`LINKTYPE_RAW`.
ETHERNET_FRAME = bytes.fromhex('ffffffffffff001122334455') + b'\x08\x06' + b'\x00' * 28


class FakeBlock:
    def __init__(self, info: FakeInfo, *, nanosecond: bool = False) -> None:
        self.info = info
        self.nanosecond = nanosecond
        self._ctx = None


class PCAPNGWriter:
    """Assemble a PCAP-NG capture out of raw blocks.

    Only the blocks that Section 4.4 of the PCAP-NG specification is about are
    supported, and none of them carry options -- the point is to build section
    shapes that no sample capture provides, such as a Simple Packet Block in a
    section with several interfaces, or a packet block in a section with no
    Interface Description Block at all.

    """

    def __init__(self, byteorder: str = 'little') -> None:
        self._endian = '<' if byteorder == 'little' else '>'
        self._data = b''

    def __bytes__(self) -> bytes:
        return self._data

    @staticmethod
    def _pad(body: bytes) -> bytes:
        """Pad a block body to a 32-bit boundary."""
        return body + b'\x00' * ((4 - len(body) % 4) % 4)

    def _block(self, block_type: int, body: bytes) -> PCAPNGWriter:
        body = self._pad(body)
        length = 12 + len(body)
        self._data += (struct.pack(f'{self._endian}II', block_type, length) + body
                       + struct.pack(f'{self._endian}I', length))
        return self

    def section_header(self) -> PCAPNGWriter:
        """Section Header Block, with an unspecified section length."""
        return self._block(0x0A0D0D0A,
                           struct.pack(f'{self._endian}IHHq', 0x1A2B3C4D, 1, 0, -1))

    def interface_description(self, linktype: int = LINKTYPE_ETHERNET) -> PCAPNGWriter:
        """Interface Description Block."""
        return self._block(0x00000001,
                           struct.pack(f'{self._endian}HHI', linktype, 0, 0x40000))

    def simple_packet(self) -> PCAPNGWriter:
        """Simple Packet Block, which has no interface ID field."""
        return self._block(0x00000003,
                           struct.pack(f'{self._endian}I', len(ETHERNET_FRAME))
                           + self._pad(ETHERNET_FRAME))

    def enhanced_packet(self, interface_id: int = 0) -> PCAPNGWriter:
        """Enhanced Packet Block."""
        return self._block(0x00000006,
                           struct.pack(f'{self._endian}IIIII', interface_id, 0, 0,
                                       len(ETHERNET_FRAME), len(ETHERNET_FRAME))
                           + self._pad(ETHERNET_FRAME))

    def packet(self, interface_id: int = 0) -> PCAPNGWriter:
        """Obsolete Packet Block."""
        return self._block(0x00000002,
                           struct.pack(f'{self._endian}HHIIII', interface_id, 0, 0, 0,
                                       len(ETHERNET_FRAME), len(ETHERNET_FRAME))
                           + self._pad(ETHERNET_FRAME))

    def interface_statistics(self, interface_id: int = 0) -> PCAPNGWriter:
        """Interface Statistics Block, with no options."""
        return self._block(0x00000005,
                           struct.pack(f'{self._endian}III', interface_id, 0, 0))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PCAPNGEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _info(self, block_type, **kwargs) -> FakeInfo:
        return FakeInfo(type=block_type, **kwargs)

    def _section(self, **kwargs) -> FakeInfo:
        """Section header block info, which always declares a byte order."""
        from pcapkit.const.pcapng.block_type import BlockType

        kwargs.setdefault('byteorder', 'little')
        return self._info(BlockType.Section_Header_Block, **kwargs)

    def test_run_validates_section_header_and_writes_context(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.foundation.engines.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import FormatError

        extractor, sink = make_extractor()
        engine = PCAPNG(extractor)
        shb = FakeBlock(self._section(section='ok'))
        with mock.patch('pcapkit.foundation.engines.pcapng.P_PCAPNG', side_effect=[shb]):
            engine.run()

        self.assertIs(engine._ctx.section, shb.info)
        self.assertEqual(engine._ctx.interfaces, [])
        self.assertEqual(engine._ctx_list, [engine._ctx])
        self.assertIs(shb._ctx, engine._ctx)
        self.assertEqual(sink.records[-1][1], 'Section Header 1')

        bad_engine = PCAPNG(make_extractor()[0])
        bad = FakeBlock(self._info(BlockType.Interface_Description_Block))
        with mock.patch('pcapkit.foundation.engines.pcapng.P_PCAPNG', side_effect=[bad]):
            with self.assertRaises(FormatError):
                bad_engine.run()

    def test_write_file_and_snaplen_helpers_cover_modes(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.foundation.engines.pcapng import Context, PCAPNG

        block_info = self._section(section='ok')
        extractor, sink = make_extractor(_flag_f=True)
        engine = PCAPNG(extractor)
        engine._ctx = Context(block_info)
        engine._write_file(block_info, name='Block')
        self.assertEqual(sink.paths[-1], 'out/Block.json')
        self.assertEqual(extractor._offmt, 'unit')
        self.assertEqual(engine._get_snaplen(), 0xFFFF_FFFF_FFFF_FFFF)

        engine._ctx.interfaces.append(FakeInfo(snaplen=1234))
        self.assertEqual(engine._get_snaplen(), 1234)

        quiet, quiet_sink = make_extractor(_flag_q=True)
        quiet_engine = PCAPNG(quiet)
        quiet_engine._write_file(block_info, name='Quiet')
        self.assertEqual(quiet_sink.records, [])

    def test_read_frame_walks_non_packet_blocks_then_enhanced_packet(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.foundation.engines.pcapng import Context, PCAPNG

        extractor, sink = make_extractor()
        engine = PCAPNG(extractor)
        engine._ctx = Context(self._section(section='initial'))
        engine._ctx_list = [engine._ctx]

        blocks = [
            FakeBlock(self._section(section='new')),
            FakeBlock(self._info(BlockType.Interface_Description_Block, snaplen=2048)),
            FakeBlock(self._info(BlockType.Name_Resolution_Block)),
            FakeBlock(self._info(BlockType.systemd_Journal_Export_Block)),
            FakeBlock(self._info(BlockType.Decryption_Secrets_Block)),
            FakeBlock(self._info(BlockType.Interface_Statistics_Block, interface_id=0)),
            FakeBlock(self._info(BlockType.Custom_Block_that_rewriters_can_copy_into_new_files)),
            FakeBlock(self._info(BlockType.Reserved_0x00000000)),
            FakeBlock(self._info(BlockType.Enhanced_Packet_Block, interface_id=0), nanosecond=True),
        ]

        with mock.patch('pcapkit.foundation.engines.pcapng.P_PCAPNG', side_effect=blocks):
            with mock.patch('pcapkit.toolkit.pcapng.ipv4_reassembly', return_value='ipv4'):
                with mock.patch('pcapkit.toolkit.pcapng.ipv6_reassembly', return_value='ipv6'):
                    with mock.patch('pcapkit.toolkit.pcapng.tcp_reassembly', return_value='tcp'):
                        with mock.patch('pcapkit.toolkit.pcapng.tcp_traceflow', return_value='trace'):
                            block = engine.read_frame()

        self.assertIs(block, blocks[-1])
        self.assertEqual(extractor._frnum, 1)
        extractor._vfunc.assert_called_once_with(extractor, block)
        self.assertEqual([record[1] for record in sink.records],
                         ['Section Header 2', 'Interface Description 1', 'Name Resolution 1',
                          'systemd Journal Export 1', 'Decryption Secrets 1',
                          'Interface Statistics 1', 'Custom 1', 'Unknown 1', 'Frame 1'])
        self.assertEqual(len(engine._ctx_list), 2)
        self.assertEqual(len(engine._ctx.interfaces), 1)
        self.assertEqual(len(engine._ctx.names), 1)
        self.assertEqual(len(engine._ctx.journals), 1)
        self.assertEqual(len(engine._ctx.secrets), 1)
        self.assertEqual(len(engine._ctx.statistics), 1)
        self.assertEqual(len(engine._ctx.custom), 1)
        self.assertEqual(len(engine._ctx.unknown), 1)
        extractor._reasm.ipv4.assert_called_once_with('ipv4')
        extractor._reasm.ipv6.assert_called_once_with('ipv6')
        extractor._reasm.tcp.assert_called_once_with('tcp')
        extractor._trace.tcp.assert_called_once_with('trace')
        self.assertEqual(extractor._frame, [block])

    def test_read_frame_supports_simple_and_deprecated_packet_blocks(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.foundation.engines.pcapng import Context, PCAPNG

        for block_type in (BlockType.Simple_Packet_Block, BlockType.Packet_Block):
            with self.subTest(block_type=block_type):
                extractor, _ = make_extractor(_flag_q=True, _flag_r=False,
                                              _flag_t=False, _flag_d=False)
                engine = PCAPNG(extractor)
                engine._ctx = Context(self._section())
                engine._ctx.interfaces.append(FakeInfo(snaplen=99))
                engine._ctx_list = [engine._ctx]
                info = self._info(block_type, interface_id=0)
                block = FakeBlock(info)
                with mock.patch('pcapkit.foundation.engines.pcapng.P_PCAPNG', side_effect=[block]):
                    self.assertIs(engine.read_frame(), block)
                self.assertEqual(extractor._frnum, 1)

    def test_read_frame_covers_none_helper_results_and_disabled_protocol_flags(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.foundation.engines.pcapng import Context, PCAPNG

        extractor, _ = make_extractor(_flag_q=True, _flag_d=False)
        engine = PCAPNG(extractor)
        engine._ctx = Context(self._section())
        engine._ctx.interfaces.append(FakeInfo(snaplen=99))
        engine._ctx_list = [engine._ctx]
        block = FakeBlock(self._info(BlockType.Enhanced_Packet_Block, interface_id=0),
                          nanosecond=False)
        with mock.patch('pcapkit.foundation.engines.pcapng.P_PCAPNG', side_effect=[block]):
            with mock.patch('pcapkit.toolkit.pcapng.ipv4_reassembly', return_value=None):
                with mock.patch('pcapkit.toolkit.pcapng.ipv6_reassembly', return_value=None):
                    with mock.patch('pcapkit.toolkit.pcapng.tcp_reassembly', return_value=None):
                        with mock.patch('pcapkit.toolkit.pcapng.tcp_traceflow', return_value=None):
                            self.assertIs(engine.read_frame(), block)
        extractor._reasm.ipv4.assert_not_called()
        extractor._reasm.ipv6.assert_not_called()
        extractor._reasm.tcp.assert_not_called()
        extractor._trace.tcp.assert_not_called()

        no_protocols, _ = make_extractor(_flag_q=True, _flag_r=True, _flag_t=True,
                                         _flag_d=False, _ipv4=False, _ipv6=False,
                                         _tcp=False)
        engine = PCAPNG(no_protocols)
        engine._ctx = Context(self._section())
        engine._ctx.interfaces.append(FakeInfo(snaplen=99))
        engine._ctx_list = [engine._ctx]
        block = FakeBlock(self._info(BlockType.Enhanced_Packet_Block, interface_id=0))
        with mock.patch('pcapkit.foundation.engines.pcapng.P_PCAPNG', side_effect=[block]):
            with mock.patch('pcapkit.toolkit.pcapng.ipv4_reassembly', return_value='unused'):
                with mock.patch('pcapkit.toolkit.pcapng.ipv6_reassembly', return_value='unused'):
                    with mock.patch('pcapkit.toolkit.pcapng.tcp_reassembly', return_value='unused'):
                        with mock.patch('pcapkit.toolkit.pcapng.tcp_traceflow', return_value='unused'):
                            self.assertIs(engine.read_frame(), block)
        no_protocols._reasm.ipv4.assert_not_called()
        no_protocols._trace.tcp.assert_not_called()

    def test_read_frame_rejects_invalid_interface_contexts(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.foundation.engines.pcapng import Context, PCAPNG
        from pcapkit.utilities.exceptions import FormatError

        # A Simple Packet Block carries no interface ID field, so a section that
        # describes no interface is the only thing there is to reject about it,
        # and ``read_frame`` is where that happens. The interface *ID* of an EPB,
        # ISB or obsolete Packet Block is instead bounds-checked while the block
        # is parsed -- see
        # ``PCAPNGSectionShapeTests.test_out_of_range_interface_id_is_a_format_error``
        # for the equivalent end-to-end coverage of those three.
        block = FakeBlock(self._info(BlockType.Simple_Packet_Block))

        extractor, _ = make_extractor(_flag_q=True, _flag_r=False,
                                      _flag_t=False, _flag_d=False)
        engine = PCAPNG(extractor)
        engine._ctx = Context(self._section())
        engine._ctx_list = [engine._ctx]
        with mock.patch('pcapkit.foundation.engines.pcapng.P_PCAPNG', side_effect=[block]):
            with self.assertRaises(FormatError) as context:
                engine.read_frame()
        self.assertIn('PCAP-NG: [SPB]', str(context.exception))

    def test_check_packet_block_context_only_fires_for_packet_blocks(self) -> None:
        import io

        from pcapkit.foundation.engines.pcapng import Context, PCAPNG
        from pcapkit.utilities.exceptions import FormatError

        def engine_for(payload: bytes, *, interfaces: int = 0, byteorder: str = 'little'):
            extractor, _ = make_extractor(_ifile=io.BufferedReader(io.BytesIO(payload)))
            engine = PCAPNG(extractor)
            engine._ctx = Context(self._section(byteorder=byteorder))
            engine._ctx_list = [engine._ctx]
            for _ in range(interfaces):
                engine._ctx.interfaces.append(FakeInfo(snaplen=99, linktype=LINKTYPE_ETHERNET))
            return engine

        # a non-packet block in a section with no interface yet is perfectly normal:
        # that is how every section starts, with its Interface Description Blocks
        engine_for(struct.pack('<I', 0x00000001))._check_packet_block_context()

        # so is a packet block once the section has described an interface
        engine_for(struct.pack('<I', 0x00000003), interfaces=1)._check_packet_block_context()

        # a truncated block type field cannot be classified, and is left to the
        # ordinary end-of-file handling rather than reported as a section error
        engine_for(b'\x03\x00')._check_packet_block_context()
        self.assertIsNone(engine_for(b'\x03\x00')._peek_block_type())

        for byteorder in ('little', 'big'):
            for block_type, tag in ((0x00000003, 'SPB'), (0x00000006, 'EPB'), (0x00000002, 'Packet')):
                with self.subTest(byteorder=byteorder, tag=tag):
                    endian = '<' if byteorder == 'little' else '>'
                    engine = engine_for(struct.pack(f'{endian}I', block_type),
                                        byteorder=byteorder)
                    self.assertEqual(engine._peek_block_type(), block_type)
                    with self.assertRaises(FormatError) as context:
                        engine._check_packet_block_context()
                    self.assertIn(f'[{tag}]', str(context.exception))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PCAPNGSectionRuleTests(unittest.TestCase):
    """End-to-end checks of the section rules of Section 4.4 of the PCAP-NG spec.

    These parse synthesised captures rather than sample files, because the section
    shapes at issue -- a Simple Packet Block alongside several interfaces, and a
    packet block with no interface described at all -- are not among the samples.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _extract(self, capture: PCAPNGWriter):
        from pcapkit.interface import extract

        handle, path = tempfile.mkstemp(suffix='.pcapng')
        try:
            with os.fdopen(handle, 'wb') as file:
                file.write(bytes(capture))
            return extract(fin=path, store=True, nofile=True)
        finally:
            os.unlink(path)

    def test_simple_packet_block_parses_in_a_multi_interface_section(self) -> None:
        for byteorder in ('little', 'big'):
            with self.subTest(byteorder=byteorder):
                capture = (PCAPNGWriter(byteorder).section_header()
                           .interface_description()
                           .interface_description()
                           .simple_packet())
                extractor = self._extract(capture)

                self.assertEqual(len(extractor.frame), 1)
                self.assertEqual(len(extractor.engine._ctx.interfaces), 2)

    def test_simple_packet_block_mixes_with_enhanced_packet_blocks(self) -> None:
        # Section 4.4: packets on any interface other than the first have to use an EPB,
        # which is what a real multi-interface section looks like
        capture = (PCAPNGWriter().section_header()
                   .interface_description()
                   .interface_description()
                   .interface_description()
                   .simple_packet()
                   .enhanced_packet(interface_id=2))
        extractor = self._extract(capture)

        self.assertEqual(len(extractor.frame), 2)
        self.assertEqual(len(extractor.engine._ctx.interfaces), 3)

    def test_simple_packet_block_decodes_against_the_first_interface(self) -> None:
        # Section 4.4: an SPB has no interface ID field, so it refers to the interface
        # described by the section's *first* IDB
        ethernet_first = (PCAPNGWriter().section_header()
                          .interface_description(LINKTYPE_ETHERNET)
                          .interface_description(LINKTYPE_RAW)
                          .simple_packet())
        raw_first = (PCAPNGWriter().section_header()
                     .interface_description(LINKTYPE_RAW)
                     .interface_description(LINKTYPE_ETHERNET)
                     .simple_packet())

        self.assertIn('Ethernet', str(self._extract(ethernet_first).frame[0].protochain))
        self.assertNotIn('Ethernet', str(self._extract(raw_first).frame[0].protochain))

    def test_packet_blocks_without_an_interface_description_are_format_errors(self) -> None:
        from pcapkit.utilities.exceptions import FormatError

        blocks = {
            'SPB': lambda writer: writer.simple_packet(),
            'EPB': lambda writer: writer.enhanced_packet(),
            'Packet': lambda writer: writer.packet(),
        }

        for byteorder in ('little', 'big'):
            for tag, add_block in blocks.items():
                with self.subTest(byteorder=byteorder, tag=tag):
                    capture = add_block(PCAPNGWriter(byteorder).section_header())
                    with self.assertRaises(FormatError) as context:
                        self._extract(capture)

                    message = str(context.exception)
                    self.assertIn(f'PCAP-NG: [{tag}]', message)
                    self.assertIn('interface description block', message)

    def test_out_of_range_interface_id_is_a_format_error(self) -> None:
        # Regression for #367: a section with at least one IDB and a block naming
        # an interface it does not describe used to escape as a bare
        # ``IndexError`` out of ``PCAPNG._get_timezone``, because the engine's
        # bounds guards ran only after the block had already been parsed.
        from pcapkit.utilities.exceptions import FormatError

        blocks = {
            'EPB': lambda writer, iface: writer.enhanced_packet(interface_id=iface),
            'Packet': lambda writer, iface: writer.packet(interface_id=iface),
            'ISB': lambda writer, iface: writer.interface_statistics(interface_id=iface),
        }

        for byteorder in ('little', 'big'):
            for tag, add_block in blocks.items():
                with self.subTest(byteorder=byteorder, tag=tag):
                    # two interfaces described, interface 7 named
                    capture = add_block(PCAPNGWriter(byteorder).section_header()
                                        .interface_description()
                                        .interface_description(), 7)
                    with self.assertRaises(FormatError) as context:
                        self._extract(capture)

                    message = str(context.exception)
                    self.assertIn(f'PCAP-NG: [{tag}]', message)
                    self.assertIn('invalid interface ID: 7', message)

    def test_interface_statistics_without_an_interface_description_is_a_format_error(self) -> None:
        # An ISB is not a packet block, so the pre-parse check for a section with
        # no IDB does not cover it; the bounds check in the parse path does.
        from pcapkit.utilities.exceptions import FormatError

        capture = PCAPNGWriter().section_header().interface_statistics(interface_id=0)
        with self.assertRaises(FormatError) as context:
            self._extract(capture)

        message = str(context.exception)
        self.assertIn('PCAP-NG: [ISB]', message)
        self.assertIn('invalid interface ID: 0', message)

    def test_in_range_interface_id_still_parses(self) -> None:
        # The guard is a bound, not a ban: the highest valid ID must still work.
        capture = (PCAPNGWriter().section_header()
                   .interface_description()
                   .interface_description()
                   .interface_statistics(interface_id=1)
                   .enhanced_packet(interface_id=1))
        extractor = self._extract(capture)

        self.assertEqual(len(extractor.frame), 1)
        self.assertEqual(extractor.frame[0].info.interface_id, 1)
        self.assertEqual(len(extractor.engine._ctx.statistics), 1)
        self.assertEqual(extractor.engine._ctx.statistics[0].interface_id, 1)


if __name__ == '__main__':
    unittest.main()
