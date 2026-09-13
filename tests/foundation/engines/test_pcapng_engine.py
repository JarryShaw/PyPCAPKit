from __future__ import annotations

import importlib.util
import unittest
from unittest import mock

from tests._support import purge_modules
from tests.foundation.engines.test_runtime_engines import FakeInfo, make_extractor

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class FakeBlock:
    def __init__(self, info: FakeInfo, *, nanosecond: bool = False) -> None:
        self.info = info
        self.nanosecond = nanosecond
        self._ctx = None


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PCAPNGEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _info(self, block_type, **kwargs) -> FakeInfo:
        return FakeInfo(type=block_type, **kwargs)

    def test_run_validates_section_header_and_writes_context(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.foundation.engines.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import FormatError

        extractor, sink = make_extractor()
        engine = PCAPNG(extractor)
        shb = FakeBlock(self._info(BlockType.Section_Header_Block, section='ok'))
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

        block_info = self._info(BlockType.Section_Header_Block, section='ok')
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
        engine._ctx = Context(self._info(BlockType.Section_Header_Block, section='initial'))
        engine._ctx_list = [engine._ctx]

        blocks = [
            FakeBlock(self._info(BlockType.Section_Header_Block, section='new')),
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
                engine._ctx = Context(self._info(BlockType.Section_Header_Block))
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
        engine._ctx = Context(self._info(BlockType.Section_Header_Block))
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
        engine._ctx = Context(self._info(BlockType.Section_Header_Block))
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

        cases = [
            FakeBlock(self._info(BlockType.Interface_Statistics_Block, interface_id=0)),
            FakeBlock(self._info(BlockType.Enhanced_Packet_Block, interface_id=0)),
            FakeBlock(self._info(BlockType.Simple_Packet_Block)),
            FakeBlock(self._info(BlockType.Packet_Block, interface_id=0)),
        ]

        for block in cases:
            with self.subTest(block=block.info.type):
                extractor, _ = make_extractor(_flag_q=True, _flag_r=False,
                                              _flag_t=False, _flag_d=False)
                engine = PCAPNG(extractor)
                engine._ctx = Context(self._info(BlockType.Section_Header_Block))
                engine._ctx_list = [engine._ctx]
                with mock.patch('pcapkit.foundation.engines.pcapng.P_PCAPNG', side_effect=[block]):
                    with self.assertRaises(FormatError):
                        engine.read_frame()


if __name__ == '__main__':
    unittest.main()
