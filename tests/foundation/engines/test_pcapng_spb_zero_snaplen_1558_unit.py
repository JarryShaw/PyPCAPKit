# -*- coding: utf-8 -*-
"""GitHub issue #1558: a Simple Packet Block keeps its padding when the snaplen is 0.

An SPB's packet data is ``min(original_len, snaplen)`` octets, with interface
0's snaplen, and a snaplen of 0 means no limit. The default engine handed
interface 0's snaplen to the parser as ``__packet__['snaplen']`` as it stood, so
a 0 read as a limit of no octets, and the block's padding was read as packet
data: 57 data octets came out as 60. The engine now hands over no limit for a
zero snaplen, and :class:`~pcapkit.protocols.misc.pcapng.PCAPNG` reads a zero
snaplen handed in as no limit too.

Each case builds its capture here. Everything from :mod:`pcapkit` is imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import os
import struct
import tempfile
import unittest
import warnings

from tests._support import reimport_once_per_class

#: 57 data octets, so the block pads them with 3 zero octets.
DATA = bytes(range(1, 58))


def _block(kind: int, body: bytes) -> bytes:
    body += bytes(-len(body) % 4)
    length = len(body) + 12
    return struct.pack('<II', kind, length) + body + struct.pack('<I', length)


def _spb() -> bytes:
    return _block(3, struct.pack('<I', len(DATA)) + DATA)


def _capture(snaplen: int) -> bytes:
    """One SHB, one Ethernet IDB with ``snaplen``, and one SPB of :data:`DATA`."""
    return b''.join([
        _block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)),
        _block(1, struct.pack('<HHI', 1, 0, snaplen)),
        _spb(),
    ])


class TestSPBZeroSnaplen(unittest.TestCase):
    """A zero snaplen clips nothing, and the padding stays padding."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        self._tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self._tmp.cleanup)

    def _extract(self, snaplen: int):  # type: ignore[no-untyped-def]
        import pcapkit

        path = os.path.join(self._tmp.name, f'snaplen-{snaplen}.pcapng')
        with open(path, 'wb') as file:
            file.write(_capture(snaplen))
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return pcapkit.extract(fin=path, engine='default', nofile=True, store=True)

    def test_engine_reads_the_original_length(self) -> None:
        for snaplen in (0, 65535):
            with self.subTest(snaplen=snaplen):
                extractor = self._extract(snaplen)
                self.assertEqual(extractor.length, 1)
                info = extractor.frame[0].info
                self.assertEqual(info.captured_len, len(DATA))
                self.assertEqual(bytes(info.packet), DATA)

    def test_engine_hands_over_no_limit_for_a_zero_snaplen(self) -> None:
        engine = self._extract(0)._exeng
        self.assertEqual(engine._ctx.interfaces[0].snaplen, 0)
        self.assertEqual(engine._get_snaplen(), 0xFFFF_FFFF_FFFF_FFFF)

    def test_engine_frame_rebuilds_byte_exactly(self) -> None:
        from pcapkit.protocols.misc.pcapng import PCAPNG

        extractor = self._extract(0)
        frame, context = extractor.frame[0], extractor._exeng._ctx
        for data in (frame.info, frame.info.to_dict()):
            with self.subTest(data=type(data).__name__):
                rebuilt = PCAPNG.from_data(data, num=1, sct=1, ctx=context)
                self.assertEqual(rebuilt.data.hex(), _spb().hex())

    def test_parser_reads_a_zero_snaplen_handed_in_as_no_limit(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.foundation.engines.pcapng import Context
        from pcapkit.protocols.misc.pcapng import PCAPNG

        octets = _spb()
        for snaplen in (0, 65535):
            with self.subTest(interface_snaplen=snaplen):
                section = PCAPNG(num=0, sct=1, ctx=None, type=BlockType.Section_Header_Block, block={})
                context = Context(section.info)
                interface = PCAPNG(num=1, sct=1, ctx=context, type=BlockType.Interface_Description_Block,
                                   block={'linktype': 1, 'snaplen': snaplen})
                context.interfaces.append(interface.info)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    parsed = PCAPNG(octets, len(octets), num=2, sct=1, ctx=context,
                                    __packet__={'snaplen': 0})
                self.assertEqual(parsed.info.captured_len, len(DATA))
                self.assertEqual(bytes(parsed.info.packet), DATA)
                rebuilt = PCAPNG.from_data(parsed.info, num=2, sct=1, ctx=context)
                self.assertEqual(rebuilt.data.hex(), octets.hex())


if __name__ == '__main__':
    unittest.main()
