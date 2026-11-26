# -*- coding: utf-8 -*-
"""GitHub issue #1558: a Simple Packet Block keeps its padding when the snaplen is 0.

An SPB's packet data is ``min(original_len, snaplen)`` octets, with interface
0's snaplen, and a snaplen of 0 means no limit. Guards against a 0 read as a
limit of no octets, which takes the block's padding as packet data: 57 data
octets come out as 60. :class:`~pcapkit.protocols.misc.pcapng.protocol.PCAPNG` reads
interface 0's snaplen off the section context only where it is not 0, and reads a
zero snaplen handed in as ``__packet__['snaplen']`` as no limit too. The default
engine hands in none (#2840).

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
            return pcapkit.extract(fin=path, engine='default', store=True)

    def test_engine_reads_the_original_length(self) -> None:
        for snaplen in (0, 65535):
            with self.subTest(snaplen=snaplen):
                extractor = self._extract(snaplen)
                self.assertEqual(extractor.length, 1)
                info = extractor.frame[0].info
                self.assertEqual(info.captured_len, len(DATA))
                self.assertEqual(bytes(info.packet), DATA)

    def test_engine_hands_over_no_snaplen(self) -> None:
        """The parser takes interface 0's from the section context the engine hands it."""
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG

        seen = []
        original = PCAPNG.unpack

        def unpack(self, length=None, **kwargs):  # type: ignore[no-untyped-def]
            seen.append(kwargs.get('__packet__'))
            return original(self, length, **kwargs)

        PCAPNG.unpack = unpack  # type: ignore[method-assign]
        try:
            engine = self._extract(0)._exeng
        finally:
            PCAPNG.unpack = original  # type: ignore[method-assign]
        self.assertEqual(engine._ctx.interfaces[0].snaplen, 0)
        self.assertTrue(seen)
        self.assertEqual([packet for packet in seen if packet is not None], [])

    def test_engine_frame_rebuilds_byte_exactly(self) -> None:
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG

        extractor = self._extract(0)
        frame, context = extractor.frame[0], extractor._exeng._ctx
        for data in (frame.info, frame.info.to_dict()):
            with self.subTest(data=type(data).__name__):
                rebuilt = PCAPNG.from_data(data, num=1, sct=1, ctx=context)
                self.assertEqual(rebuilt.data.hex(), _spb().hex())

    def test_parser_reads_a_zero_snaplen_handed_in_as_no_limit(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.foundation.engines.pcapng import Context
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG

        octets = _spb()
        for snaplen in (0, 65535):
            with self.subTest(interface_snaplen=snaplen):
                section = PCAPNG.build(num=0, sct=1, ctx=None, type=BlockType.Section_Header_Block, block={})
                context = Context(section.info)
                interface = PCAPNG.build(num=1, sct=1, ctx=context, type=BlockType.Interface_Description_Block,
                                         block={'linktype': 1, 'snaplen': snaplen})
                context.interfaces.append(interface.info)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    # NOTE: Handed in as state, the one route left for it (#2840).
                    parsed = PCAPNG._from_parent(octets, len(octets), {'num': 2, 'sct': 1, 'ctx': context},
                                                 __packet__={'snaplen': 0})
                self.assertEqual(parsed.info.captured_len, len(DATA))
                self.assertEqual(bytes(parsed.info.packet), DATA)
                rebuilt = PCAPNG.from_data(parsed.info, num=2, sct=1, ctx=context)
                self.assertEqual(rebuilt.data.hex(), octets.hex())


if __name__ == '__main__':
    unittest.main()
