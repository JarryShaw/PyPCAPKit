"""#1474 -- a last SCTP chunk captured without (all of) its padding rebuilds as captured.

:rfc:`9260#section-3.2` pads every chunk to four octets, but the last chunk of a
packet may arrive with fewer pad octets, or none. Parsing already read what was
there; the rebuild zero-filled the rest, so 17 octets in gave 20 out. The chunk's
``padding`` now records the octets as captured whenever they are short, and the
rebuild writes exactly those.

"""
from __future__ import annotations

import importlib.util
import struct
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: SCTP common header with a zero checksum.
COMMON = struct.pack('!HHII', 5000, 5001, 0xdeadbeef, 0)
#: DATA chunk TSN, stream, sequence and PPID.
DATA_HEAD = b'\x00\x00\x00\x01' + b'\x00\x01\x00\x02' + bytes(4)
#: INIT chunk fixed part.
INIT_HEAD = b'\x00\x00\x00\x01' + b'\x00\x00\xff\xff' + b'\x00\x01\x00\x01' + b'\x00\x00\x00\x01'


def chunk(type_: int, flags: int, value: bytes, pad: 'bytes | None' = None) -> bytes:
    """An SCTP chunk, zero-padded to four octets unless ``pad`` is given."""
    length = 4 + len(value)
    pad = bytes(-length % 4) if pad is None else pad
    return struct.pack('!BBH', type_, flags, length) + value + pad


#: Packets whose last chunk is short of its padding, by name.
SHORT = {
    'unknown-chunk-no-padding': COMMON + chunk(0x3f, 0, b'a', pad=b''),
    'data-chunk-one-of-three-zero-pad': COMMON + chunk(0, 0x03, DATA_HEAD + b'X', pad=b'\x00'),
    'data-chunk-two-of-three-zero-pad': COMMON + chunk(0, 0x03, DATA_HEAD + b'X', pad=b'\x00\x00'),
    'data-chunk-two-of-three-nonzero-pad':
        COMMON + chunk(0, 0x03, DATA_HEAD + b'X', pad=b'\xff\xff'),
    'cookie-echo-no-padding': COMMON + chunk(10, 0, b'abcde', pad=b''),
    'second-chunk-no-padding': COMMON + chunk(11, 0, b'') + chunk(0xbf, 0, b'abcde', pad=b''),
}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class SCTPUnpaddedLastChunkUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_rebuilds_from_info(self) -> None:
        """#1474: ``from_data(info)`` writes back only the pad octets captured."""
        from pcapkit.protocols.transport.sctp import SCTP

        for name, raw in SHORT.items():
            with self.subTest(case=name):
                self.assertEqual(SCTP.from_data(SCTP(raw).info).data.hex(), raw.hex())

    def test_rebuilds_from_to_dict(self) -> None:
        """#1474: the record survives ``info.to_dict()``."""
        from pcapkit.protocols.transport.sctp import SCTP

        for name, raw in SHORT.items():
            with self.subTest(case=name):
                self.assertEqual(SCTP.from_data(SCTP(raw).info.to_dict()).data.hex(), raw.hex())

    def test_info_records_padding_as_captured(self) -> None:
        """#1474: the chunk's ``padding`` holds the octets that were there."""
        from pcapkit.protocols.transport.sctp import SCTP

        info = SCTP(SHORT['unknown-chunk-no-padding']).info
        last = list(info.chunks.items(multi=True))[-1][1]
        self.assertEqual(last.padding, b'')

        info = SCTP(SHORT['data-chunk-two-of-three-zero-pad']).info
        last = list(info.chunks.items(multi=True))[-1][1]
        self.assertEqual(last.padding, b'\x00\x00')

    def test_whole_zero_padding_is_not_recorded(self) -> None:
        """#1474: a chunk padded as a fresh build pads keeps no ``padding`` key."""
        from pcapkit.protocols.transport.sctp import SCTP

        raw = COMMON + chunk(0x3f, 0, b'a')
        last = list(SCTP(raw).info.chunks.items(multi=True))[-1][1]
        self.assertNotIn('padding', last)
        self.assertEqual(SCTP.from_data(SCTP(raw).info).data, raw)

    def test_parsed_short_chunk_is_short_only_when_last(self) -> None:
        """#1474: a parsed short chunk moved ahead of another pads in full; last, it stays short."""
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.transport.sctp import SCTP

        short = SCTP(COMMON + chunk(0x3f, 0, b'a', pad=b'')).info
        fresh = SCTP(COMMON + chunk(0x3f, 0, b'ab')).info
        chunks = OrderedMultiDict()  # type: OrderedMultiDict
        for info in (short, fresh):
            for code, value in info.chunks.items(multi=True):
                chunks.add(code, value)

        data = SCTP(srcport=5000, dstport=5001, vtag=0xdeadbeef, chksum=bytes(4),
                    chunks=chunks).data
        self.assertEqual(data[12:], chunk(0x3f, 0, b'a') + chunk(0x3f, 0, b'ab'))

        chunks = OrderedMultiDict()
        for info in (fresh, short):
            for code, value in info.chunks.items(multi=True):
                chunks.add(code, value)
        data = SCTP(srcport=5000, dstport=5001, vtag=0xdeadbeef, chksum=bytes(4),
                    chunks=chunks).data
        self.assertEqual(data[12:], chunk(0x3f, 0, b'ab') + chunk(0x3f, 0, b'a', pad=b''))

    def test_short_record_on_a_non_last_chunk_rebuilds_aligned(self) -> None:
        """#1474: only the last chunk may end short; an earlier one pads in full."""
        from pcapkit.protocols.transport.sctp import SCTP

        raw = COMMON + chunk(0x3f, 0, b'a') + chunk(0xbf, 0, b'b')
        info = SCTP(raw).info
        first = next(iter(info.chunks.values()))
        first.__update__({'padding': b''})
        self.assertEqual(SCTP.from_data(info).data.hex(), raw.hex())

        data = info.to_dict()
        first = next(iter(data['chunks'].values()))
        first.__update__({'padding': b''})
        self.assertEqual(SCTP.from_data(data).data.hex(), raw.hex())

    def test_short_record_on_a_non_last_parameter_rebuilds_aligned(self) -> None:
        """#1474: the same holds for parameters, which end their chunk, not the packet."""
        from pcapkit.protocols.transport.sctp import SCTP

        param = struct.pack('!HH', 0xbfff, 5) + b'q\x00\x00\x00'
        raw = COMMON + chunk(1, 0, INIT_HEAD + param + param) + chunk(11, 0, b'')
        info = SCTP(raw).info
        init = next(iter(info.chunks.values()))
        for item in init.parameters.values():
            item.__update__({'padding': b''})
        self.assertEqual(SCTP.from_data(info).data.hex(), raw.hex())

    def test_make_still_pads_the_last_chunk(self) -> None:
        """#1474: a chunk built from keywords is padded in full, last or not."""
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.transport.sctp import SCTP

        data = SCTP(chunks=[(Chunk.State_Cookie, {'cookie': b'abcde'})]).data
        self.assertEqual(data[12:], chunk(10, 0, b'abcde'))


if __name__ == '__main__':
    unittest.main()
