"""#1221 and #1222 -- SCTP chunks rebuild byte-exactly through ``from_data``.

#1221: the chunk makers wrote the flags octet back as zero, the DATA and T-bit
flag schemas mapped only the defined bits, and the Invalid Stream Identifier
cause wrote its reserved field back as zero. The raw octets are now kept.

#1222: :rfc:`9260#section-3.2` excludes the last parameter's (or cause's)
padding from the chunk length, but the makers counted it. The canonical length
is now computed, and a parsed chunk that counted the final padding keeps it.

"""
from __future__ import annotations

import importlib.util
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: SCTP common header with a zero checksum.
HEADER = '138813891122334400000000'


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class SCTPRoundTripUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def assertRoundTrip(self, hexdata: str) -> None:
        from pcapkit.protocols.transport.sctp import SCTP

        raw = bytes.fromhex(hexdata)
        self.assertEqual(SCTP.from_data(SCTP(raw).info).data.hex(), raw.hex())

    def test_reserved_chunk_flags_round_trip(self) -> None:
        """#1221: every chunk with reserved flags keeps the raw flags octet."""
        cases = {
            'INIT': '13881389112233445d2a322901a50014aabbccdd00010000000a000a00000001',
            'SACK': HEADER + '035a0010' + '00000001' + '00010000' + '00000000',
            'HEARTBEAT': HEADER + '04110008' + '00010004',
            'HEARTBEAT ACK': HEADER + '05220008' + '00010004',
            'SHUTDOWN': HEADER + '07010008' + '00000001',
            'SHUTDOWN ACK': HEADER + '08800004',
            'ERROR': HEADER + '09770004',
            'COOKIE ECHO': HEADER + '0a020008' + 'deadbeef',
            'COOKIE ACK': HEADER + '0b400004',
        }
        for name, hexdata in cases.items():
            with self.subTest(chunk=name):
                self.assertRoundTrip(hexdata)

    def test_reserved_flag_bits_round_trip(self) -> None:
        """#1221: DATA, ABORT and SHUTDOWN COMPLETE keep their reserved flag bits."""
        from pcapkit.protocols.transport.sctp import SCTP

        cases = {
            'DATA': (HEADER + '00f30011' + '00000001' + '00010002' + '00000000' + 'ab000000', 0xf),
            'ABORT': (HEADER + '06fe0004', 0x7f),
            'SHUTDOWN COMPLETE': (HEADER + '0eff0004', 0x7f),
        }
        for name, (hexdata, reserved) in cases.items():
            with self.subTest(chunk=name):
                self.assertRoundTrip(hexdata)
                chunk = next(iter(SCTP(bytes.fromhex(hexdata)).info.chunks.values()))
                self.assertEqual(chunk.flags.reserved, reserved)

    def test_invalid_stream_cause_reserved_round_trip(self) -> None:
        """#1221: the Invalid Stream Identifier cause keeps its reserved field."""
        from pcapkit.protocols.transport.sctp import SCTP

        hexdata = HEADER + '0600000c' + '00010008' + '0005beef'
        self.assertRoundTrip(hexdata)
        chunk = next(iter(SCTP(bytes.fromhex(hexdata)).info.chunks.values()))
        self.assertEqual(next(iter(chunk.error.values())).reserved, b'\xbe\xef')

    def test_make_defaults_flags_to_zero(self) -> None:
        """#1221: a chunk built from keywords still emits zero flags."""
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.transport.sctp import SCTP

        data = SCTP(srcport=1, dstport=2, chunks=[(Chunk.Initiation, {})]).data
        self.assertEqual(data[13], 0)

    def test_chunk_length_excludes_final_padding(self) -> None:
        """#1222: the final parameter's or cause's padding is not counted."""
        cases = {
            'INIT': '13881389112233445c42009a0100001baabbccdd00010000000a000a00000001000b000761620000',
            'INIT ACK': HEADER + '0200001b' + 'aabbccdd00010000000a000a00000001' + '000b000761620000',
            'HEARTBEAT': HEADER + '0400000b' + '00010007' + '61626300',
            'HEARTBEAT ACK': HEADER + '0500000b' + '00010007' + '61626300',
            'ABORT': HEADER + '0600000b' + '000c0007' + '61626300',
            'ERROR': HEADER + '0900000b' + '000c0007' + '61626300',
        }
        for name, hexdata in cases.items():
            with self.subTest(chunk=name):
                self.assertRoundTrip(hexdata)

    def test_chunk_length_counting_final_padding_is_kept(self) -> None:
        """#1222: a parsed length that counts the final padding, which RFC 9260 allows, is kept."""
        self.assertRoundTrip(
            '13881389112233445c42009a0100001caabbccdd00010000000a000a00000001000b000761620000')

    def test_make_emits_canonical_length(self) -> None:
        """#1222: ``make()`` declares the RFC 9260 length for an unpadded final parameter."""
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.const.sctp.parameter import Parameter
        from pcapkit.protocols.transport.sctp import SCTP

        data = SCTP(srcport=1, dstport=2, chunks=[
            (Chunk.Heartbeat_Request, {'parameters': [(Parameter.Heartbeat_Info, {'info': b'abc'})]}),
        ]).data
        self.assertEqual(data[12:].hex(), '0400000b' + '00010007' + '61626300')


if __name__ == '__main__':
    unittest.main()
