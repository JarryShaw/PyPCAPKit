# -*- coding: utf-8 -*-
"""GitHub issue #1984: an unknown, custom or journal block the file cuts short is kept.

The bodies of an unknown block, a Custom Block and a systemd Journal Export
Block are each one field spanning the whole block. A Block Total Length past
the end of the file made that one field declare the missing octets, and past
the zero-pad ceiling the read raised
:exc:`~pcapkit.utilities.exceptions.FieldValueError` from inside the block's
schema, which ended the whole extraction and lost every earlier frame. The body
is sized from the octets the file holds, at any declared length, so the
block is reported as truncated as every other block type is, and extraction
keeps the frames before it.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import io
import struct
import unittest
import warnings

from tests.protocols.misc.test_pcapng_roundtrip2_unit import PCAPNGTestCase

FRAME = bytes(range(1, 61))

#: An unregistered block type, the systemd Journal Export Block, and a Custom Block.
UNKNOWN = 0x77
JOURNAL = 0x9
CUSTOM = 0xBAD

#: Block Total Lengths past and within the zero-pad ceiling.
LENGTHS = (0x7FFF_FFF0, 0x10000)

#: The octets the file holds of a cut block after its Block Total Length.
TAIL = bytes(range(1, 9))

#: The body field of each block type.
FIELD = {UNKNOWN: 'body', JOURNAL: 'entry', CUSTOM: 'data'}


def _block(btype: 'int', body: 'bytes') -> 'bytes':
    """A little-endian block of ``btype`` around ``body``, padded to 32 bits."""
    body += bytes(-len(body) % 4)
    total = 12 + len(body)
    return struct.pack('<II', btype, total) + body + struct.pack('<I', total)


SHB = _block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
IDB = _block(1, struct.pack('<HHI', 1, 0, 0))

#: A well-formed body of each block type.
BODY = {
    UNKNOWN: b'abcdefgh',
    JOURNAL: b'__REALTIME_TIMESTAMP=1\nMESSAGE=hi\n\n',
    CUSTOM: struct.pack('<I', 32473) + b'custom data\x00',
}


def _epb() -> 'bytes':
    """An Enhanced Packet Block on interface 0 holding :data:`FRAME`."""
    return _block(6, struct.pack('<IIIII', 0, 0, 0, len(FRAME), len(FRAME)) + FRAME)


def _cut(btype: 'int', length: 'int') -> 'bytes':
    """A block of ``btype`` declaring ``length`` that the file ends inside."""
    return struct.pack('<II', btype, length) + TAIL


class TestPCAPNGCutBlockPastEOF(PCAPNGTestCase):
    """Pin how a block whose body is one field parses when the file cuts it short."""

    def _extract(self, data: 'bytes') -> 'tuple[list[bytes], list[str]]':
        """Extract ``data``, returning its frames' packets and the warnings raised."""
        import pcapkit

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            extraction = pcapkit.extract(fin=io.BytesIO(data), nofile=True, store=True,
                                         engine='default')
        return ([bytes(frame.info.packet) for frame in extraction.frame],
                [str(item.message) for item in caught])

    def test_earlier_frames_survive(self) -> None:
        for btype in FIELD:
            for length in LENGTHS:
                with self.subTest(btype=hex(btype), length=hex(length)):
                    frames, messages = self._extract(SHB + IDB + _epb() + _cut(btype, length))
                    self.assertEqual(frames, [FRAME])
                    self.assertIn(f'PCAP-NG: [Block {btype}] block length {length} exceeds the '
                                  f'{len(TAIL) + 8} octet(s) left in the file; block truncated',
                                  messages)

    def test_body_is_the_octets_held(self) -> None:
        for btype, name in FIELD.items():
            for length in LENGTHS:
                with self.subTest(btype=hex(btype), length=hex(length)):
                    octets = _cut(btype, length)
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        parsed = self._parse(octets)
                    held = TAIL[4:] if btype == CUSTOM else TAIL
                    self.assertEqual(getattr(parsed.__header__.block, name), held)
                    self.assertEqual(parsed.info.length, length)

    def test_cut_block_rebuilds_as_captured(self) -> None:
        for btype in FIELD:
            for length in LENGTHS:
                with self.subTest(btype=hex(btype), length=hex(length)):
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        self.assertRebuilds(_cut(btype, length))

    def test_well_formed_blocks_are_unchanged(self) -> None:
        for btype, body in BODY.items():
            with self.subTest(btype=hex(btype)):
                octets = _block(btype, body)
                frames, messages = self._extract(SHB + IDB + _epb() + octets + _epb())
                self.assertEqual(frames, [FRAME, FRAME])
                self.assertFalse(any('block truncated' in text for text in messages), messages)
                self.assertFalse(any('block length mismatch' in text for text in messages), messages)
                parsed = self._parse(octets)
                held = body[4:] if btype == CUSTOM else body
                self.assertEqual(getattr(parsed.__header__.block, FIELD[btype]),
                                 held + bytes(-len(held) % 4))
                self.assertRebuilds(octets)


if __name__ == '__main__':
    unittest.main()
