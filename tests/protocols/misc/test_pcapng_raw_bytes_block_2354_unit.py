# -*- coding: utf-8 -*-
"""GitHub issue #2354: ``PCAPNG.make(block=<bytes>)`` parses the raw block.

``make()`` types ``block`` as accepting :obj:`bytes`, and packs a raw block
verbatim, but :meth:`~pcapkit.protocols.misc.pcapng.PCAPNG.read` then read the
made header, whose ``block`` was those :obj:`bytes` rather than a block schema,
and raised ``AttributeError: 'bytes' object has no attribute 'length'`` for
every block type. The raw block is now parsed out of the packed octets, as a
block read from a capture is, and octets that hold no block raise
:exc:`~pcapkit.utilities.exceptions.ProtocolError`.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import struct
import unittest

from tests.protocols.misc.test_pcapng_roundtrip2_unit import PCAPNGTestCase

#: Secrets Type no registry names.
UNKNOWN_SECRETS = 0x12345678


def _body(body: 'bytes') -> 'bytes':
    """A little-endian block body around ``body``, after the Block Type."""
    body += bytes(-len(body) % 4)
    total = 12 + len(body)
    return struct.pack('<I', total) + body + struct.pack('<I', total)


class TestPCAPNGRawBytesBlock(PCAPNGTestCase):
    """Pin how a block given to ``make()`` as raw bytes builds."""

    def _make(self, btype: 'int', block: 'bytes') -> 'object':
        from pcapkit.protocols.misc.pcapng import PCAPNG

        return PCAPNG(num=2, sct=1, ctx=self._context(), type=btype, block=block)

    def test_dsb_from_raw_bytes(self) -> None:
        raw = _body(struct.pack('<II', UNKNOWN_SECRETS, 5) + b'abcde')
        made = self._make(10, raw)
        self.assertEqual(made.data, struct.pack('<I', 10) + raw)
        self.assertEqual(made.info.secrets_type, UNKNOWN_SECRETS)
        self.assertEqual(made.info.secrets_length, 5)
        self.assertEqual(made.info.secrets_data.data, b'abcde')

    def test_matches_the_parsed_block(self) -> None:
        cases = {
            1: _body(struct.pack('<HHI', 1, 0, 0x40000)),
            6: _body(struct.pack('<IIIII', 0, 0, 0, 4, 4) + b'\x01\x02\x03\x04'),
            10: _body(struct.pack('<II', UNKNOWN_SECRETS, 4) + b'abcd'),
        }
        for btype, raw in cases.items():
            with self.subTest(type=btype):
                octets = struct.pack('<I', btype) + raw
                made = self._make(btype, raw)
                parsed = self._parse(octets)
                self.assertEqual(made.data, octets)
                self.assertEqual(made.info, parsed.info)

    def test_raw_bytes_holding_no_block(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        for raw in (b'', bytes(8)):
            with self.subTest(raw=raw):
                with self.assertRaises(ProtocolError) as context:
                    self._make(10, raw)
                self.assertIn('malformed raw block given to make()', str(context.exception))


if __name__ == '__main__':
    unittest.main()
