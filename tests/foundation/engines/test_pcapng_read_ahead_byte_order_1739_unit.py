# -*- coding: utf-8 -*-
"""The PCAP-NG engine sizes a Section Header Block's read-ahead in the order it declares. C.f. #1739.

:meth:`PCAPNG._bound_read_ahead <pcapkit.foundation.engines.pcapng.PCAPNG._bound_read_ahead>`
reads a Section Header Block's Block Total Length in the byte order its
Byte-Order Magic declares, mapped by ``_BYTE_ORDER_OCTETS`` from the magic's one
home, :data:`pcapkit.protocols.schema.misc.pcapng.BYTE_ORDER_MAGIC`. Read in
the wrong order, the length of a 28-octet section header is ``0x1C000000``, so
the reader would read ahead hundreds of megabytes instead of to the block's end.

Both byte orders are checked, as no capture in the test suite is a big-endian
PCAP-NG file read through this probe. Every value is built here, so the module
is in the unit tier.

"""
from __future__ import annotations

import io
import struct
import types
import unittest


def _shb(byteorder: 'str', length: 'int' = 28) -> 'bytes':
    """A Section Header Block with no options, in ``byteorder``."""
    end = '>' if byteorder == 'big' else '<'
    return (struct.pack(f'{end}IIIHHq', 0x0A0D0D0A, length, 0x1A2B3C4D, 1, 0, -1)
            + struct.pack(f'{end}I', length))


class TestReadAheadByteOrder(unittest.TestCase):
    """A Section Header Block is measured in its own byte order."""

    def _read_ahead(self, data: 'bytes') -> 'int':
        from pcapkit.corekit.io import SeekableReader  # pylint: disable=import-outside-toplevel
        from pcapkit.foundation.engines.pcapng import PCAPNG  # pylint: disable=import-outside-toplevel

        reader = SeekableReader(io.BytesIO(data), buffer_size=16, stream_closing=False)
        self.addCleanup(reader.close)
        engine = PCAPNG.__new__(PCAPNG)
        engine._extractor = types.SimpleNamespace(_ifile=reader)  # type: ignore[assignment]  # pylint: disable=protected-access
        engine._ctx = None  # type: ignore[assignment]  # pylint: disable=protected-access
        engine._peek = lambda size: data[:size]  # type: ignore[method-assign]  # pylint: disable=protected-access
        engine._bound_read_ahead()  # pylint: disable=protected-access
        return reader._read_ahead_size  # pylint: disable=protected-access

    def test_big_endian(self) -> 'None':
        data = _shb('big')
        self.assertEqual(data[8:12], b'\x1a\x2b\x3c\x4d')
        self.assertEqual(self._read_ahead(data), 28)

    def test_little_endian(self) -> 'None':
        data = _shb('little')
        self.assertEqual(data[8:12], b'\x4d\x3c\x2b\x1a')
        self.assertEqual(self._read_ahead(data), 28)

    def test_longer_block_both_orders(self) -> 'None':
        for byteorder in ('big', 'little'):
            with self.subTest(byteorder=byteorder):
                data = _shb(byteorder, 40)
                self.assertEqual(self._read_ahead(data), 40)

    def test_unknown_magic_keeps_the_buffer(self) -> 'None':
        data = bytearray(_shb('big'))
        data[8:12] = b'\x00\x11\x22\x33'
        self.assertEqual(self._read_ahead(bytes(data)), 16)


if __name__ == '__main__':
    unittest.main()
