# -*- coding: utf-8 -*-
"""The PCAP-NG engine reads a Decryption Secrets Block ahead as far as its padded secrets run.

:meth:`PCAPNG._bound_read_ahead <pcapkit.foundation.engines.pcapng.PCAPNG._bound_read_ahead>`
has a non-seekable input read ahead to a block's Total Length, and a Decryption
Secrets Block further when its Secrets Length runs past it: to the block's fixed
fields plus the secrets padded to 32 bits by
:func:`~pcapkit.corekit.schema.padding.pad_length`, the span the block is
parsed over (#1586, #2614). Every value is built here, so the module is in the
unit tier.

"""
from __future__ import annotations

import io
import struct
import types
import unittest

#: Octets of a Decryption Secrets Block's fixed fields: type, both lengths,
#: Secrets Type and Secrets Length.
DSB_MINIMUM = 20


def _dsb(length: 'int', secrets: 'int') -> 'bytes':
    """The first 16 octets of a little-endian Decryption Secrets Block."""
    return struct.pack('<IIII', 0x0000000A, length, 0x544c534b, secrets)


class TestReadAheadDecryptionSecrets(unittest.TestCase):
    """A Decryption Secrets Block is read ahead to whichever ends later."""

    def _read_ahead(self, data: 'bytes') -> 'int':
        from pcapkit.corekit.io import SeekableReader  # pylint: disable=import-outside-toplevel
        from pcapkit.foundation.engines.pcapng import PCAPNG  # pylint: disable=import-outside-toplevel

        reader = SeekableReader(io.BytesIO(data), buffer_size=8, stream_closing=False)
        self.addCleanup(reader.close)
        engine = PCAPNG.__new__(PCAPNG)
        engine._extractor = types.SimpleNamespace(_ifile=reader)  # type: ignore[assignment]  # pylint: disable=protected-access
        engine._ctx = types.SimpleNamespace(section=types.SimpleNamespace(byteorder='little'))  # type: ignore[assignment]  # pylint: disable=protected-access
        engine._peek = lambda size: data[:size]  # type: ignore[method-assign]  # pylint: disable=protected-access
        engine._bound_read_ahead()  # pylint: disable=protected-access
        return reader._read_ahead_size  # pylint: disable=protected-access

    def test_secrets_within_the_block_keep_its_length(self) -> 'None':
        for secrets in (0, 1, 8, 12):
            with self.subTest(secrets=secrets):
                self.assertEqual(self._read_ahead(_dsb(32, secrets)), 32)

    def test_secrets_past_the_block_read_to_their_padding(self) -> 'None':
        for secrets, padded in ((13, 16), (14, 16), (15, 16), (16, 16), (17, 20), (100, 100)):
            with self.subTest(secrets=secrets):
                self.assertEqual(self._read_ahead(_dsb(32, secrets)), DSB_MINIMUM + padded)


if __name__ == '__main__':
    unittest.main()
