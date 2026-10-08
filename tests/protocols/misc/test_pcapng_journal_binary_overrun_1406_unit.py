# -*- coding: utf-8 -*-
"""GitHub issue #1406: a journal binary field past its entry keeps the entry as captured.

A systemd Journal Export binary field declaring more octets than its entry
holds was clamped. The rebuild then differed: the length prefix rewritten to the
clamped size, and a terminating newline appended that was never there. Under the
owner's ruling (option 1, strict, like #1325) the overrun raises, and the whole
entry is kept as the octets captured: it parses as no entries, is exposed as
``entry_raw``, and the block's ``make`` writes it back verbatim.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import struct
import unittest
import warnings

from tests.protocols.misc.test_pcapng_roundtrip2_unit import PCAPNGTestCase


def _journal(entry: 'bytes') -> 'bytes':
    """A systemd Journal Export Block holding ``entry``, zero-padded to 32 bits."""
    entry += bytes(-len(entry) % 4)
    length = len(entry) + 12
    return struct.pack('<II', 9, length) + entry + struct.pack('<I', length)


class TestPCAPNGJournalBinaryOverrun(PCAPNGTestCase):
    """Pin how an overrunning journal binary field parses and rebuilds."""

    def test_overrun_keeps_the_entry_and_rebuilds(self) -> None:
        from pcapkit.utilities.warnings import ProtocolWarning

        for entry in (b'BIN\n' + struct.pack('<Q', 100) + b'abc',
                      b'MESSAGE=hi\nBIN\n' + struct.pack('<Q', 100) + b'abc',
                      b'A=1\n\nBIN\n' + struct.pack('<Q', 2 ** 64 - 1) + b'xy',
                      b'BIN\n' + struct.pack('<Q', 1 << 63) + b'abc\n'):
            with self.subTest(entry=entry):
                octets = _journal(entry)
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    info = self._parse(octets).info
                self.assertTrue(any(item.category is ProtocolWarning
                                    and 'kept as captured' in str(item.message) for item in caught))
                self.assertEqual(info.data, ())
                self.assertEqual(info.entry_raw, octets[8:-4])
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    self.assertRebuilds(octets)

    def test_well_formed_entries_still_parse(self) -> None:
        for entry, field, value in ((b'BIN\n' + struct.pack('<Q', 3) + b'abc\n', 'BIN', b'abc'),
                                    (b'MESSAGE=hello\n', 'MESSAGE', 'hello')):
            with self.subTest(entry=entry):
                octets = _journal(entry)
                info = self._parse(octets).info
                self.assertEqual(info.data[0][field], value)
                self.assertFalse(hasattr(info, 'entry_raw'))
                self.assertRebuilds(octets)

    def test_extraction_continues_past_the_kept_block(self) -> None:
        """The block after the malformed journal entry is still extracted."""
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from tests.protocols.misc.test_pcapng_unit import NamedBuffer

        shb = struct.pack('<IIIHHqI', 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
        idb = struct.pack('<IIHHII', 0x00000001, 20, 1, 0, 0, 20)
        bad = _journal(b'BIN\n' + struct.pack('<Q', 100) + b'abc')
        good = _journal(b'MESSAGE=hello\n')
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = Extractor(NamedBuffer(shb + idb + bad + good), nofile=True, store=True)
            journals = extractor.engine._ctx_list[0].journals
            self.assertEqual(len(journals), 2)
            self.assertEqual(journals[0].data, ())
            self.assertEqual(journals[1].data[0]['MESSAGE'], 'hello')
            rebuilt = PCAPNG.from_data(journals[0], num=0, sct=1, ctx=None).data
        self.assertEqual(rebuilt, bad)


if __name__ == '__main__':
    unittest.main()
