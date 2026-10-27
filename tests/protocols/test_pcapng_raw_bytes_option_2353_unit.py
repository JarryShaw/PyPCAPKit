# -*- coding: UTF-8 -*-
"""Regression tests for issue #2353.

A raw ``bytes`` item inside an IDB's ``options=[...]`` list used to raise
``AttributeError: 'PCAPNG' object has no attribute '_byte'``, as
``_make_pcapng_options`` read ``self._byte`` although only the SHB (and the
systemd journal entry maker) ever set that attribute. The options maker now
falls back to the section context's byteorder, or the system byteorder when
no context is bound.
"""

import unittest

__all__ = ['RawBytesOptionTest']


class RawBytesOptionTest(unittest.TestCase):
    """Test making blocks with a raw ``bytes`` option item."""

    def test_idb_raw_bytes_option_without_context(self) -> 'None':
        """A raw ``bytes`` option in an IDB must not require ``self._byte``."""
        from pcapkit.protocols.misc.pcapng import PCAPNG

        interface = PCAPNG(num=1, sct=1, ctx=None, type=0x00000001,
                           block={'linktype': 1, 'snaplen': 0x40000,
                                  'options': [b'\x01\x00\x05\x00hello\x00\x00\x00']})
        self.assertEqual(len(interface.data) % 4, 0)

    def test_idb_raw_bytes_option_after_shb(self) -> 'None':
        """Ordering SHB → IDB must keep working (byteorder already set)."""
        from pcapkit.foundation.engines.pcapng import Context
        from pcapkit.protocols.misc.pcapng import PCAPNG

        section = PCAPNG(num=0, sct=1, ctx=None, type=0x0A0D0D0A, block={'byteorder': 'big'})
        context = Context(section.info)
        interface = PCAPNG(num=1, sct=1, ctx=context, type=0x00000001,
                           block={'linktype': 1, 'snaplen': 0x40000,
                                  'options': [b'\x01\x00\x05\x00hello\x00\x00\x00']})
        self.assertEqual(len(interface.data) % 4, 0)


if __name__ == '__main__':
    unittest.main()
