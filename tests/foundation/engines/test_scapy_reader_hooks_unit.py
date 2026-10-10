# -*- coding: utf-8 -*-
"""The scapy engine's PCAP-NG reader overrides Scapy's private hooks safely.

Its reader subclass of :mod:`pcapkit.foundation.engines.scapy` overrides private
methods of :class:`scapy.utils.RawPcapNgReader` whose contracts differ by Scapy
version, and ``sniff`` turns an exception raised by any of them into a warning
and an empty capture. So each contract is pinned here against a stand-in for
the parent method, whichever Scapy is installed:

* ``_check_interface_id`` returns whether the interface exists since Scapy 2.8,
  which then skips the block on a false result; before 2.8 it returns
  :data:`None` and raises instead. An override that dropped the result made 2.8
  skip every packet block.
* Scapy 2.5 keeps an interface as ``(linktype, snaplen, tsresol)`` and 2.7 as
  ``(linktype, snaplen, options)``, so the ``if_tsoffset`` of each interface is
  kept by the reader itself, not written into Scapy's tuple.
* A hook Scapy no longer has is an error, never a fix left unapplied.

"""
from __future__ import annotations

import importlib.util
import struct
import unittest
from unittest import mock

from tests._support import reimport_once_per_class

HAS_SCAPY = importlib.util.find_spec('scapy') is not None
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))


def _options(order: 'str', *options: 'tuple[int, bytes]') -> 'bytes':
    """An options area, each value padded to 32 bits, then ``opt_endofopt``."""
    out = b''
    for code, value in options:
        out += struct.pack(f'{order}HH', code, len(value)) + value + bytes(-len(value) % 4)
    return out + struct.pack(f'{order}HH', 0, 0)


@unittest.skipUnless(HAS_RUNTIME and HAS_SCAPY, 'runtime dependencies or scapy not installed')
class ScapyReaderHookTests(unittest.TestCase):
    """Each overridden hook keeps the contract of the Scapy it subclasses."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _reader(order: 'str' = '<'):  # type: ignore[no-untyped-def]
        """A PCAP-NG reader of the engine's, opened on no file."""
        from pcapkit.foundation.engines.scapy import _reader_type

        reader_type = _reader_type().alternative
        reader = object.__new__(reader_type)
        reader.endian = order
        reader.interfaces = []
        reader._offsets = []  # pylint: disable=protected-access
        return reader

    def test_check_interface_id_passes_the_result_through(self) -> None:
        from scapy.utils import RawPcapNgReader

        reader = self._reader()
        for result in (True, False, None):
            with self.subTest(result=result), \
                    mock.patch.object(RawPcapNgReader, '_check_interface_id', autospec=True,
                                      return_value=result) as parent:
                self.assertIs(reader._check_interface_id(3), result)  # pylint: disable=protected-access
                parent.assert_called_once_with(reader, 3)
                self.assertEqual(reader._interface, 3)  # pylint: disable=protected-access

    def test_tsoffset_is_kept_beside_any_shape_of_interface(self) -> None:
        from scapy.utils import RawPcapNgReader

        def parent(self: 'RawPcapNgReader', block: 'bytes', _: 'int') -> 'None':
            self.interfaces.append(shape)

        idb = struct.pack('<HHI', 228, 0, 65535) + _options('<', (14, struct.pack('<q', 100)))
        # Scapy 2.5's interface, and 2.7's
        for shape in ((228, 65535, 1_000_000), (228, 65535, {'tsresol': 1_000_000})):
            with self.subTest(shape=type(shape[2]).__name__), \
                    mock.patch.object(RawPcapNgReader, '_read_block_idb', parent):
                reader = self._reader()
                reader._read_block_idb(idb, 0)  # pylint: disable=protected-access
                reader._read_block_idb(idb[:8], 0)  # pylint: disable=protected-access
                self.assertEqual(reader.interfaces, [shape, shape])
                self.assertEqual(reader._offsets, [100, 0])  # pylint: disable=protected-access

    def test_tsoffset_is_read_in_either_byte_order(self) -> None:
        from pcapkit.foundation.engines.scapy import _read_tsoffset

        for order in ('<', '>'):
            with self.subTest(order=order):
                offset = struct.pack(f'{order}q', -1_000_000)
                # after an option whose value needs padding
                self.assertEqual(_read_tsoffset(_options(order, (2, b'eth0\x00'), (14, offset)), order),
                                 -1_000_000)
                self.assertEqual(_read_tsoffset(_options(order, (9, b'\x06')), order), 0)
                self.assertEqual(_read_tsoffset(b'', order), 0)
                # not 8 octets: not an offset
                self.assertEqual(_read_tsoffset(_options(order, (14, offset[:4])), order), 0)
                # nothing is read past opt_endofopt
                self.assertEqual(_read_tsoffset(_options(order) + _options(order, (14, offset)), order), 0)

    def test_a_missing_hook_is_a_version_error(self) -> None:
        import scapy.utils

        from pcapkit.foundation.engines.scapy import _READER_HOOKS, _reader_type
        from pcapkit.utilities.exceptions import VersionError

        stand_in = type('PcapNgReader', (), {name: lambda self: None for name in _READER_HOOKS[1:]})
        with mock.patch.object(scapy.utils, 'PcapNgReader', stand_in), \
                self.assertRaisesRegex(VersionError, _READER_HOOKS[0]):
            _reader_type()


if __name__ == '__main__':
    unittest.main()
