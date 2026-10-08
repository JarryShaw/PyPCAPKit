# -*- coding: utf-8 -*-
"""Regression tests for #1256: PCAP-NG block names are unique across sections.

The PCAP-NG engine used to number a non-packet block by the length of its
section's context list, which restarts with every Section Header Block. The
first Interface Description Block of the second section was therefore named
``Interface Description 1`` again, so a mapping dumper (JSON, plist) kept only
one of the two blocks and ``files=True`` overwrote the first block's file.

"""
from __future__ import annotations

import json
import os
import struct
import tempfile
import unittest
import warnings

from pcapkit.interface import extract
from tests._support import sample_path
from tests.foundation.engines.test_pcapng_engine import PCAPNGWriter

#: Every non-packet block kind the engine names by a per-kind counter.
NAMED_KINDS = ('Interface Description', 'Name Resolution', 'systemd Journal Export',
               'Decryption Secrets', 'Interface Statistics', 'Custom', 'Unknown')


class SectionWriter(PCAPNGWriter):
    """:class:`PCAPNGWriter` plus the remaining non-packet block kinds."""

    def name_resolution(self) -> SectionWriter:
        """Name Resolution Block holding only the end-of-records record."""
        return self._block(0x00000004, struct.pack(f'{self._endian}HH', 0, 0))

    def journal_export(self) -> SectionWriter:
        """systemd Journal Export Block with one journal entry field."""
        return self._block(0x00000009, b'MESSAGE=1256\n')

    def decryption_secrets(self) -> SectionWriter:
        """Decryption Secrets Block carrying a TLS key log line."""
        secret = b'CLIENT_RANDOM 00 00\n'
        return self._block(0x0000000A, struct.pack(f'{self._endian}II', 0x544c534b, len(secret))
                           + self._pad(secret))

    def custom(self) -> SectionWriter:
        """Custom Block (copyable) with a private enterprise number and no data."""
        return self._block(0x00000BAD, struct.pack(f'{self._endian}I', 32473))

    def unknown(self) -> SectionWriter:
        """A reserved block type, which the engine records as an unknown block."""
        return self._block(0x00000000, b'\x00' * 4)

    def section(self) -> SectionWriter:
        """One section holding every named block kind once, then one packet."""
        self.section_header().interface_description().name_resolution()
        self.journal_export().decryption_secrets().interface_statistics()
        self.custom().unknown().enhanced_packet()
        return self


def dumped(path: str) -> tuple[list[str], list[str]]:
    """Extract ``path`` to JSON twice: as one file, and as one file per block.

    Returns:
        The top-level keys of the JSON file in order, duplicates included, and
        the sorted file names of the ``files=True`` output directory.

    """
    with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings():
        warnings.simplefilter('ignore')
        out = os.path.join(tmp, 'out.json')
        extract(fin=path, fout=out, format='json', store=False, extension=False,
                engine='pcapkit')
        with open(out, encoding='utf-8') as file:
            keys = [key for key, _ in json.load(file, object_pairs_hook=lambda pairs: pairs)]

        folder = os.path.join(tmp, 'blocks')
        extract(fin=path, fout=folder, format='json', store=False, extension=False,
                files=True, engine='pcapkit')
        files = sorted(os.listdir(folder))
    return keys, files


class SingleSectionSampleTests(unittest.TestCase):
    """A single-section file is named exactly as before the fix."""

    def test_single_section_names_are_unchanged(self) -> None:
        keys, files = dumped(sample_path('dhcp.pcapng'))
        self.assertEqual(keys, ['Section Header 1', 'Interface Description 1',
                                'Frame 1', 'Frame 2', 'Frame 3', 'Frame 4'])
        self.assertEqual(files, sorted(f'{key}.json' for key in keys))


class EveryKindAcrossSectionsTests(unittest.TestCase):
    """Each per-kind counter runs on across sections, not just the IDB one."""

    def test_second_section_continues_every_counter(self) -> None:
        capture = SectionWriter().section().section()
        handle, path = tempfile.mkstemp(suffix='.pcapng')
        try:
            with os.fdopen(handle, 'wb') as file:
                file.write(bytes(capture))
            keys, files = dumped(path)
        finally:
            os.unlink(path)

        expected = []
        for number in (1, 2):
            expected.append(f'Section Header {number}')
            expected.extend(f'{kind} {number}' for kind in NAMED_KINDS)
            expected.append(f'Frame {number}')
        self.assertEqual(keys, expected)
        self.assertEqual(files, sorted(f'{key}.json' for key in expected))


if __name__ == '__main__':
    unittest.main()
