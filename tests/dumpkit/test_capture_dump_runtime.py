# -*- coding: utf-8 -*-
"""Every output format over every sample capture: exact, complete, deterministic.

GitHub issue #1202. For each capture in :file:`examples/captures/`:

* ``format='pcap'`` writes a file byte-identical to its input. PCAP-NG input is
  left out, because PCAP output of it is refused by design.
* ``json``, ``plist`` and ``tree`` each write the same bytes on a second run.
* each of the three holds one section per record or block of the input, counted
  from the file itself rather than from the extractor, and in the same order;
* a ``json`` frame section carries every top-level key of the frame's
  :class:`~pcapkit.corekit.infoclass.Info` and its protocol chain.

Deeper key-by-key completeness is not asserted: options dump as one mapping per
entry (#1263), so the rendering legitimately differs from ``Info.to_dict()``.

A failing check is listed in :data:`KNOWN_FAILURES` with its tracking issue and
must still fail in the recorded way; every other check must pass.

The module reads generated captures, so it belongs to the fixture-dependent tier.

"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import plistlib
import struct
import tempfile
import unittest
import warnings
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING, NamedTuple

from tests._support import close_extractor, reimport_once_per_class, time_limit
from tests._tiers import SAMPLE_ROOT

if TYPE_CHECKING:
    from typing import Any, Optional

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Whole seconds one sweep over every capture may take. The slowest takes ~15.
SWEEP_TIMEOUT = 300


class Gap(NamedTuple):
    """One check that fails today, and the defect that stops it."""

    #: Tracking issue, or :data:`None` while the defect is not yet filed.
    issue: 'Optional[int]'
    #: Name of the exception the check raises.
    status: 'str'
    #: The defect and how to reproduce it.
    defect: 'str'


#: Every check that fails today, by test method; each applies to every capture.
KNOWN_FAILURES = {}  # type: dict[str, Gap]


def captures(pcapng: 'bool' = True) -> 'list[str]':
    """Every capture under :data:`~tests._tiers.SAMPLE_ROOT`, by file name."""
    return sorted(path.name for path in SAMPLE_ROOT.iterdir()
                  if path.suffix in ('.pcap', '.cap') or (pcapng and path.suffix == '.pcapng'))


def section_count(raw: 'bytes') -> 'int':
    """Sections a dump of ``raw`` should hold, counted from the file's own framing.

    PCAP: the global header plus one per record. PCAP-NG: one per block.

    """
    count, offset = 0, 0
    if raw[:4] == b'\x0a\x0d\x0d\x0a':
        endian = '<'
        while offset < len(raw):
            if raw[offset:offset + 4] == b'\x0a\x0d\x0d\x0a':
                endian = '<' if raw[offset + 8:offset + 12] == b'\x4d\x3c\x2b\x1a' else '>'
            offset += struct.unpack(f'{endian}I', raw[offset + 4:offset + 8])[0]
            count += 1
        return count
    endian = '<' if raw[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    offset, count = 24, 1
    while offset + 16 <= len(raw):
        offset += 16 + struct.unpack(f'{endian}I', raw[offset + 8:offset + 12])[0]
        count += 1
    return count


def sections(fmt: 'str', path: 'str') -> 'list[str]':
    """Top-level section names of a ``fmt`` dump, read without pcapkit."""
    if fmt == 'json':
        with open(path, encoding='utf-8') as file:
            return list(json.load(file))
    if fmt == 'plist':
        # ElementTree, so the plistlib test below is checked against an independent reader.
        root = ET.parse(path).getroot()
        return [key.text or '' for key in root[0].findall('key')]
    with open(path, encoding='utf-8') as file:
        return [line.rstrip('\n') for line in file if line.strip() and not line[0].isspace()]


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class CaptureDumpTests(unittest.TestCase):
    """Pin what each writer makes of every capture, by reading the file back."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        self.tmpdir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self.tmpdir.cleanup)
        quiet = warnings.catch_warnings()
        quiet.__enter__()  # pylint: disable=unnecessary-dunder-call
        self.addCleanup(quiet.__exit__, None, None, None)
        warnings.simplefilter('ignore')

    def dump(self, name: 'str', fmt: 'str', stem: 'str', **kwargs: 'Any') -> 'tuple[Any, str]':
        """Extract capture ``name`` to ``stem`` as ``fmt``; return the extractor and output path."""
        from pcapkit import extract

        out = os.path.join(self.tmpdir.name, stem)
        extractor = extract(fin=str(SAMPLE_ROOT / name), fout=out, format=fmt, **kwargs)
        self.addCleanup(close_extractor, extractor)
        return extractor, extractor.output

    def test_pcap_output_is_byte_identical_to_its_input(self) -> None:
        with time_limit(SWEEP_TIMEOUT):
            for name in captures(pcapng=False):
                _, path = self.dump(name, 'pcap', f'{name}.out.pcap', store=False, extension=False)
                with self.subTest(capture=name), open(path, 'rb') as file:
                    self.assertEqual(file.read(), (SAMPLE_ROOT / name).read_bytes())

    def assertDumpIsCompleteAndDeterministic(self, fmt: 'str') -> None:
        """Two runs agree byte for byte, with one section per record or block."""
        with time_limit(SWEEP_TIMEOUT):
            for name in captures():
                outputs = [self.dump(name, fmt, f'{name}.{run}', store=False)[1] for run in (1, 2)]
                first, second = (pathlib.Path(path).read_bytes() for path in outputs)
                names = sections(fmt, outputs[0])
                with self.subTest(capture=name, format=fmt):
                    self.assertEqual(first, second, 'the second run wrote different bytes')
                    self.assertEqual(len(names), section_count((SAMPLE_ROOT / name).read_bytes()))
                    self.assertEqual(len(set(names)), len(names), 'a section name repeats')
                    # Every format names the same sections in the same order.
                    if fmt != 'json':
                        json_path = self.dump(name, 'json', f'{name}.ref', store=False)[1]
                        self.assertEqual(names, sections('json', json_path))

    def test_json_dump_is_complete_and_deterministic(self) -> None:
        self.assertDumpIsCompleteAndDeterministic('json')

    def test_plist_dump_is_complete_and_deterministic(self) -> None:
        self.assertDumpIsCompleteAndDeterministic('plist')

    def test_tree_dump_is_complete_and_deterministic(self) -> None:
        self.assertDumpIsCompleteAndDeterministic('tree')

    def test_json_frame_sections_carry_every_info_key_and_the_chain(self) -> None:
        with time_limit(SWEEP_TIMEOUT):
            for name in captures():
                extractor, path = self.dump(name, 'json', f'{name}.frames', store=True)
                with open(path, encoding='utf-8') as file:
                    report = json.load(file)
                for number, frame in enumerate(extractor.frame, start=1):
                    section = report[f'Frame {number}']
                    with self.subTest(capture=name, frame=number):
                        self.assertEqual(list(section), list(frame.info.to_dict()))
                        self.assertEqual(section['protocols'], str(frame.protochain))

    def test_plist_dump_reads_back_through_plistlib(self) -> None:
        gap = KNOWN_FAILURES.get('test_plist_dump_reads_back_through_plistlib')
        with time_limit(SWEEP_TIMEOUT):
            for name in captures():
                _, path = self.dump(name, 'plist', f'{name}.lib', store=False)
                with self.subTest(capture=name), open(path, 'rb') as file:
                    try:
                        report = plistlib.load(file)
                    except Exception as exc:  # pylint: disable=broad-except
                        got = type(exc).__name__
                    else:
                        got = 'OK'
                        self.assertEqual(list(report), sections('plist', path))
                    self.assertEqual(got, 'OK' if gap is None else gap.status)


if __name__ == '__main__':
    unittest.main()
