# -*- coding: utf-8 -*-
"""End-to-end extraction into every output format.

Translates the demonstration scripts that only ever checked that
:func:`pcapkit.interface.extract` did not raise --
:file:`examples/legacy_smoke/test_extractor.py` (``tree``, ``json`` and
``plist`` reports), :file:`test_basic.py` (``verbose``),
:file:`test_api.py` and :file:`test_ipv6.py` (``files=True``) and
:file:`test_file.py` (an already-open binary stream) -- into assertions about
the file that actually lands on disk.

Every report is written into the test's own temporary directory. The captures
under :file:`examples/captures/` are inputs only.

"""
from __future__ import annotations

import unittest

from tests._support import sample_path
from tests.integration._helpers import (HAS_RUNTIME, EndToEndTestCase, plist_keys, read_json,
                                        report_stems, section_counts)

#: Sections a report of :file:`in.pcap` has: the global header and six frames.
IN_PCAP_SECTIONS = ['Global Header', 'Frame 1', 'Frame 2', 'Frame 3', 'Frame 4', 'Frame 5', 'Frame 6']
#: Protocol chain of the first frame of :file:`in.pcap`.
IN_PCAP_FIRST_CHAIN = 'Ethernet:IPv6:IPv6_ICMP'


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TreeReportTests(EndToEndTestCase):
    """``format='tree'``, the human-readable report."""

    def test_tree_report_describes_the_global_header_and_every_frame(self) -> None:
        extractor = self.extract(fin=sample_path('in.pcap'), fout=self.out('report'),
                                 format='tree', store=False)

        self.assertEqual(extractor.length, 6)
        self.assertEqual(extractor.output, self.out('report.txt'))

        report = (self.tmp_path / 'report.txt').read_text(encoding='utf-8')
        self.assertIn('Global Header', report)
        for number in range(1, 7):
            self.assertIn(f'Frame {number}', report)
        self.assertIn(IN_PCAP_FIRST_CHAIN, report)

    def test_extension_flag_decides_whether_a_suffix_is_appended(self) -> None:
        appended = self.extract(fin=sample_path('arp.pcap'), fout=self.out('with-suffix'),
                                format='tree', store=False, extension=True)
        verbatim = self.extract(fin=sample_path('arp.pcap'), fout=self.out('verbatim'),
                                format='tree', store=False, extension=False)

        self.assertEqual(appended.output, self.out('with-suffix.txt'))
        self.assertEqual(verbatim.output, self.out('verbatim'))
        self.assertTrue((self.tmp_path / 'with-suffix.txt').is_file())
        self.assertTrue((self.tmp_path / 'verbatim').is_file())

    def test_report_directory_is_created_on_demand(self) -> None:
        extractor = self.extract(fin=sample_path('arp.pcap'), fout=self.out('nested/deeper/report'),
                                 format='tree', store=False)

        self.assertEqual(extractor.length, 2)
        self.assertTrue((self.tmp_path / 'nested' / 'deeper' / 'report.txt').is_file())


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class JsonReportTests(EndToEndTestCase):
    """``format='json'``, the machine-readable report."""

    def test_json_report_parses_and_holds_one_section_per_frame(self) -> None:
        extractor = self.extract(fin=sample_path('in.pcap'), fout=self.out('report'),
                                 format='json', store=False)

        self.assertEqual(extractor.output, self.out('report.json'))

        report = read_json(extractor.output)
        self.assertEqual(list(report), IN_PCAP_SECTIONS)
        self.assertEqual(section_counts(report), {'Global Header': 1, 'Frame': 6})

    def test_json_report_records_the_protocol_chain_of_each_frame(self) -> None:
        extractor = self.extract(fin=sample_path('in.pcap'), fout=self.out('report'),
                                 format='json', store=False)
        report = read_json(extractor.output)

        self.assertEqual(report['Frame 1']['protocols'], IN_PCAP_FIRST_CHAIN)
        self.assertEqual(report['Frame 6']['protocols'], 'Ethernet:IPv4:UDP:Raw')
        self.assertEqual(report['Frame 1']['number'], 1)
        self.assertIn('ethernet', report['Frame 1'])
        self.assertIn('ipv6', report['Frame 1']['ethernet'])

    def test_json_global_header_records_the_capture_byte_order(self) -> None:
        extractor = self.extract(fin=sample_path('in.pcap'), fout=self.out('report'),
                                 format='json', store=False)
        report = read_json(extractor.output)

        self.assertEqual(extractor.magic_number, b'\xd4\xc3\xb2\xa1')
        self.assertEqual(report['Global Header']['magic_number']['byteorder'], 'little')
        self.assertFalse(report['Global Header']['magic_number']['nanosecond'])


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PlistReportTests(EndToEndTestCase):
    """``format='plist'``, the macOS property list report."""

    def test_plist_report_is_well_formed_xml_with_one_key_per_frame(self) -> None:
        extractor = self.extract(fin=sample_path('in.pcap'), fout=self.out('report'),
                                 format='plist', store=False)

        self.assertEqual(extractor.output, self.out('report.plist'))
        self.assertEqual(plist_keys(extractor.output), IN_PCAP_SECTIONS)


class PlistRoundTripTests(EndToEndTestCase):
    """The property list report against a real property list reader.

    Kept apart from :class:`PlistReportTests` so that the skip below covers only
    the reader, and the structural assertions above keep running.

    """

    @unittest.skip('blocked on dictdumper writing <date> values with fractional seconds, '
                   'which plistlib rejects (dictdumper/plist.py:278)')
    def test_plist_report_round_trips_through_plistlib(self) -> None:
        """A ``plist`` report should be readable by :func:`plistlib.load`.

        It is not. ``dictdumper/plist.py:278`` formats every timestamp as
        ``'%Y-%m-%dT%H:%M:%S.%fZ'``, and a property list ``<date>`` carries no
        fractional part, so :func:`plistlib.load` fails on the first frame's
        ``time`` with ``AttributeError: 'NoneType' object has no attribute
        'groupdict'`` -- its date pattern simply does not match. Reproduce with::

            >>> import dictdumper, datetime, plistlib
            >>> dictdumper.PLIST('probe.plist')({'time': datetime.datetime.now()})
            >>> plistlib.load(open('probe.plist', 'rb'))

        The assertions below are what a fixed writer should satisfy, so this
        test can simply be un-skipped once the dumper emits a conformant date.

        """
        import plistlib

        extractor = self.extract(fin=sample_path('in.pcap'), fout=self.out('report'),
                                 format='plist', store=False)

        with open(extractor.output, 'rb') as stream:
            report = plistlib.load(stream)

        self.assertEqual(list(report), IN_PCAP_SECTIONS)
        self.assertEqual(report['Frame 1']['protocols'], IN_PCAP_FIRST_CHAIN)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class SplitReportTests(EndToEndTestCase):
    """``files=True``, one report file per frame."""

    def test_split_json_reports_are_written_one_per_section(self) -> None:
        extractor = self.extract(fin=sample_path('in.pcap'), fout=self.out('frames'),
                                 format='json', files=True, store=False)

        self.assertEqual(extractor.output, self.out('frames'))
        self.assertTrue(self.tmp_path.joinpath('frames').is_dir())
        self.assertEqual(report_stems(extractor.output), sorted(IN_PCAP_SECTIONS))

    def test_every_split_report_is_parseable_on_its_own(self) -> None:
        extractor = self.extract(fin=sample_path('in.pcap'), fout=self.out('frames'),
                                 format='json', files=True, store=False)

        for report in sorted(self.tmp_path.joinpath('frames').iterdir()):
            with self.subTest(report=report.name):
                section = read_json(str(report))
                self.assertIsInstance(section, dict)
                self.assertTrue(section)

        self.assertEqual(extractor.length, 6)

    def test_split_tree_reports_cover_a_sixteen_frame_capture(self) -> None:
        # ``examples/legacy_smoke/test_ipv6.py`` used ipv6.pcap for exactly this,
        # and at 16 frames it is still small enough to be a cheap check that the
        # frame numbering does not collide once it passes single digits.
        extractor = self.extract(fin=sample_path('ipv6.pcap'), fout=self.out('ipv6'),
                                 format='tree', files=True, store=False)

        expected = ['Global Header'] + [f'Frame {number}' for number in range(1, 17)]
        self.assertEqual(extractor.length, 16)
        self.assertEqual(report_stems(extractor.output), sorted(expected))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class InputAndProgressTests(EndToEndTestCase):
    """How the capture gets in, and what the caller is told while it does."""

    def test_extraction_accepts_an_already_open_binary_stream(self) -> None:
        # ``examples/legacy_smoke/test_file.py``: hand ``fin`` a file object
        # rather than a path.
        with open(sample_path('in.pcap'), 'rb') as stream:
            extractor = self.extract(fin=stream, nofile=True, store=True)

            self.assertEqual(extractor.length, 6)
            self.assertEqual(extractor.input, sample_path('in.pcap'))
            self.assertEqual(str(extractor.frame[0].protochain), IN_PCAP_FIRST_CHAIN)

    def test_verbose_handler_is_called_once_per_frame(self) -> None:
        # ``verbose`` also takes a callable, which is the only form of it that
        # can be asserted on without capturing stdout.
        seen = []  # type: list[tuple[int, str]]
        extractor = self.extract(fin=sample_path('in.pcap'), nofile=True, store=False,
                                 verbose=lambda ext, frame: seen.append(
                                     (ext.length, str(frame.protochain))))

        self.assertEqual(extractor.length, 6)
        self.assertEqual([number for number, _ in seen], [1, 2, 3, 4, 5, 6])
        self.assertEqual(seen[0][1], IN_PCAP_FIRST_CHAIN)
        self.assertEqual(seen[-1][1], 'Ethernet:IPv4:UDP:Raw')

    def test_report_attributes_are_refused_when_no_report_is_written(self) -> None:
        from pcapkit.utilities.exceptions import UnsupportedCall

        extractor = self.extract(fin=sample_path('arp.pcap'), nofile=True, store=False)

        with self.assertRaises(UnsupportedCall):
            extractor.output  # pylint: disable=pointless-statement
        with self.assertRaises(UnsupportedCall):
            extractor.frame  # pylint: disable=pointless-statement


if __name__ == '__main__':
    unittest.main()
