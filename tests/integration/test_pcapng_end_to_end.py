# -*- coding: utf-8 -*-
"""End-to-end extraction of PCAP-NG captures.

Translates :file:`examples/legacy_smoke/test_pcapng.py`, which dumped
:file:`dhcp.pcapng` to a tree report and checked nothing.
:file:`tests/protocols/test_pcapng_regression.py` already asserts that each
PCAP-NG fixture extracts with ``length > 0`` and ``nofile=True``; this module
pins the exact block inventory *and* dumps a real report file, which is the part
that was never covered.

The six fixtures and what each is for are documented in the module docstring of
:file:`examples/generators/pcapng.py`, which also records the parser defects
they provoke -- those show up as log noise here and are not assertions.

"""
from __future__ import annotations

import unittest

from tests._support import sample_path
from tests.integration._helpers import (HAS_RUNTIME, EndToEndTestCase, read_json, report_stems,
                                        section_counts)

#: Frame count of every PCAP-NG fixture.
PCAPNG_FRAMES = {
    'dhcp.pcapng': 4,
    'dhcp_big_endian.pcapng': 4,
    'dhcp_little_endian.pcapng': 4,
    'many_interfaces.pcapng': 64,
    'test.pcapng': 5,
    'profile.pcapng': 40,
}

#: Block inventory of each fixture whose report can be read back. The
#: ``test.pcapng`` report cannot; see :class:`PcapngUnescapedKeyTests`.
PCAPNG_SECTIONS = {
    'dhcp.pcapng': {'Section Header': 1, 'Interface Description': 1, 'Frame': 4},
    'dhcp_big_endian.pcapng': {'Section Header': 1, 'Interface Description': 1, 'Frame': 4},
    'dhcp_little_endian.pcapng': {'Section Header': 1, 'Interface Description': 1, 'Frame': 4},
    'many_interfaces.pcapng': {'Section Header': 1, 'Interface Description': 11, 'Frame': 64,
                               'Name Resolution': 1, 'Interface Statistics': 11},
    'profile.pcapng': {'Section Header': 1, 'Interface Description': 2, 'Frame': 40,
                       'Interface Statistics': 2},
}

#: The DHCP exchange all three ``dhcp*.pcapng`` fixtures carry, as
#: ``(src, dst, srcport, dstport, udp payload length)`` per frame.
DHCP_EXCHANGE = [
    ('0.0.0.0', '255.255.255.255', 68, 67, 272),
    ('192.168.0.1', '192.168.0.10', 67, 68, 300),
    ('0.0.0.0', '255.255.255.255', 68, 67, 272),
    ('192.168.0.1', '192.168.0.10', 67, 68, 300),
]

#: PCAP-NG's own magic, i.e. the section header block's byte-order magic.
PCAPNG_MAGIC = b'\n\r\r\n'


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PcapngTreeReportTests(EndToEndTestCase):
    """Every fixture dumps a tree report."""

    def test_every_fixture_dumps_a_report_with_its_expected_frame_count(self) -> None:
        for capture, frames in PCAPNG_FRAMES.items():
            with self.subTest(capture=capture):
                extractor = self.extract(fin=sample_path(capture), fout=self.out(capture),
                                         format='tree', store=False)

                report = self.tmp_path / f'{capture}.txt'
                self.assertEqual(extractor.length, frames)
                self.assertEqual(extractor.magic_number, PCAPNG_MAGIC)
                self.assertTrue(report.is_file())
                self.assertGreater(report.stat().st_size, 0)
                self.assertIn('Section Header', report.read_text(encoding='utf-8'))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PcapngJsonReportTests(EndToEndTestCase):
    """The block inventory each fixture's report records."""

    def test_reports_hold_the_expected_blocks(self) -> None:
        for capture, sections in PCAPNG_SECTIONS.items():
            with self.subTest(capture=capture):
                extractor = self.extract(fin=sample_path(capture), fout=self.out(capture),
                                         format='json', store=False)
                report = read_json(extractor.output)

                self.assertEqual(section_counts(report), sections)
                self.assertEqual(extractor.length, PCAPNG_FRAMES[capture])

    def test_interface_descriptions_are_reported_one_per_interface(self) -> None:
        extractor = self.extract(fin=sample_path('many_interfaces.pcapng'),
                                 fout=self.out('many'), format='json', store=False)
        report = read_json(extractor.output)

        self.assertEqual(extractor.length, 64)
        for number in range(1, 12):
            with self.subTest(interface=number):
                self.assertIn(f'Interface Description {number}', report)
        self.assertNotIn('Interface Description 12', report)

    def test_split_reports_cover_every_block_not_just_the_frames(self) -> None:
        extractor = self.extract(fin=sample_path('dhcp.pcapng'), fout=self.out('blocks'),
                                 format='json', files=True, store=False)

        self.assertEqual(report_stems(extractor.output), sorted([
            'Section Header 1', 'Interface Description 1',
            'Frame 1', 'Frame 2', 'Frame 3', 'Frame 4',
        ]))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PcapngByteOrderTests(EndToEndTestCase):
    """The same DHCP exchange read out of three differently laid out files.

    :file:`dhcp.pcapng` is the committed upstream capture, ``_big_endian`` is a
    big-endian section header downloaded from the Wireshark tree, and
    ``_little_endian`` is synthesised. If the section header's byte-order magic
    is honoured, all three yield the same four DHCP datagrams.

    """

    def exchange(self, capture: 'str') -> 'list[tuple[str, str, int, int, int]]':
        extractor = self.extract(fin=sample_path(capture), nofile=True, store=True)
        self.assertEqual(extractor.length, 4)

        rows = []
        for frame in extractor.frame:
            ipv4 = frame['IPv4'].info
            udp = frame['UDP']
            rows.append((str(ipv4.src), str(ipv4.dst),
                         udp.info.srcport.port, udp.info.dstport.port,
                         len(bytes(udp.packet.payload))))
        return rows

    def test_all_three_layouts_yield_the_same_exchange(self) -> None:
        for capture in ('dhcp.pcapng', 'dhcp_big_endian.pcapng', 'dhcp_little_endian.pcapng'):
            with self.subTest(capture=capture):
                self.assertEqual(self.exchange(capture), DHCP_EXCHANGE)

    def test_all_three_layouts_yield_the_same_protocol_chains(self) -> None:
        chains = {}
        for capture in ('dhcp.pcapng', 'dhcp_big_endian.pcapng', 'dhcp_little_endian.pcapng'):
            extractor = self.extract(fin=sample_path(capture), nofile=True, store=True)
            chains[capture] = [str(frame.protochain) for frame in extractor.frame]

        self.assertEqual(list(chains.values()),
                         [['Ethernet:IPv4:UDP:Raw'] * 4] * 3)


class PcapngUnescapedKeyTests(EndToEndTestCase):
    """The report of :file:`test.pcapng`, which carries a decryption secrets block.

    Its tree report is fine -- :class:`PcapngTreeReportTests` covers it -- and
    since #784 its ``plist`` report parses too. Its ``json`` report still comes
    out unparseable, so that round trip lives here behind a skip rather than
    being asserted either way.

    """

    @unittest.skip('blocked on dictdumper interpolating mapping keys into the report without '
                   'escaping them (dictdumper/json.py:224), which the bytes-keyed TLS key log '
                   'entries of a decryption secrets block then break')
    def test_json_report_of_a_decryption_secrets_block_parses(self) -> None:
        """A ``json`` report should be readable by :func:`json.load`.

        For this fixture it is not, and two things stack up to make it so:

        1. ``pcapkit/protocols/schema/misc/pcapng.py:1982`` keys the TLS key log
           entries by ``bytes.fromhex(random)``, i.e. by a raw :class:`bytes`
           client random rather than by its hex text, so the report's key is a
           Python ``bytes`` repr: ``b' !"#$%&\\'()*+,-./0123456789:;<=>?'``.
        2. ``dictdumper/json.py:224`` writes a key as
           ``'"{item}": '.format(item=item)``, with no escaping at all -- values
           go through ``_encode_value`` and are escaped, keys do not. The quotes
           inside that repr therefore land in the document verbatim. Reproduce
           with::

               >>> import dictdumper, json
               >>> dictdumper.JSON('probe.json')({'a"b': 'c"d'})
               >>> json.load(open('probe.json'))
               json.decoder.JSONDecodeError: Expecting ':' delimiter ...

        Measured on this fixture at ``ef859f776``: ``json.load`` fails with
        ``Expecting ':' delimiter: line 1019 column 12`` -- quoted as what that
        commit measured, not as a promise the fixture will keep producing it,
        since a stale instance of exactly this number is what #785 was filed
        over. The same key used to make the ``plist`` report invalid XML too;
        #784 fixed that half by adding an ``escape_key`` helper in
        ``pcapkit/dumpkit/common.py:250`` that XML-escapes mapping keys, leaving
        only this ``json`` quoting defect, still open upstream as
        JarryShaw/DictDumper#121.

        """
        extractor = self.extract(fin=sample_path('test.pcapng'), fout=self.out('report'),
                                 format='json', store=False)
        report = read_json(extractor.output)

        self.assertEqual(extractor.length, 5)
        self.assertEqual(section_counts(report)['Frame'], 5)
        self.assertIn('Decryption Secrets 1', report)


if __name__ == '__main__':
    unittest.main()
