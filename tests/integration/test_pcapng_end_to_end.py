# -*- coding: utf-8 -*-
"""End-to-end extraction of PCAP-NG captures.

Translates :file:`examples/legacy_smoke/test_pcapng.py`, which dumped
:file:`dhcp.pcapng` to a tree report and checked nothing.
:file:`tests/protocols/test_pcapng_regression.py` already asserts that each
PCAP-NG fixture extracts with ``length > 0`` and ``nofile=True``; this module
pins the exact block inventory *and* dumps a real report file, which that module
does not cover.

The fixtures and what each is for are documented in the module docstring of
:file:`examples/generators/pcapng.py`, which also records the parser defects
they provoke -- those show up as log noise here and are not assertions.

The ``many_interfaces.pcapng`` counts are those of the upstream download. When
the download fails the generator writes a 24-frame stand-in instead, and
:func:`~tests._support.skip_if_stand_in` turns each assertion pinned to upstream
into a skip rather than a failure (#1478). The ``dhcp_big_endian.pcapng``
stand-in is built to upstream's four-frame inventory, so it is asserted either
way.

"""
from __future__ import annotations

import unittest

from tests._support import sample_path, skip_if_stand_in
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

#: Fixtures whose counts above hold for the upstream download only, not for the
#: stand-in the generator synthesises when that download fails (#1478).
UPSTREAM_ONLY_COUNTS = frozenset({'many_interfaces.pcapng'})

#: Block inventory of each fixture's ``json`` report. The ``test.pcapng`` report
#: is read back by :class:`PcapngUnescapedKeyTests` instead.
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
                path = sample_path(capture)
                if capture in UPSTREAM_ONLY_COUNTS:
                    skip_if_stand_in(self, path)
                extractor = self.extract(fin=path, fout=self.out(capture),
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
                path = sample_path(capture)
                if capture in UPSTREAM_ONLY_COUNTS:
                    skip_if_stand_in(self, path)
                extractor = self.extract(fin=path, fout=self.out(capture),
                                         format='json', store=False)
                report = read_json(extractor.output)

                self.assertEqual(section_counts(report), sections)
                self.assertEqual(extractor.length, PCAPNG_FRAMES[capture])

    def test_interface_descriptions_are_reported_one_per_interface(self) -> None:
        path = sample_path('many_interfaces.pcapng')
        skip_if_stand_in(self, path)
        extractor = self.extract(fin=path, fout=self.out('many'), format='json', store=False)
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


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PcapngUnescapedKeyTests(EndToEndTestCase):
    """The ``json`` report of :file:`test.pcapng`, whose mapping keys need escaping.

    The fixture's decryption secrets block keys its TLS key log entries by a raw
    :class:`bytes` client random, and :mod:`dictdumper` writes a mapping key
    into a ``json`` report without escaping it. The report parses only because
    :mod:`pcapkit.dumpkit` escapes the keys itself (GitHub issue #1152).

    """

    def test_json_report_of_a_decryption_secrets_block_parses(self) -> None:
        """The report is readable by :func:`json.load` despite its keys.

        :meth:`TLSKeyLog.post_process
        <pcapkit.protocols.schema.misc.pcapng.TLSKeyLog.post_process>` keys the
        entries by ``bytes.fromhex(random)``, so the key the writer formats is a
        :class:`bytes` repr carrying ``"`` and ``\\``:
        ``b' !"#$%&\\'()*+,-./0123456789:;<=>?'``.
        :meth:`dictdumper.json.JSON._append_object` writes a key into
        ``'"{item}": '`` raw, so that ``"`` would end the JSON string early --
        still open upstream as JarryShaw/DictDumper#121. The ``escape_key``
        helper of :func:`~pcapkit.dumpkit.common.make_dumper` escapes it with
        :func:`json.dumps` first; without that, this test fails.

        """
        extractor = self.extract(fin=sample_path('test.pcapng'), fout=self.out('report'),
                                 format='json', store=False)
        report = read_json(extractor.output)

        self.assertEqual(extractor.length, 5)
        self.assertEqual(section_counts(report)['Frame'], 5)
        self.assertIn('Decryption Secrets 1', report)


if __name__ == '__main__':
    unittest.main()
