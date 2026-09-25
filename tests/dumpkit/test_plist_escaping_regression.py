# -*- coding: utf-8 -*-
"""Reports of a capture whose keys carry XML special characters.

:file:`tests/dumpkit/test_common_unit.py` pins what
:meth:`~pcapkit.dumpkit.common.make_dumper.DictDumper.object_hook` returns. This
module pins the only thing that actually matters about it -- that the file on
disk parses -- against the fixture that used to prove it did not.

:file:`examples/captures/test.pcapng` carries a decryption secrets block whose
TLS key log entries are keyed by a raw :class:`bytes` client random
(:meth:`~pcapkit.protocols.schema.misc.pcapng.TLSKeyLog.post_process`), so the
report's key is a ``bytes`` repr holding ``&``, ``<`` and ``>``. GitHub issue
#772 and JarryShaw/DictDumper#125 are the two halves of that: ``dictdumper``
interpolates a mapping key into its markup without escaping it, and until the
in-repo half landed the ``plist`` and ``xml`` reports of this fixture stopped
parsing at line 1517 of 1958 with ``not well-formed (invalid token)``.

This module is fixture-tier by its ``_regression.py`` name -- ``test.pcapng`` is
generated rather than committed, so a unit-tier module may not read it (see
:mod:`tests._tiers`).

"""
from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest
import xml.etree.ElementTree as ET

from tests._support import close_extractor, purge_modules, sample_path

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: The fixture's client random as the writer spells it, i.e. the ``bytes`` repr
#: of every character from ``0x20`` to ``0x3F``.
RAW_BYTES_KEY = """b' !"#$%&\\'()*+,-./0123456789:;<=>?'"""
#: The same key with the three XML entities escaped, and nothing else touched --
#: both quotes stay as they are, being legal in an XML text node.
ESCAPED_BYTES_KEY = """b' !"#$%&amp;\\'()*+,-./0123456789:;&lt;=&gt;?'"""
#: The first of the three undeclared PCAP-NG option types this fixture carries,
#: as :func:`~pcapkit.dumpkit.common.render_enum` spells it and the writer has to
#: escape it. It arrives as a mapping *key*, which is what makes it the
#: double-escape witness: ``&amp;lt;`` here would mean the escaping ran twice.
ESCAPED_PSEUDO_MEMBER_KEY = '<key>OptionType::&lt;unassigned&gt; [opt_unknown [2]]</key>'


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PlistKeyEscapingTests(unittest.TestCase):
    """The reports of :file:`test.pcapng`, one per output format."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])
        tmpdir = tempfile.TemporaryDirectory(prefix='pcapkit-772-')
        self.addCleanup(tmpdir.cleanup)
        self.tmp_path = pathlib.Path(tmpdir.name)

    def report(self, capture: 'str', fmt: 'str') -> 'pathlib.Path':
        """Extract ``capture`` into a report of ``fmt`` and return its path."""
        from pcapkit.interface import extract

        output = self.tmp_path / f'{capture}.{fmt}'
        extractor = extract(fin=sample_path(capture), fout=str(output), format=fmt,
                            store=False, extension=False)
        self.addCleanup(close_extractor, extractor)

        self.assertEqual(extractor.length, 5)
        return output

    def test_the_plist_report_of_a_bytes_keyed_mapping_parses(self) -> None:
        """The regression itself: the document has to be well-formed XML.

        :func:`plistlib.load` cannot stand in for the parser here --
        ``dictdumper`` writes a ``<date>`` with fractional seconds, which it
        rejects for reasons that have nothing to do with #772 (see
        ``PlistRoundTripTests`` in
        :file:`tests/integration/test_output_formats.py`) -- so this asserts
        well-formedness with :mod:`xml.etree.ElementTree` and then reads the key
        back out of the tree rather than out of the text, which is the part a
        string comparison would not have caught.

        """
        report = self.report('test.pcapng', 'plist')

        keys = [element.text for element in ET.parse(report).iter('key')]
        self.assertIn(ESCAPED_BYTES_KEY, report.read_text(encoding='utf-8'))
        # ElementTree resolves the entities, so the key comes back as the octets
        # the fixture holds: escaping is a transport detail, not a rename.
        self.assertIn(RAW_BYTES_KEY, keys)

    def test_the_xml_report_is_the_same_writer_and_parses_too(self) -> None:
        """``'xml'`` and ``'plist'`` both map to ``dictdumper.PLIST``.

        ``Extractor.__output__`` gives the two formats the same writer, so
        neither can be fixed without the other -- but that is a mapping a future
        change could redirect, and the format a user asked for by name is the one
        whose report has to parse.

        """
        report = self.report('test.pcapng', 'xml')

        ET.parse(report)
        self.assertIn(ESCAPED_BYTES_KEY, report.read_text(encoding='utf-8'))

    def test_the_json_and_tree_reports_keep_the_key_verbatim(self) -> None:
        """Nothing is escaped for the formats that take the characters literally.

        ``json``, ``tree`` and ``text`` accept ``&``, ``<`` and ``>`` as
        themselves, so escaping them there would corrupt every report in those
        formats. The ``json`` report of this fixture is separately unparseable --
        ``dictdumper`` writes a key as ``'"{item}": '`` and this one's repr holds
        a quote -- and that is deliberately still true here: it is
        JarryShaw/DictDumper#125's half, not this one's.

        """
        for fmt in ('json', 'tree', 'text'):
            with self.subTest(format=fmt):
                text = self.report('test.pcapng', fmt).read_text(encoding='utf-8')

                self.assertIn(RAW_BYTES_KEY, text)
                self.assertNotIn('&amp;', text)
                self.assertNotIn('&lt;', text)

    def test_the_plist_report_escapes_a_pseudo_member_key_exactly_once(self) -> None:
        """An already-escaped rendering must not be escaped a second time.

        This fixture carries three undeclared PCAP-NG option types, each of which
        reaches the writer as a mapping key rendered
        ``OptionType::<unassigned> [opt_unknown [N]]`` -- #771's case, and now the
        same escaping as every other key rather than a special case beside it.
        ``&amp;lt;`` anywhere in the report is what a second pass over an
        already-escaped key would leave behind, so it is what this looks for.

        """
        text = self.report('test.pcapng', 'plist').read_text(encoding='utf-8')

        self.assertIn(ESCAPED_PSEUDO_MEMBER_KEY, text)
        self.assertNotIn('&amp;lt;', text)
        self.assertNotIn('&amp;gt;', text)
        self.assertNotIn('&amp;amp;', text)
        # Nothing was left raw either, which is the other way to pass the line above.
        self.assertNotIn('<unassigned>', text)


if __name__ == '__main__':
    unittest.main()
