# -*- coding: utf-8 -*-
"""JSON reports of a mapping whose keys need escaping.

:class:`dictdumper.json.JSON` escapes every string *value* it writes, but
interpolates a mapping key into ``'"{item}": '`` raw, so a key holding a ``"``
or a ``\\`` closes the JSON string early and the report stops parsing (GitHub
issue #1152). :func:`~pcapkit.dumpkit.common.make_dumper` escapes the keys on
the writer's behalf; this module pins that the file on disk parses and that the
key reads back as the writer's own rendering of it.

"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest

HAS_RUNTIME = importlib.util.find_spec('dictdumper') is not None

#: Keys that each break an unescaped ``'"{item}": '``, or would if escaped wrongly.
AWKWARD_KEYS = (
    b' !"#$%&\'()*+,-./0123456789:;<=>?',  # test.pcapng's client random
    'quote " and backslash \\',
    'tab\tnewline\ncontrol\x01',
    'non-ascii é中',
)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class JSONKeyEscapingTests(unittest.TestCase):
    """Dump one mapping per container type and read the report back."""

    def setUp(self) -> None:
        tmpdir = tempfile.TemporaryDirectory(prefix='pcapkit-1152-')
        self.addCleanup(tmpdir.cleanup)
        self.tmp_path = pathlib.Path(tmpdir.name)

    def dump(self, fmt: 'str', value: 'object') -> 'pathlib.Path':
        """Write ``{'entries': value}`` through the customised ``fmt`` writer."""
        import dictdumper

        from pcapkit.dumpkit.common import make_dumper

        output = self.tmp_path / f'report.{fmt}'
        writer = make_dumper({'json': dictdumper.JSON, 'tree': dictdumper.Tree}[fmt])
        writer(str(output))({'entries': value}, name='Frame 1')
        return output

    def test_a_multidict_with_awkward_keys_parses(self) -> None:
        """The #1152 path: ``TLSKeyLog`` keys an ``OrderedMultiDict`` by bytes."""
        from pcapkit.corekit.multidict import OrderedMultiDict

        entries = OrderedMultiDict()  # type: OrderedMultiDict[object, int]
        for index, key in enumerate(AWKWARD_KEYS):
            entries.add(key, index)

        report = json.loads(self.dump('json', entries).read_text(encoding='utf-8'))

        self.assertEqual(report['Frame 1']['entries'],
                         {format(key, ''): [index] for index, key in enumerate(AWKWARD_KEYS)})

    def test_a_plain_dict_with_awkward_keys_parses(self) -> None:
        """A plain :class:`dict` goes through a separate branch of the hook."""
        entries = {key: index for index, key in enumerate(AWKWARD_KEYS)}

        report = json.loads(self.dump('json', {'nested': entries}).read_text(encoding='utf-8'))

        self.assertEqual(report['Frame 1']['entries']['nested'],
                         {format(key, ''): index for index, key in enumerate(AWKWARD_KEYS)})

    def test_the_tree_report_keeps_the_key_verbatim(self) -> None:
        """``tree`` takes the characters literally, so nothing is escaped there."""
        key = 'quote " and backslash \\'

        text = self.dump('tree', {key: 0}).read_text(encoding='utf-8')

        self.assertIn(key, text)
        self.assertNotIn('\\"', text)


if __name__ == '__main__':
    unittest.main()
