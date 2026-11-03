# -*- coding: utf-8 -*-
"""Pins ``protocol.rst``'s entries for the shared value helpers (#2676).

The helpers the protocols read and make their field values with -- among them
``_make_uint``, ``_make_sint``, ``_read_sint``, ``_uint_size`` and
``_make_octets`` -- are contract for a protocol's author, so each has an
``automethod`` on the ``Protocol`` autoclass and a place in the ``ProtocolBase``
method group, linked to that entry. The page's "Value Helpers" section names
``pad_length`` beside them, by name only, as its module may move.

Each helper is checked as a method of ``ProtocolBase`` with a docstring, read
from the source rather than imported, so this module runs as a project pin.

"""

from __future__ import annotations

import ast
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The page that documents the helpers.
PAGE = ROOT / 'docs' / 'source' / 'pcapkit' / 'protocols' / 'protocol.rst'

#: The module that defines them.
SOURCE = ROOT / 'pcapkit' / 'protocols' / 'protocol.py'

#: The value helpers, in the page's order.
HELPERS = ('_read_unpack', '_read_octets', '_read_uint', '_read_sint', '_read_vector', '_read_whole_vector',
           '_read_uints', '_make_pack', '_make_octets', '_fill_short_read', '_make_uint', '_make_sint',
           '_uint_size', '_make_vector', '_make_uints')


class ValueHelperEntryTests(unittest.TestCase):
    """Each helper has an entry on ``Protocol`` and a place in the ``ProtocolBase`` group."""

    text = PAGE.read_text(encoding='utf-8')

    def test_helpers_are_documented(self) -> None:
        tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'ProtocolBase')
        methods = {node.name: node for node in cls.body if isinstance(node, ast.FunctionDef)}
        protocol, base = self.text.split('.. autoclass:: pcapkit.protocols.protocol.ProtocolBase')
        group = re.search(r'\.\. py:method:: id\n((?: {18}\w+\n)+)', base)
        assert group is not None
        for name in HELPERS:
            with self.subTest(helper=name):
                self.assertTrue(ast.get_docstring(methods[name]))
                self.assertIn(f'   .. automethod:: {name}\n', protocol)
                self.assertIn(f' {name}\n', group.group(1))
                self.assertIn(f':meth:`~Protocol.{name}`', base)
        self.assertIn('pad_length`', protocol)


if __name__ == '__main__':
    unittest.main()
