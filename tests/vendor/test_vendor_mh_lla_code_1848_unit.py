# -*- coding: utf-8 -*-
"""The ``LLACode`` crawler renders the committed const module, renames included.

GitHub issue #1848. :mod:`pcapkit.vendor.mh.lla_code` hand-writes its table, so
its generator runs offline: :meth:`~pcapkit.vendor.mh.lla_code.LLACode.request`
returns :data:`~pcapkit.vendor.mh.lla_code.DATA`. This suite drives the
crawler's :meth:`count`, :meth:`process` and :meth:`context` on that table,
without :meth:`~pcapkit.vendor.default.Vendor.__init__`'s file write, and
checks that the result is the committed :mod:`pcapkit.const.mh.lla_code`
byte for byte, so the template and the module cannot drift apart.

"""
from __future__ import annotations

import importlib.util
import pathlib
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): renders a constant module from recorded data and compares it
#: with the committed file, which the vendor scripts regenerate on one interpreter.
__tier__ = 'LATEST'

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The committed module the crawler generates.
CONST = ROOT / 'pcapkit' / 'const' / 'mh' / 'lla_code.py'

#: Every distribution importing :mod:`pcapkit.vendor` needs, as
#: :file:`tests/vendor/test_user_agent_unit.py` explains.
VENDOR_DEPS = ('requests', 'bs4', 'html5lib')

#: Whether the crawlers are importable at all.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)


def _normalize(context: 'str') -> 'str':
    """Apply the whitespace normalisation :meth:`Vendor.__init__` writes with.

    Args:
        context: Return value of :meth:`~pcapkit.vendor.default.Vendor.context`.

    Returns:
        The text as the generator would have written it to disk.

    """
    lines = []  # type: list[str]
    for line in context.splitlines():
        if line:
            if line.strip():
                lines.append(line.rstrip())
        else:
            lines.append(line)
    return '\n'.join(lines) + '\n'


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class LLACodeVendorTests(unittest.TestCase):
    """The hand-written table and its template, rendered without a write."""

    if TYPE_CHECKING:
        vendor_module: 'Any'

    def setUp(self) -> 'None':
        reimport_once_per_class(self)

        import pcapkit.vendor.mh.lla_code as vendor_module

        resolved = pathlib.Path(vendor_module.__file__).resolve()
        if ROOT not in resolved.parents:
            self.skipTest(f'{vendor_module.__name__} was imported from {resolved}, which is '
                          f'outside {ROOT}; install this checkout with `pip install -e .` to '
                          f'run this suite against it')

        self.vendor_module = vendor_module

    def _vendor(self) -> 'tuple[Any, dict[int, str]]':
        """A crawler with the attributes ``__init__`` sets, but none of its I/O."""
        cls = self.vendor_module.LLACode
        vendor = cls.__new__(cls)
        vendor.NAME = cls.__name__
        vendor.DOCS = cls.__doc__
        data = vendor.request()
        vendor.record = vendor.count(data)
        return vendor, data

    def test_the_table_carries_the_rfc_names(self) -> 'None':
        vendor, data = self._vendor()
        self.assertEqual(data[0], 'Wildcard')
        self.assertEqual(data[2], 'MN')

        enum, _ = vendor.process(data)
        members = [entry.strip() for entry in enum]
        self.assertIn('Wildcard = 0', members)
        self.assertIn('MN = 2', members)
        self.assertNotIn('Wilcard = 0', members)
        self.assertNotIn('MH = 2', members)

    def test_context_renders_no_version_directive(self) -> 'None':
        # Generated modules carry no version directives: the scripts
        # regenerate them, so the rename is noted on the docs page instead.
        vendor, data = self._vendor()
        context = vendor.context(data)
        self.assertIn('    """[LLACode] Link-Layer Address (LLA) Option Code"""\n', context)
        for directive in ('.. versionadded::', '.. versionchanged::', '.. versionremoved::'):
            with self.subTest(directive=directive):
                self.assertNotIn(directive, context)

    def test_context_matches_the_committed_const_file_byte_for_byte(self) -> 'None':
        vendor, data = self._vendor()
        rendered = _normalize(vendor.context(data))
        self.assertEqual(rendered, CONST.read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
