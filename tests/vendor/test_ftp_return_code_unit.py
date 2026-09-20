# -*- coding: utf-8 -*-
"""Regression tests for :mod:`pcapkit.vendor.ftp.return_code`'s empty-row guard.

GitHub issue #518. Fixing the shared ``User-Agent`` got this crawler past the
Wikipedia 403 it had been taking, and it then died one step further on:
:meth:`~pcapkit.vendor.ftp.return_code.ReturnCode.process` read ``line[0]`` on
every row of the registry table, and revision 1354125851 of the article ends that
table with ``<tr class="mw-empty-elt"></tr>`` -- which is what MediaWiki renders a
trailing ``|-`` row separator in the wikitext as. It carries no cells at all, so
``line[0]`` raised ``IndexError: list index out of range`` and took the whole
crawler down. The guard is ``if len(line) < 2: continue``.

That guard is the most fragile line in the #518 change and it had no test: the
suite's other cases all run against the hand-maintained IPX table or a mocked
fetch, so none of them ever sees a cell-less row. This module is that test.

**The fixture is built inline and parsed with the same ``html5lib`` the crawler
uses**, rather than fetched. Two reasons: the unit tier makes no network call, and
the empty ``<tr>`` is partly a *parser* artefact -- what matters is the shape
``bs4`` hands ``process()``, so going through
:meth:`~pcapkit.vendor.ftp.return_code.ReturnCode.request` exercises the real path.
:meth:`test_fixture_really_does_carry_a_cell_less_row` guards against the fixture
silently losing its point, which would otherwise leave every assertion here
passing for the wrong reason.

``process`` is the seam rather than ``count``: this crawler's
:meth:`~pcapkit.vendor.ftp.return_code.ReturnCode.count` ignores its argument and
returns an empty :class:`~collections.Counter`, its real body having been commented
out, so it never touches a row at all.

The suite is unit-tier (see :mod:`tests._tiers`): it reads no capture and makes no
network call.

"""
from __future__ import annotations

import importlib.util
import pathlib
import unittest
from typing import TYPE_CHECKING

from tests._support import purge_modules

if TYPE_CHECKING:
    from typing import Any

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Every distribution importing :mod:`pcapkit.vendor` needs -- see
#: :mod:`tests.vendor.test_user_agent_unit` for why ``requests`` alone is not
#: enough. They ship in the ``vendor`` extra (:file:`pyproject.toml`), not
#: ``test``, and CI installs ``.[test]``.
VENDOR_DEPS = ('requests', 'bs4', 'html5lib')

#: Whether the crawlers are importable at all.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: A cut-down stand-in for the article, carrying the three ``wikitable``s the live
#: page has -- ``process`` indexes the third, ``[2]``, so the two decoys have to be
#: there -- and ending the third with the cell-less row this module is about.
#:
#: The rows mirror the real ones in shape, not just in content: the code sits in a
#: ``<code>`` element inside the ``<td>``, the "``100 Series``" heading row is a
#: real data row whose code is not three characters (and so is dropped by the
#: separate ``len(code) != 3`` test rather than by the guard), and the final row is
#: written exactly as MediaWiki emits it.
REGISTRY_HTML = """\
<html><body>
<table class="wikitable"><tbody>
<tr><th>Range</th><th>Purpose</th></tr>
<tr><td><code>1xx</code></td><td>Positive Preliminary reply.</td></tr>
</tbody></table>
<table class="wikitable"><tbody>
<tr><th>Range</th><th>Purpose</th></tr>
<tr><td><code>x0x</code></td><td>Syntax.</td></tr>
</tbody></table>
<table class="wikitable"><tbody>
<tr><th style="width:100px">Code</th><th>Explanation</th></tr>
<tr><td><code>100 Series</code></td><td><b>The requested action is being initiated.</b></td></tr>
<tr><td><code>110</code></td><td>Restart marker replay.</td></tr>
<tr><td><code>200</code></td><td>Command okay.</td></tr>
<tr class="mw-empty-elt"></tr>
</tbody></table>
</body></html>
"""

#: A row carrying one cell rather than none. ``len(line) < 2`` covers this too,
#: and a guard written as ``if not line`` would not -- ``line[1]`` would then
#: raise instead of ``line[0]``, which is the same defect one column over.
SINGLE_CELL_HTML = REGISTRY_HTML.replace(
    '<tr class="mw-empty-elt"></tr>',
    '<tr><td><code>250</code></td></tr>',
)


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class FTPReturnCodeEmptyRowTests(unittest.TestCase):
    """The trailing ``<tr class="mw-empty-elt">`` the live article ends with."""

    if TYPE_CHECKING:
        vendor_module: 'Any'

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

        import pcapkit.vendor.ftp.return_code as vendor_module

        # The module has to come from this checkout, or the guard under test is
        # not the one being exercised. An environment mismatch, hence a skip.
        resolved = pathlib.Path(vendor_module.__file__).resolve()
        if ROOT not in resolved.parents:
            self.skipTest(f'{vendor_module.__name__} was imported from {resolved}, which is '
                          f'outside {ROOT}; install this checkout with `pip install -e .` to run '
                          f'this suite against it')

        self.vendor_module = vendor_module

    def _vendor(self) -> 'Any':
        """A crawler with the attributes ``__init__`` would have set.

        ``Vendor.__init__`` fetches over the network and *writes* the constant
        file as a side effect of construction, neither of which a unit test has
        any business doing, so the attributes ``process`` needs are set by hand.

        """
        cls = self.vendor_module.ReturnCode
        vendor = cls.__new__(cls)
        vendor.NAME = cls.__name__
        vendor.DOCS = cls.__doc__
        vendor.record = vendor.count(None)
        return vendor

    def test_fixture_really_does_carry_a_cell_less_row(self) -> None:
        # Without this, every other assertion in the module could pass because
        # html5lib quietly dropped the empty <tr> -- i.e. because the fixture had
        # stopped reproducing the defect, not because the guard works.
        import bs4

        vendor = self._vendor()
        soup = vendor.request(REGISTRY_HTML)
        table = soup.find_all('table', class_='wikitable')[2]
        rows = [row for row in table.tbody if isinstance(row, bs4.element.Tag)]

        self.assertEqual(rows[-1].find_all('td'), [],
                         'the last row must carry no <td> at all, or this suite proves nothing')
        self.assertEqual(rows[-1].find_all('th'), [])
        self.assertEqual(rows[-1].get('class'), ['mw-empty-elt'])

    def test_process_skips_the_cell_less_row_instead_of_raising(self) -> None:
        # The regression itself. Before the guard this raised
        # `IndexError: list index out of range` at `line[0]`.
        vendor = self._vendor()
        enum = vendor.process(vendor.request(REGISTRY_HTML))

        self.assertEqual(len(enum), 2, f'expected only the two 3-digit codes, got {enum!r}')
        self.assertIn("CODE_110: 'ReturnCode' = 110, 'Restart marker replay.'", enum[0])
        self.assertIn("CODE_200: 'ReturnCode' = 200, 'Command okay.'", enum[1])

    def test_process_skips_a_row_with_only_one_cell(self) -> None:
        # ``len(line) < 2`` rather than ``not line``: a one-cell row would pass
        # the latter and then raise on ``line[1]``.
        vendor = self._vendor()
        enum = vendor.process(vendor.request(SINGLE_CELL_HTML))

        self.assertEqual(len(enum), 2, f'expected only the two 3-digit codes, got {enum!r}')
        self.assertNotIn('CODE_250', '\n'.join(enum))

    def test_guard_does_not_swallow_legitimate_rows(self) -> None:
        # The other half of the guard's contract: skipping cell-less rows must not
        # cost any row that does carry a code and an explanation.
        vendor = self._vendor()
        enum = vendor.process(vendor.request(REGISTRY_HTML))
        rendered = '\n'.join(enum)

        for code in ('110', '200'):
            with self.subTest(code=code):
                self.assertIn(f'CODE_{code}', rendered)
        # ``100 Series`` is dropped by ``len(code) != 3``, not by the guard.
        self.assertNotIn('100 Series', rendered)

    def test_context_survives_the_cell_less_row(self) -> None:
        # ``process`` is called from ``context``, which is what ``__init__`` writes
        # to disk, so the whole generation path has to survive the row too.
        vendor = self._vendor()
        context = vendor.context(vendor.request(REGISTRY_HTML))

        self.assertIn("CODE_110: 'ReturnCode' = 110", context)
        self.assertIn("CODE_200: 'ReturnCode' = 200", context)
        self.assertIn('class ReturnCode(IntEnum):', context)


if __name__ == '__main__':
    unittest.main()
