# -*- coding: utf-8 -*-
"""Pins the docs build to unique table ids.

GitHub issue #1861: furo wraps each table in a ``table-wrapper`` container and
copies every attribute of the table onto it, ``ids`` included, so a titled
``list-table`` -- which Sphinx gives an id, to number it, as on ``const/reg.html``
-- carries its id on the wrapper as well as on the table. ``DropTableWrapperIds`` in
:file:`docs/source/conf.py` takes the table's ids off the wrapper after furo's
transform has run.

The tests run furo's transform and then this one over a parsed ``list-table``.
They need Sphinx, the pinned ``sphinx-autodoc-typehints`` and furo, and skip without them, but run
no build.

"""

from __future__ import annotations

import importlib.util
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests.project.test_docs_ambiguous_xrefs_1775_unit import HAS_SPHINX, SPHINX_SKIP_REASON, load_conf

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): drives a hook of docs/source/conf.py, which the docs build runs
#: on one interpreter.
__tier__ = 'LATEST'

#: The theme whose transform copies the ids.
HAS_FURO = importlib.util.find_spec('furo') is not None

#: A titled table, as ``AppType.tabulate`` writes them on ``const/reg.html``.
SOURCE = '''\
.. list-table:: Transport protocols

   * - TCP
     - 6
'''


@unittest.skipUnless(HAS_SPHINX, SPHINX_SKIP_REASON)
@unittest.skipUnless(HAS_FURO, 'furo is not installed')
class TableWrapperIdTests(unittest.TestCase):
    """``DropTableWrapperIds`` leaves each id on the table alone."""

    conf = None  # type: Any

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.conf = load_conf()

    def wrapped(self, *extra: 'str') -> 'Any':
        """The table furo has wrapped, with the id Sphinx's numbering gives it."""
        # pylint: disable=import-outside-toplevel
        import furo
        from docutils import nodes
        from docutils.core import publish_doctree

        document = publish_doctree(SOURCE)
        table = next(iter(document.findall(nodes.table)))
        # NB: what Sphinx's ``AutoNumbering`` transform does for a titled table.
        document.note_implicit_target(table)
        furo.WrapTableAndMathInAContainerTransform(document).run()
        wrapper = table.parent
        wrapper['ids'].extend(extra)
        return document, wrapper, table

    def test_furo_copies_the_id(self) -> 'None':
        """Without the fix, the wrapper and the table carry the same id."""
        _, wrapper, table = self.wrapped()
        self.assertIn('table-wrapper', wrapper['classes'])
        self.assertEqual(wrapper['ids'], table['ids'])
        self.assertTrue(table['ids'])

    def test_wrapper_loses_the_table_id(self) -> 'None':
        """The table keeps it, so a reference to the table still lands on it."""
        document, wrapper, table = self.wrapped()
        ids = list(table['ids'])
        self.conf.DropTableWrapperIds(document).run()
        self.assertEqual(wrapper['ids'], [])
        self.assertEqual(table['ids'], ids)

    def test_wrapper_keeps_ids_of_its_own(self) -> 'None':
        """Only the ids the table carries are taken off."""
        document, wrapper, _ = self.wrapped('wrapper-only')
        self.conf.DropTableWrapperIds(document).run()
        self.assertEqual(wrapper['ids'], ['wrapper-only'])

    def test_setup_registers_it_after_furo(self) -> 'None':
        """Post-transforms run by priority, so at furo's or below it would find nothing to fix."""
        import furo  # pylint: disable=import-outside-toplevel
        from sphinx.application import Sphinx  # pylint: disable=import-outside-toplevel
        app = mock.create_autospec(Sphinx, instance=True)
        self.conf.setup(app)
        app.add_post_transform.assert_called_once_with(self.conf.DropTableWrapperIds)
        self.assertGreater(self.conf.DropTableWrapperIds.default_priority,
                           furo.WrapTableAndMathInAContainerTransform.default_priority)
        self.assertEqual(self.conf.DropTableWrapperIds.formats, ('html',))


if __name__ == '__main__':
    unittest.main()
