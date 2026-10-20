# -*- coding: utf-8 -*-
"""Pins viewcode's module index to modules that have source pages.

GitHub issue #1863: each ``BufferID`` alias is a subscripted ``Tuple``, which is
the builtin :class:`tuple` on every Python the docs build on, so it reports
``__module__ == 'builtins'``. viewcode followed that, and its module index linked
a ``builtins.html`` that is never written. ``follow_builtins_alias`` in
:file:`docs/source/conf.py` keeps viewcode on the module that binds such a name.

The tests call the hook directly and replay the event through Sphinx's own
:class:`~sphinx.events.EventManager`. They need Sphinx and
the pinned ``sphinx-autodoc-typehints``, and skip without them, but run no build.

"""

from __future__ import annotations

import types
import unittest
from typing import TYPE_CHECKING

from tests.project.test_docs_ambiguous_xrefs_1775_unit import (HAS_SPHINX, SPHINX_SKIP_REASON, connections,
                                                               load_conf)
from tests.project.test_docs_class_signature_1860_unit import emit, resolve

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): drives a hook of docs/source/conf.py, which the docs build runs
#: on one interpreter.
__tier__ = 'LATEST'

#: The event the hook answers.
EVENT = 'viewcode-follow-imported'

#: The modules binding a ``BufferID`` alias.
ALIASES = (
    'pcapkit.foundation.reassembly.data.ip',
    'pcapkit.foundation.reassembly.data.tcp',
    'pcapkit.foundation.traceflow.data.tcp',
)


@unittest.skipUnless(HAS_SPHINX, SPHINX_SKIP_REASON)
class ViewcodeBuiltinsTests(unittest.TestCase):
    """``follow_builtins_alias`` answers for an object reporting :mod:`builtins`, and nothing else."""

    conf = None  # type: Any

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.conf = load_conf()

    def follow(self, modname: 'Any', attribute: 'str') -> 'Any':
        """The hook's own answer for ``attribute`` documented in ``modname``."""
        return self.conf.follow_builtins_alias(None, modname, attribute)

    def test_aliases_stay_in_their_module(self) -> 'None':
        """viewcode's own lookup would record :mod:`builtins` for each."""
        from sphinx.ext.viewcode import _get_full_modname  # pylint: disable=import-outside-toplevel
        for modname in ALIASES:
            with self.subTest(modname=modname):
                self.assertEqual(_get_full_modname(modname, 'BufferID'), 'builtins')
                self.assertEqual(self.follow(modname, 'BufferID'), modname)

    def test_other_names_are_left_to_viewcode(self) -> 'None':
        """A class defined there, a name it lacks, and an object with no module."""
        self.assertIsNone(self.follow(ALIASES[0], 'Packet'))
        self.assertIsNone(self.follow(ALIASES[0], 'NoSuchName'))
        self.assertIsNone(self.follow(None, 'BufferID'))

    def test_setup_connects_it(self) -> 'None':
        """Unconnected, viewcode records :mod:`builtins` again."""
        wired = [event for event, handler, _ in connections(self.conf)
                 if handler is self.conf.follow_builtins_alias]
        self.assertEqual(wired, [EVENT])

    def test_build_follows_the_alias_to_its_module(self) -> 'None':
        """Through the event, as viewcode emits it before its own lookup."""
        self.assertEqual(resolve(f'{ALIASES[0]}.BufferID').__module__, 'builtins')
        app = types.SimpleNamespace(pdb=False)
        self.assertEqual(emit(self.conf, app, EVENT, ALIASES[0], 'BufferID'), ALIASES[0])


if __name__ == '__main__':
    unittest.main()
