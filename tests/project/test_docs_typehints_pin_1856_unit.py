# -*- coding: utf-8 -*-
"""Pins :file:`docs/source/conf.py` to the ``sphinx-autodoc-typehints`` it is built with.

GitHub issue #1856: :file:`docs/source/conf.py` imports
``resolve_type_guarded_imports`` from a private module of
``sphinx-autodoc-typehints``, and 3.14.0 replaced that module, ``_resolver``,
with the ``_resolve`` package, so a dependency bump to such a release fails the
docs build at import. The import now follows the installed release.

3.14.0 also stopped binding a module's ``if TYPE_CHECKING:`` names into
the module, so Sphinx's own signature introspection lost them again: the schema
class signatures fell back to a bare ``_VT``, which matched two TypeVars.
``bind_guarded_names`` binds them itself now.

The pin test runs only where the release :file:`docs/requirements.txt` pins is
the one installed, since only there does it check what the docs build imports,
and it says why when it skips. The other tests need Sphinx and
``sphinx-autodoc-typehints`` of any release, and skip without them.

"""

from __future__ import annotations

import importlib.metadata
import inspect
import re
import typing
import unittest
from typing import TYPE_CHECKING

from tests.project.test_docs_ambiguous_xrefs_1775_unit import (HAS_SPHINX, ROOT, connections,
                                                               load_conf)

if TYPE_CHECKING:
    from typing import Any

#: The distribution whose private API :file:`docs/source/conf.py` imports.
DISTRIBUTION = 'sphinx-autodoc-typehints'

#: The requirements file the docs build installs.
REQUIREMENTS = ROOT / 'docs' / 'requirements.txt'


def pinned_release() -> 'str':
    """The release of :data:`DISTRIBUTION` that :data:`REQUIREMENTS` pins."""
    text = REQUIREMENTS.read_text(encoding='utf-8')
    match = re.search(rf'^{re.escape(DISTRIBUTION)}==(\S+)\s*$', text, re.MULTILINE)
    if match is None:
        raise AssertionError(f'{REQUIREMENTS} pins no exact {DISTRIBUTION} release')
    return match.group(1)


class PinnedReleaseTests(unittest.TestCase):
    """The import in :file:`docs/source/conf.py` works with the pinned release."""

    def test_conf_imports_the_function_from_the_pinned_release(self) -> 'None':
        """Loading the file binds the library's ``resolve_type_guarded_imports``.

        A release that moves the function makes the load raise instead, which
        is how the docs build fails too.

        """
        pin = pinned_release()
        try:
            installed = importlib.metadata.version(DISTRIBUTION)
        except importlib.metadata.PackageNotFoundError:
            self.skipTest(f'{DISTRIBUTION} is not installed; docs/requirements.txt pins {pin}')
        if installed != pin:
            self.skipTest(f'{DISTRIBUTION} {installed} is installed, '
                          f'not the {pin} that docs/requirements.txt pins')

        function = load_conf().resolve_type_guarded_imports
        self.assertTrue(callable(function))
        self.assertEqual(function.__name__, 'resolve_type_guarded_imports')
        self.assertEqual(function.__module__.partition('.')[0], 'sphinx_autodoc_typehints')


@unittest.skipUnless(HAS_SPHINX, 'Sphinx and sphinx-autodoc-typehints are not installed')
class GuardedNameTests(unittest.TestCase):
    """``bind_guarded_names`` leaves a module's guarded names where Sphinx reads them."""

    conf = None  # type: Any

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.conf = load_conf()

    def test_schema_constructor_hints_resolve(self) -> 'None':
        """``Schema.__new__`` returns the guarded ``'Self'``, which must resolve.

        Without it :func:`typing.get_type_hints` raises :exc:`NameError` for the
        whole constructor, and Sphinx renders ``*args: '_VT'`` from the string.

        """
        from pcapkit.protocols.schema import schema  # pylint: disable=import-outside-toplevel

        namespace = vars(schema)
        before = set(namespace)
        try:
            self.conf.bind_guarded_names([], schema)
            hints = typing.get_type_hints(schema.Schema.__new__)
        finally:
            for name in set(namespace) - before:
                del namespace[name]
        self.assertIs(hints['args'], schema._VT)  # pylint: disable=protected-access

    def test_setup_binds_after_the_library_clears_its_record(self) -> 'None':
        """From 3.14 the library clears what it recorded on ``env-before-read-docs``.

        It connects its handler at the default priority, so the walk has to
        come after that one to be kept.

        """
        from sphinx.application import Sphinx  # pylint: disable=import-outside-toplevel
        default = inspect.signature(Sphinx.connect).parameters['priority'].default
        wired = [(event, priority) for event, handler, priority in connections(self.conf)
                 if handler is self.conf.bind_type_checking_names]
        self.assertEqual([event for event, _ in wired], ['env-before-read-docs'])
        self.assertGreater(wired[0][1], default)

    def test_attribute_signature_claim_follows_the_release(self) -> 'None':
        """Only a release before 3.14 hands a class-valued attribute a signature."""
        claimed = [event for event, handler, _ in connections(self.conf)
                   if handler is self.conf.claim_attribute_signature]
        expected = ['autodoc-process-signature'] if self.conf.TYPEHINTS_RELEASE < (3, 14) else []
        self.assertEqual(claimed, expected)


if __name__ == '__main__':
    unittest.main()
