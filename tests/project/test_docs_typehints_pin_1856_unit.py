# -*- coding: utf-8 -*-
"""Pins :file:`docs/source/conf.py` to the ``sphinx-autodoc-typehints`` it is built with.

GitHub issue #1856: :file:`docs/source/conf.py` imports
``resolve_type_guarded_imports`` from a private module of
``sphinx-autodoc-typehints``, and 3.14.0 replaced that module, ``_resolver``,
with the ``_resolve`` package, so a dependency bump to such a release failed the
docs build at import.

The file is written against a pinned release rather than branching on the
installed one. :file:`docs/requirements.txt` pins it for the docs build, and the
``docs`` extra in :file:`pyproject.toml` pins the same release, so ``pip install
-e '.[docs]'`` installs what the build runs. The pin test is textual and runs
everywhere.

3.14.0 also stopped binding a module's ``if TYPE_CHECKING:`` names into the
module, so Sphinx's own signature introspection lost them again: the schema
class signatures fell back to a bare ``_VT``, which matched another module's
TypeVar as well. ``bind_guarded_names`` binds them itself.

The tests that load :file:`conf.py` need Sphinx and the pinned release, and skip
without them, saying which.

"""

from __future__ import annotations

import inspect
import typing
import unittest
from typing import TYPE_CHECKING

from tests._dependency_gates import declared_requirements, requirement_key
from tests.project.test_docs_ambiguous_xrefs_1775_unit import (HAS_SPHINX, SPHINX_SKIP_REASON, TYPEHINTS,
                                                               connections, load_conf, pinned_release)

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): checks docs/source/conf.py against the docs build's pins, which
#: run on one interpreter.
__tier__ = 'LATEST'


class PinAgreementTests(unittest.TestCase):
    """The ``docs`` extra installs the release :file:`docs/requirements.txt` pins."""

    def test_docs_extra_pins_the_requirements_release(self) -> 'None':
        """Every extra naming the distribution pins exactly that release.

        Unpinned, ``pip install -e '.[docs]'`` resolves the newest release, which
        :file:`conf.py` is not written against.

        """
        name = requirement_key(TYPEHINTS).name
        found = {extra: [requirement.text.replace(' ', '') for requirement in requirements
                         if requirement.name == name]
                 for extra, requirements in declared_requirements().items()}
        self.assertEqual({extra: texts for extra, texts in found.items() if texts},
                         {'docs': [f'{TYPEHINTS}=={pinned_release()}']})


@unittest.skipUnless(HAS_SPHINX, SPHINX_SKIP_REASON)
class PinnedReleaseTests(unittest.TestCase):
    """The import in :file:`docs/source/conf.py` works with the pinned release."""

    def test_conf_imports_the_function_from_the_pinned_release(self) -> 'None':
        """Loading the file binds the library's ``resolve_type_guarded_imports``.

        A release that moves the function makes the load raise instead, which
        is how the docs build fails too.

        """
        function = load_conf().resolve_type_guarded_imports
        self.assertTrue(callable(function))
        self.assertEqual(function.__name__, 'resolve_type_guarded_imports')
        self.assertEqual(function.__module__.partition('.')[0], 'sphinx_autodoc_typehints')


@unittest.skipUnless(HAS_SPHINX, SPHINX_SKIP_REASON)
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
        """The library clears what it recorded on ``env-before-read-docs``.

        It connects its handler at the default priority, so the walk has to
        come after that one to be kept.

        """
        from sphinx.application import Sphinx  # pylint: disable=import-outside-toplevel
        default = inspect.signature(Sphinx.connect).parameters['priority'].default
        wired = [(event, priority) for event, handler, priority in connections(self.conf)
                 if handler is self.conf.bind_type_checking_names]
        self.assertEqual([event for event, _ in wired], ['env-before-read-docs'])
        self.assertGreater(wired[0][1], default)


if __name__ == '__main__':
    unittest.main()
