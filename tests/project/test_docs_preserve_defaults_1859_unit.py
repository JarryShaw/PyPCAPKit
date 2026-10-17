# -*- coding: utf-8 -*-
"""Pins the docs build's signature defaults to their source text.

GitHub issue #1859: autodoc renders a default's ``repr()`` unless
``autodoc_preserve_defaults`` is on, so every ``byteorder=sys.byteorder`` showed
the build host's ``'little'``, and the ``corekit.fields`` pages showed
``default=<pcapkit.corekit.sentinels.NoValueType object>`` and
``callback=<function NumberField.<lambda>>``. :file:`docs/source/conf.py` turns
the setting on. Source text then exposed the private aliases the protocol
modules import their registries under, ``next=Enum_TransType.UDP``, so
``name_aliased_defaults`` names each such class by its own name.

The tests replay ``autodoc-before-process-signature`` through Sphinx's own
:class:`~sphinx.events.EventManager`, with Sphinx's
:func:`~sphinx.ext.autodoc.preserve_defaults.update_defvalue`, which acts only
when the setting is on, and render the signature as autodoc does. They need
Sphinx and the pinned ``sphinx-autodoc-typehints``, and skip without them, but run no build.

"""

from __future__ import annotations

import inspect
import unittest
from typing import TYPE_CHECKING

from tests.project.test_docs_ambiguous_xrefs_1775_unit import (HAS_SPHINX, SPHINX_SKIP_REASON, connections,
                                                               load_conf)
from tests.project.test_docs_class_signature_1860_unit import app_for, emit

if TYPE_CHECKING:
    from typing import Any, Callable

#: The event the alias hook answers.
EVENT = 'autodoc-before-process-signature'


@unittest.skipUnless(HAS_SPHINX, SPHINX_SKIP_REASON)
class PreserveDefaultsTests(unittest.TestCase):
    """With the build's settings and hooks, defaults render as written, aliases named."""

    conf = None  # type: Any

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.conf = load_conf()

    def render(self, function: 'Callable[..., Any]') -> 'str':
        """The signature autodoc renders for ``function`` in the build."""
        # pylint: disable=import-outside-toplevel
        from sphinx.ext.autodoc.preserve_defaults import update_defvalue
        from sphinx.util.inspect import stringify_signature

        had = '__signature__' in vars(function)
        try:
            emit(self.conf, app_for(self.conf), EVENT, function, False, library=update_defvalue)
            return stringify_signature(inspect.signature(function), show_annotation=False)
        finally:
            if not had:
                vars(function).pop('__signature__', None)

    def test_byteorder_renders_as_written(self) -> 'None':
        """Not as the byte order of whichever host built the docs; a module alias stays."""
        from pcapkit.interface.core import trace  # pylint: disable=import-outside-toplevel
        rendered = self.render(trace)
        self.assertIn('byteorder=sys.byteorder', rendered)
        self.assertNotIn("'little'", rendered)
        self.assertNotIn("'big'", rendered)

    def test_sentinel_and_lambda_render_as_written(self) -> 'None':
        """``NO_VALUE`` and the lambda, rather than their ``repr()``."""
        from pcapkit.corekit.fields.numbers import NumberField  # pylint: disable=import-outside-toplevel
        rendered = self.render(NumberField.__init__)
        self.assertIn('default=NO_VALUE', rendered)
        self.assertIn('callback=lambda', rendered)
        self.assertNotIn('<', rendered)

    def test_aliased_registries_are_named_by_their_class(self) -> 'None':
        """``Enum_TransType`` is the module's private name for ``TransType``."""
        # pylint: disable=import-outside-toplevel
        from pcapkit.protocols.application.httpv2 import HTTP
        from pcapkit.protocols.internet.ah import AH
        from pcapkit.protocols.misc.pcapng import PCAPNG

        for function, expected in ((AH.make, 'next=TransType.UDP'), (HTTP.make, 'type=Frame.DATA'),
                                   (PCAPNG._make_option_if_filter,  # pylint: disable=protected-access
                                    'filter=FilterType(0)')):
            with self.subTest(function=function.__qualname__):
                rendered = self.render(function)
                self.assertIn(expected, rendered)
                self.assertNotIn('Enum_', rendered)

    def test_setup_renames_after_the_defaults_are_preserved(self) -> 'None':
        """At or below the legacy ``update_defvalue``'s priority, nothing would be preserved yet."""
        from sphinx.application import Sphinx  # pylint: disable=import-outside-toplevel
        default = inspect.signature(Sphinx.connect).parameters['priority'].default
        wired = [(event, priority) for event, handler, priority in connections(self.conf)
                 if handler is self.conf.name_aliased_defaults]
        self.assertEqual([event for event, _ in wired], [EVENT])
        self.assertGreater(wired[0][1], default)


if __name__ == '__main__':
    unittest.main()
