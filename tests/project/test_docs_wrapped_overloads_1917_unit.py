# -*- coding: utf-8 -*-
"""Pins the docs build's reading of a decorated method's overloads in its own module.

GitHub issue #1917: ``autodoc_preserve_defaults`` stores the signature on the
``@seekset`` wrapper of
:meth:`~pcapkit.protocols.protocol.ProtocolBase._read_packet`, and
``sphinx-autodoc-typehints`` stops unwrapping at a stated signature, so it read
the overloads in :mod:`pcapkit.corekit.decorators`. The third overload's return,
``'Data_Packet'``, is an alias only :mod:`pcapkit.protocols.protocol` binds, and
rendered as that bare word. ``sign_wrapped_function`` in
:file:`docs/source/conf.py` moves the signature onto the wrapped function.

The tests replay ``autodoc-before-process-signature`` through Sphinx's own
:class:`~sphinx.events.EventManager`, as the #1859 tests do. They need Sphinx and
the pinned ``sphinx-autodoc-typehints``, and skip without them, but run no build.

"""

from __future__ import annotations

import functools
import inspect
import unittest
from typing import TYPE_CHECKING

from tests.project.test_docs_ambiguous_xrefs_1775_unit import (HAS_SPHINX, SPHINX_SKIP_REASON, connections,
                                                               load_conf)
from tests.project.test_docs_class_signature_1860_unit import app_for, emit

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): drives a hook of docs/source/conf.py, which the docs build runs
#: on one interpreter.
__tier__ = 'LATEST'

#: The event the hook answers.
EVENT = 'autodoc-before-process-signature'


@unittest.skipUnless(HAS_SPHINX, SPHINX_SKIP_REASON)
class WrappedOverloadTests(unittest.TestCase):
    """A decorated method's annotations evaluate where they were written."""

    conf = None  # type: Any

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.conf = load_conf()

    def test_read_packet_overload_resolves_its_alias(self) -> 'None':
        """``'Data_Packet'`` evaluates to the class, in the function the library reads."""
        # pylint: disable=import-outside-toplevel
        from sphinx.ext.autodoc.preserve_defaults import DefaultValue, update_defvalue
        from sphinx_autodoc_typehints._objects import callable_target
        from sphinx_autodoc_typehints._resolve.evaluate.expression import resolve_string_annotations

        from pcapkit.protocols.data.protocol import Packet
        from pcapkit.protocols.protocol import ProtocolBase

        wrapper = vars(ProtocolBase)['_read_packet']
        wrapped = inspect.unwrap(wrapper)
        self.assertIsNot(wrapped, wrapper)
        saved = [(function, vars(function).get('__signature__')) for function in (wrapper, wrapped)]
        try:
            emit(self.conf, app_for(self.conf), EVENT, wrapper, False, library=update_defvalue)
            target = callable_target(wrapper)
            self.assertIsNotNone(target)
            hints = resolve_string_annotations(target[0], {'return': 'Data_Packet'}, {})  # type: ignore[index]
            self.assertIs(hints['return'], Packet)
            # NB: and the preserved defaults are still the ones autodoc reads.
            self.assertIsInstance(inspect.signature(wrapper).parameters['length'].default, DefaultValue)
        finally:
            for function, signature in saved:
                vars(function).pop('__signature__', None)
                if signature is not None:
                    function.__signature__ = signature  # type: ignore[attr-defined]

    def test_a_stated_signature_stays(self) -> 'None':
        """A wrapper whose signature differs from the wrapped function's keeps it."""
        def wrapped(first: 'int', second: 'int' = 0) -> 'int':
            return first + second

        @functools.wraps(wrapped)
        def wrapper(*args: 'Any', **kwargs: 'Any') -> 'int':
            return wrapped(*args, **kwargs)

        stated = inspect.Signature([inspect.Parameter('first', inspect.Parameter.POSITIONAL_OR_KEYWORD)])
        wrapper.__signature__ = stated  # type: ignore[attr-defined]
        self.conf.sign_wrapped_function(app_for(self.conf), wrapper, False)
        self.assertIs(vars(wrapper)['__signature__'], stated)
        self.assertNotIn('__signature__', vars(wrapped))

    def test_setup_moves_after_the_aliases_are_named(self) -> 'None':
        """After ``name_aliased_defaults``, which writes its signature to the wrapper."""
        wired = {handler: (event, priority) for event, handler, priority in connections(self.conf)}
        event, priority = wired[self.conf.sign_wrapped_function]
        self.assertEqual(event, EVENT)
        self.assertGreater(priority, wired[self.conf.name_aliased_defaults][1])


if __name__ == '__main__':
    unittest.main()
