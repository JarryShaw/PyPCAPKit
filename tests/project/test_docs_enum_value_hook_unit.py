# -*- coding: utf-8 -*-
"""Pins the docs build's skip of the enum machinery's ``_generate_next_value_``.

The enum metaclass copies ``_generate_next_value_`` into the namespace of every
enumeration it creates, so ``:members:`` lists it on every enum page. An
``:exclude-members:`` entry cannot take it out again: autodoc lets the
``autodoc-skip-member`` event overrule that option, and napoleon's handler
answers ``False`` -- include -- for a private member that has a docstring.
``skip_enum_value_hook`` in :file:`docs/source/conf.py` answers first.

The tests call the hook directly, and replay the event through Sphinx's own
:class:`~sphinx.events.EventManager` with napoleon's real handler, in the order
the build connects them. They need Sphinx and the pinned sphinx-autodoc-typehints,
and skip without them, but run no build.

"""

from __future__ import annotations

import enum
import inspect
import types
import unittest
from typing import TYPE_CHECKING

from tests.project.test_docs_ambiguous_xrefs_1775_unit import (HAS_SPHINX, SPHINX_SKIP_REASON, connections,
                                                               load_conf)

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): drives a hook of docs/source/conf.py, which the docs build runs
#: on one interpreter.
__tier__ = 'LATEST'

#: The member the hook skips.
HOOK = '_generate_next_value_'

#: The event it answers.
EVENT = 'autodoc-skip-member'


class Colour(enum.Enum):
    """A standard library enumeration, whose hook is :mod:`enum`'s."""

    RED = 1


@unittest.skipUnless(HAS_SPHINX, SPHINX_SKIP_REASON)
class EnumValueHookTests(unittest.TestCase):
    """``skip_enum_value_hook`` skips the inherited hook, and nothing else."""

    conf = None  # type: Any

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.conf = load_conf()

    def setUp(self) -> 'None':
        # NB: an ``aenum`` ``StrEnum`` with a ``_missing_`` of its own. Its hook is
        # ``aenum``'s ``StrEnum._generate_next_value_``, which napoleon includes
        # because that class owns it; an ``aenum`` ``IntEnum``'s hook is a
        # module-level function, which napoleon leaves alone, so a registry of
        # that kind would pass the build test below with or without the fix.
        from pcapkit.const.ftp.command import Command  # pylint: disable=import-outside-toplevel
        self.registry = Command

    def skip(self, name: 'str', obj: 'Any') -> 'Any':
        """The hook's own answer for ``name``, as autodoc would ask it."""
        return self.conf.skip_enum_value_hook(None, 'class', name, obj, False, {})

    def emit(self, name: 'str', obj: 'Any') -> 'Any':
        """What the build's ``autodoc-skip-member`` handlers decide for ``name``.

        Napoleon's ``setup`` connects its handler with no priority, and runs
        before :file:`conf.py`'s, so it is connected first, at
        :meth:`Sphinx.connect <sphinx.application.Sphinx.connect>`'s default;
        :file:`conf.py`'s handlers follow with the priorities its ``setup``
        gives them. ``skip`` is :obj:`True`, as autodoc passes it for a private
        member that ``private-members`` does not ask for.

        """
        # pylint: disable=import-outside-toplevel
        from sphinx.application import Sphinx
        from sphinx.events import EventManager
        from sphinx.ext import napoleon

        settings = {key: getattr(self.conf, key) for key in dir(self.conf) if key.startswith('napoleon_')}
        app = types.SimpleNamespace(pdb=False, config=napoleon.Config(**settings))
        events = EventManager(app)  # type: ignore[arg-type]
        events.add(EVENT)
        default = inspect.signature(Sphinx.connect).parameters['priority'].default
        events.connect(EVENT, napoleon._skip_member, default)  # pylint: disable=protected-access
        for event, handler, priority in connections(self.conf):
            if event == EVENT:
                events.connect(event, handler, priority)
        return events.emit_firstresult(EVENT, 'class', name, obj, True, {})

    def test_stdlib_hook_is_skipped(self) -> 'None':
        """A standard library enumeration's hook is :mod:`enum`'s, not pcapkit's."""
        self.assertIs(self.skip(HOOK, getattr(Colour, HOOK)), True)

    def test_aenum_hook_is_skipped(self) -> 'None':
        """A ``pcapkit.const`` registry's hook is :mod:`aenum`'s."""
        obj = getattr(self.registry, HOOK)
        self.assertEqual(obj.__module__.partition('.')[0], 'aenum')
        self.assertIs(self.skip(HOOK, obj), True)

    def test_other_members_are_left_to_the_other_handlers(self) -> 'None':
        """``_missing_`` implements a registry's lookup contract and stays documented."""
        for name in ('_missing_', 'get'):
            with self.subTest(name=name):
                self.assertIsNone(self.skip(name, getattr(self.registry, name)))

    def test_pcapkit_override_is_kept(self) -> 'None':
        """A ``_generate_next_value_`` that pcapkit defines itself is documented."""
        def override(name: 'str', start: 'int', count: 'int', last_values: 'list[Any]') -> 'Any':
            return count
        override.__module__ = 'pcapkit.x'
        self.assertIsNone(self.skip(HOOK, override))

    def test_setup_connects_it_ahead_of_napoleon(self) -> 'None':
        """At napoleon's priority the hook would run after it, and napoleon's ``False`` wins."""
        from sphinx.application import Sphinx  # pylint: disable=import-outside-toplevel
        default = inspect.signature(Sphinx.connect).parameters['priority'].default
        wired = [(event, priority) for event, handler, priority in connections(self.conf)
                 if handler is self.conf.skip_enum_value_hook]
        self.assertEqual([event for event, _ in wired], [EVENT])
        self.assertLess(wired[0][1], default)

    def test_build_skips_the_hook(self) -> 'None':
        """Through the event, the hook is skipped on either kind of enumeration."""
        for owner in (Colour, self.registry):
            with self.subTest(owner=owner.__name__):
                self.assertIs(self.emit(HOOK, getattr(owner, HOOK)), True)

    def test_build_still_documents_missing(self) -> 'None':
        """Through the event, a registry's own ``_missing_`` is still included."""
        self.assertIs(self.emit('_missing_', getattr(self.registry, '_missing_')), False)


if __name__ == '__main__':
    unittest.main()
