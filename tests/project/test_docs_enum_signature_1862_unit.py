# -*- coding: utf-8 -*-
"""Pins the docs build's enumeration signatures to ``(*values)``.

GitHub issue #1862: for an enumeration with no members, the standard library's
``__signature__`` is the functional-API form, ``(new_class_name, /, names, *,
module=None, ...)``, so
:class:`~pcapkit.const.reg.apptype.apptype.AppType`,
:class:`~pcapkit.const.pcapng.filter_type.FilterType` and
:class:`FrameType.Flags <pcapkit.protocols.schema.application.httpv2.FrameType.Flags>`
render it by default. ``restore_class_signature`` in :file:`docs/source/conf.py` gives
every enumeration the ``(*values)`` an enumeration with members renders.

The tests call the hook directly and replay the event through Sphinx's own
:class:`~sphinx.events.EventManager`. They need Sphinx and
the pinned ``sphinx-autodoc-typehints``, and skip without them, but run no build.

"""

from __future__ import annotations

import enum
import inspect
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests.project.test_docs_ambiguous_xrefs_1775_unit import HAS_SPHINX, SPHINX_SKIP_REASON, load_conf
from tests.project.test_docs_class_signature_1860_unit import EVENT, app_for, emit, resolve

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): drives a hook of docs/source/conf.py, which the docs build runs
#: on one interpreter.
__tier__ = 'LATEST'

#: The memberless enumerations that render the functional-API form by default.
MEMBERLESS = (
    'pcapkit.const.reg.apptype.apptype.AppType',
    'pcapkit.const.pcapng.filter_type.FilterType',
    'pcapkit.protocols.schema.application.httpv2.FrameType.Flags',
)

#: The signature every enumeration gets.
VALUES = '(*values)'


class Empty(enum.Enum):
    """A standard library enumeration with no members."""


class Colour(enum.Enum):
    """A standard library enumeration with members."""

    RED = 1


@unittest.skipUnless(HAS_SPHINX, SPHINX_SKIP_REASON)
class EnumSignatureTests(unittest.TestCase):
    """``restore_class_signature`` gives every enumeration ``(*values)``."""

    conf = None  # type: Any

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.conf = load_conf()

    def setUp(self) -> 'None':
        patcher = mock.patch.object(self.conf, 'typehints_process_signature', return_value=None)
        self.library = patcher.start()
        self.addCleanup(patcher.stop)
        self.app = app_for(self.conf)

    def restore(self, name: 'str', obj: 'Any') -> 'Any':
        """The hook's own answer for the enumeration ``obj``."""
        return self.conf.restore_class_signature(self.app, 'class', name, obj, {}, str(inspect.signature(obj)), None)

    def test_memberless_registries_get_values(self) -> 'None':
        """Each one's own signature is another form, the functional API's from Python 3.12."""
        for name in MEMBERLESS:
            obj = resolve(name)
            with self.subTest(name=name):
                self.assertFalse(obj.__members__)
                self.assertNotEqual(str(inspect.signature(obj)), VALUES)
                self.assertEqual(self.restore(name, obj), (VALUES, None))

    def test_any_enumeration_gets_values(self) -> 'None':
        """An :mod:`aenum` registry with members, and standard library ones with and without."""
        for obj in (resolve('pcapkit.const.arp.hardware.Hardware'), Empty, Colour):
            with self.subTest(obj=obj):
                self.assertEqual(self.restore(obj.__qualname__, obj), (VALUES, None))

    def test_build_gives_values(self) -> 'None':
        """Through the event, the library's functional-API answer is replaced."""
        name = MEMBERLESS[0]
        obj = resolve(name)
        written = str(inspect.signature(obj))
        result = emit(self.conf, self.app, EVENT, 'class', name, obj, {}, written, None,
                      library=lambda *args: (written, None))
        self.assertEqual(result, (VALUES, None))


if __name__ == '__main__':
    unittest.main()
