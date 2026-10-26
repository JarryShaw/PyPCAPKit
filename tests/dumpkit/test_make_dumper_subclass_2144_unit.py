# -*- coding: utf-8 -*-
"""GitHub issue #2144: ``make_dumper``'s ``object_hook`` must not recurse in a subclass.

Without the fix, the fallback branch of the ``object_hook`` that
:func:`~pcapkit.dumpkit.common.make_dumper` builds calls
``super(type(self), self).object_hook(o)``. In a subclass of the class it
returns, ``type(self)`` is the subclass, so the call resolves back to that same
``object_hook`` and recurses until :exc:`RecursionError`. A value no branch
recognises falls through to the output class's own ``object_hook``.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import importlib.util
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Every output class the extractor and the flow tracers hand ``make_dumper``,
#: as ``(module, name)``.
OUTPUTS = (
    ('dictdumper', 'JSON'),
    ('dictdumper', 'PLIST'),
    ('dictdumper', 'Tree'),
    ('pcapkit.dumpkit', 'PCAPIO'),
    ('pcapkit.dumpkit', 'NotImplementedIO'),
)


class Unhandled:
    """A value none of the hook's branches recognises."""


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestMakeDumperSubclass(unittest.TestCase):
    """A subclass of ``make_dumper``'s class falls through to the output class."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def outputs(self) -> 'list[tuple[str, type]]':
        """The output classes of :data:`OUTPUTS`, imported."""
        return [(name, getattr(importlib.import_module(module), name)) for module, name in OUTPUTS]

    @staticmethod
    def hook(cls: 'type', value: 'object') -> 'object':
        """Call ``cls``'s ``object_hook`` on ``value``.

        The instance is made without ``__init__``, which opens the output file,
        since the hook reads no state from it. :class:`dictdumper.dumper.Dumper`'s
        ``__new__`` takes the file name, and ignores it.

        """
        return cls.__new__(cls, 'unused').object_hook(value)

    def test_subclass_falls_through(self) -> None:
        """A direct subclass hands an unhandled value to the output class."""
        from pcapkit.dumpkit.common import make_dumper

        for name, output in self.outputs():
            with self.subTest(output=name):
                class Sub(make_dumper(output)):  # type: ignore[misc,valid-type]
                    pass

                value = Unhandled()
                self.assertIs(self.hook(Sub, value), value)

    def test_nested_subclass_falls_through(self) -> None:
        """So does a subclass of that subclass."""
        from pcapkit.dumpkit.common import make_dumper

        for name, output in self.outputs():
            with self.subTest(output=name):
                class Sub(make_dumper(output)):  # type: ignore[misc,valid-type]
                    pass

                class SubSub(Sub):
                    pass

                value = Unhandled()
                self.assertIs(self.hook(SubSub, value), value)

    def test_subclass_override_reaches_the_hook(self) -> None:
        """A subclass's own ``object_hook`` can defer to the built one."""
        from pcapkit.dumpkit.common import make_dumper

        for name, output in self.outputs():
            with self.subTest(output=name):
                class Sub(make_dumper(output)):  # type: ignore[misc,valid-type]
                    def object_hook(self, o: 'object') -> 'object':
                        return ('sub', super().object_hook(o))

                value = Unhandled()
                self.assertEqual(self.hook(Sub, value), ('sub', value))

    def test_unsubclassed_class_unchanged(self) -> None:
        """The class ``make_dumper`` returns, unsubclassed, still falls through."""
        from pcapkit.dumpkit.common import make_dumper

        for name, output in self.outputs():
            with self.subTest(output=name):
                value = Unhandled()
                self.assertIs(self.hook(make_dumper(output), value), value)


if __name__ == '__main__':
    unittest.main()
