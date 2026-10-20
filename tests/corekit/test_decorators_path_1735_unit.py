# -*- coding: utf-8 -*-
"""The decorators live at :mod:`pcapkit.corekit.decorators`, and only there.

GitHub issue #1735, applying #1712's placement rule. ``seekset``, ``beholder``
and ``prepare`` act on a protocol's file and the schema it unpacks, and
``beholder`` falls back to protocol classes, so they moved from
``pcapkit.utilities.decorators`` to :mod:`pcapkit.corekit.decorators`. Per the
ruling on #1715 nothing is left at the old path, and :mod:`pcapkit.utilities`
no longer exports the three names. This pins both halves of that: the old path
and the old exports are gone, and every importer uses the new module.

"""
import importlib
import importlib.util
import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): checks where the decorators live and that their old path is
#: gone, a question about the tree.
__tier__ = 'LATEST'

#: Where the decorators live.
NEW_PATH = 'pcapkit.corekit.decorators'

#: Where they lived before #1735; removed, not re-exported.
OLD_PATH = 'pcapkit.utilities.decorators'

#: The three decorators.
NAMES = ('seekset', 'beholder', 'prepare')

#: ``(importing module, decorator it imports)``, for every module that does.
IMPORTERS = (
    ('pcapkit.protocols.protocol', 'seekset'),
    ('pcapkit.protocols.protocol', 'beholder'),
    ('pcapkit.protocols.internet.internet', 'beholder'),
    ('pcapkit.protocols.internet.ipv6', 'beholder'),
    ('pcapkit.protocols.schema.schema', 'prepare'),
)


class DecoratorsPathTests(unittest.TestCase):
    """Pin the move of the decorators into :mod:`pcapkit.corekit`."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_the_old_module_path_no_longer_imports(self) -> None:
        with self.assertRaises(ModuleNotFoundError) as ctx:
            importlib.import_module(OLD_PATH)
        self.assertEqual(ctx.exception.name, OLD_PATH)
        self.assertIsNone(importlib.util.find_spec(OLD_PATH))

    def test_utilities_no_longer_exports_the_decorators(self) -> None:
        utilities = importlib.import_module('pcapkit.utilities')
        self.assertFalse(hasattr(utilities, 'decorators'))
        for name in NAMES:
            with self.subTest(name=name):
                self.assertNotIn(name, utilities.__all__)
                self.assertFalse(hasattr(utilities, name))

    def test_the_new_module_holds_the_decorators(self) -> None:
        decorators = importlib.import_module(NEW_PATH)
        self.assertEqual(decorators.__all__, list(NAMES))
        self.assertEqual(decorators.logger.name, NEW_PATH)
        for name in NAMES:
            with self.subTest(name=name):
                self.assertEqual(getattr(decorators, name).__module__, NEW_PATH)

    def test_every_importer_uses_the_new_module(self) -> None:
        decorators = importlib.import_module(NEW_PATH)
        for module, name in IMPORTERS:
            with self.subTest(module=module, name=name):
                self.assertIs(getattr(importlib.import_module(module), name),
                              getattr(decorators, name))


if __name__ == '__main__':
    unittest.main()
