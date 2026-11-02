# -*- coding: utf-8 -*-
"""``NoPayload`` and its schema and data model live in ``no_payload`` modules, and only there.

GitHub issue #2529: a protocol class and the module holding it share a name, so
:class:`~pcapkit.protocols.misc.no_payload.NoPayload` is in
:mod:`pcapkit.protocols.misc.no_payload`, its header schema in
:mod:`pcapkit.protocols.schema.misc.no_payload` and its data model in
:mod:`pcapkit.protocols.data.misc.no_payload`. The ``misc.null`` paths they
shipped under in 1.5.x keep no re-export, by the ruling on #1715 (#1744). This
pins both halves: the old paths do not import, and every importer reaches the
classes through the new modules. The ``versionremoved`` notes for the old paths
are pinned with the other shipped paths, in
:mod:`tests.project.test_no_moved_name_re_exports_1744_unit`.

"""
import importlib
import importlib.util
import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): checks where ``NoPayload`` lives and that its old paths are
#: gone, a question about the tree.
__tier__ = 'LATEST'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: ``(new module, old module)`` for the protocol, its header schema and its data model.
PATHS = (
    ('pcapkit.protocols.misc.no_payload', 'pcapkit.protocols.misc.null'),
    ('pcapkit.protocols.schema.misc.no_payload', 'pcapkit.protocols.schema.misc.null'),
    ('pcapkit.protocols.data.misc.no_payload', 'pcapkit.protocols.data.misc.null'),
)

#: The packages that export ``NoPayload``, as ``(package, module it comes from)``.
PACKAGES = (
    ('pcapkit', 'pcapkit.protocols.misc.no_payload'),
    ('pcapkit.protocols', 'pcapkit.protocols.misc.no_payload'),
    ('pcapkit.protocols.misc', 'pcapkit.protocols.misc.no_payload'),
    ('pcapkit.protocols.schema', 'pcapkit.protocols.schema.misc.no_payload'),
    ('pcapkit.protocols.schema.misc', 'pcapkit.protocols.schema.misc.no_payload'),
    ('pcapkit.protocols.data', 'pcapkit.protocols.data.misc.no_payload'),
    ('pcapkit.protocols.data.misc', 'pcapkit.protocols.data.misc.no_payload'),
)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class NoPayloadPathTests(unittest.TestCase):
    """Pin the ``no_payload`` modules as the only home of ``NoPayload``."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_the_null_paths_do_not_import(self) -> None:
        importlib.import_module('pcapkit.protocols.misc')
        for _, old in PATHS:
            with self.subTest(path=old):
                with self.assertRaises(ModuleNotFoundError) as ctx:
                    importlib.import_module(old)
                self.assertEqual(ctx.exception.name, old)
                self.assertIsNone(importlib.util.find_spec(old))

    def test_each_module_holds_no_payload_alone(self) -> None:
        for new, _ in PATHS:
            with self.subTest(path=new):
                module = importlib.import_module(new)
                self.assertEqual(module.__all__, ['NoPayload'])
                self.assertEqual(module.NoPayload.__module__, new)

    def test_the_protocol_binds_the_new_schema_and_data_model(self) -> None:
        from pcapkit.protocols.data.misc.no_payload import NoPayload as Data_NoPayload
        from pcapkit.protocols.misc.no_payload import NoPayload
        from pcapkit.protocols.schema.misc.no_payload import NoPayload as Schema_NoPayload

        self.assertIs(NoPayload.__schema__, Schema_NoPayload)
        self.assertIs(NoPayload.__data__, Data_NoPayload)
        self.assertIsInstance(NoPayload().info, Data_NoPayload)

    def test_every_package_exports_the_new_modules_class(self) -> None:
        for package, home in PACKAGES:
            with self.subTest(package=package):
                module = importlib.import_module(package)
                self.assertIn('NoPayload', module.__all__)
                self.assertIs(module.NoPayload, importlib.import_module(home).NoPayload)


if __name__ == '__main__':
    unittest.main()
