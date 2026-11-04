# -*- coding: utf-8 -*-
"""HTTP's member classes take their modules' names. C.f. #2529.

A protocol class is named after its module, and a module's top-level schema and data
classes follow: :mod:`~pcapkit.protocols.application.httpv1.protocol`,
:mod:`~pcapkit.protocols.application.httpv1.schema` and
:mod:`~pcapkit.protocols.application.httpv1.data` each hold ``HTTPv1``, and the
``httpv2`` modules ``HTTPv2``. The old module-level name ``HTTP`` keeps no alias
(#1715, #1744), while the package-level names are unchanged.

A dispatched layer is its version's class (#2524), so the key its enclosing layer
stores it under follows that class's name, ``httpv1`` or ``httpv2``, as a member
built directly does. Since the members no longer share the base's name,
registering one keeps its own key rather than displacing the base under
``'HTTP'``.

This module is unit-tier: the segments are built in memory.

"""

from __future__ import annotations

import importlib
import importlib.util
import io
import unittest
import warnings

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Each renamed module, with the class it holds.
MODULES = {
    'pcapkit.protocols.application.httpv1.protocol': 'HTTPv1',
    'pcapkit.protocols.application.httpv2.protocol': 'HTTPv2',
    'pcapkit.protocols.application.httpv1.schema': 'HTTPv1',
    'pcapkit.protocols.application.httpv2.schema': 'HTTPv2',
    'pcapkit.protocols.application.httpv1.data': 'HTTPv1',
    'pcapkit.protocols.application.httpv2.data': 'HTTPv2',
}

#: Each package that exports the classes, with the module it exports them from.
PACKAGES = {
    'pcapkit': 'pcapkit.protocols.application',
    'pcapkit.protocols': 'pcapkit.protocols.application',
    'pcapkit.protocols.application': 'pcapkit.protocols.application',
}

#: A 20-octet TCP header, data offset 5, ACK set, from port 50000 to port 80.
_TCP_TO_80 = bytes.fromhex('c350005000000001000000015010ffff00000000')

#: An HTTP/1.1 request and a nine-octet HTTP/2 ``DATA`` frame on stream 1.
PAYLOADS = {
    'HTTPv1': b'GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n',
    'HTTPv2': bytes.fromhex('000000000000000001'),
}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HTTPMemberNameTests(unittest.TestCase):
    """The class names, the exports, ``info_name`` and the registry key."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_each_module_holds_the_class_named_after_it(self) -> None:
        for module_name, class_name in MODULES.items():
            with self.subTest(module=module_name):
                module = importlib.import_module(module_name)
                klass = getattr(module, class_name)
                self.assertEqual(klass.__name__, class_name)
                self.assertEqual(klass.__module__, module_name)
                self.assertIn(class_name, module.__all__)
                self.assertNotIn('HTTP', module.__all__)
                self.assertFalse(hasattr(module, 'HTTP'))

    def test_package_names_are_unchanged(self) -> None:
        for package_name, home in PACKAGES.items():
            package = importlib.import_module(package_name)
            for class_name in ('HTTPv1', 'HTTPv2'):
                module = importlib.import_module(f'{home}.{class_name.lower()}')
                with self.subTest(package=package_name, name=class_name):
                    self.assertIs(getattr(package, class_name), getattr(module, class_name))

    def test_each_protocol_binds_its_own_modules_schema_and_data(self) -> None:
        for class_name in ('HTTPv1', 'HTTPv2'):
            suffix = class_name.lower()
            klass = getattr(importlib.import_module(f'pcapkit.protocols.application.{suffix}.protocol'),
                            class_name)
            schema = importlib.import_module(f'pcapkit.protocols.application.{suffix}.schema')
            data = importlib.import_module(f'pcapkit.protocols.application.{suffix}.data')
            with self.subTest(klass=class_name):
                self.assertIs(klass.__schema__, getattr(schema, class_name))
                self.assertIs(klass.__data__, getattr(data, class_name))

    def test_a_dispatched_layer_sits_under_its_versions_key(self) -> None:
        """The dispatched layer is the member, so its key is the member's name."""
        from pcapkit.protocols.transport.tcp.protocol import TCP

        for class_name, payload in PAYLOADS.items():
            klass = getattr(importlib.import_module(
                f'pcapkit.protocols.application.{class_name.lower()}.protocol'), class_name)
            data = _TCP_TO_80 + payload
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                tcp = TCP(io.BytesIO(data), len(data))
            with self.subTest(payload=class_name):
                self.assertIs(type(tcp.payload), klass)
                self.assertEqual(tcp.payload.info_name, class_name.lower())
                self.assertIs(tcp.info[class_name.lower()], tcp.payload.info)
                self.assertNotIn('http', tcp.info)

    def test_a_member_built_directly_reports_its_own_name(self) -> None:
        for class_name, payload in PAYLOADS.items():
            klass = getattr(importlib.import_module(
                f'pcapkit.protocols.application.{class_name.lower()}.protocol'), class_name)
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                layer = klass(io.BytesIO(payload), len(payload))
            with self.subTest(klass=class_name):
                self.assertEqual(layer.info_name, class_name.lower())

    def test_registering_a_member_keeps_the_base_under_http(self) -> None:
        """Each member's own key holds it, and ``'HTTP'`` keeps the base."""
        from pcapkit.foundation.registry import protocols as registry
        from pcapkit.foundation.registry.protocols import protocol as reg_protocol
        from pcapkit.protocols.application.http.protocol import HTTP
        from pcapkit.utilities.warnings import RegistryWarning

        names = reg_protocol.protocol_registry
        before = dict(names)

        def restore() -> None:
            names.clear()
            names.update(before)

        self.addCleanup(restore)
        for class_name in ('HTTPv2', 'HTTPv1'):
            klass = getattr(importlib.import_module(
                f'pcapkit.protocols.application.{class_name.lower()}.protocol'), class_name)
            with self.subTest(klass=class_name):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    registry.register_protocol(klass)
                self.assertEqual([str(item.message) for item in caught
                                  if issubclass(item.category, RegistryWarning)], [])
                self.assertIs(names['HTTP'], HTTP)
                self.assertIs(names[class_name.upper()], klass)


if __name__ == '__main__':
    unittest.main()
