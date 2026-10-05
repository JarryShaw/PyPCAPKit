# -*- coding: utf-8 -*-
"""GitHub issue #1026: the ``register`` classmethods reject a non-class themselves.

Each ``register`` classmethod guarded with a bare ``issubclass(protocol,
ProtocolBase)``. A non-class argument is refused by ``issubclass`` itself
before the guard's own ``raise`` is reached, so the caller got ``TypeError:
issubclass() arg 1 must be a class`` leaked out of ``abc`` rather than
:class:`~pcapkit.utilities.exceptions.RegistryError`. Each now tests
``isinstance(protocol, type)`` first, after the
:class:`~pcapkit.corekit.module.ModuleDescriptor` is unwrapped, so a descriptor
naming a non-class attribute is rejected too.

Every registry is process-wide, so each call runs under
:func:`unittest.mock.patch.dict`; the refusals under test write nothing, and the
patch keeps a regression that *did* write from leaking into other tests.

"""
from __future__ import annotations

import importlib
import importlib.util
import unittest
import warnings
from unittest import mock

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: ``(label, module, class, code)``; the code is any key the site accepts.
SITES = (
    ('ProtocolBase', 'pcapkit.protocols.protocol', 'ProtocolBase', 1),
    ('Frame', 'pcapkit.protocols.misc.pcap.frame', 'Frame', 1),
    ('PCAPNG', 'pcapkit.protocols.misc.pcapng', 'PCAPNG', 1),
    ('SCTP', 'pcapkit.protocols.transport.sctp', 'SCTP', 1),
    ('Link', 'pcapkit.protocols.link.link', 'Link', 1),
    ('Internet', 'pcapkit.protocols.internet.internet', 'Internet', 1),
    # ``Transport.register`` raises ``UnsupportedCall`` only for ``Transport``
    # itself; a concrete subclass reaches the guard.
    ('TCP', 'pcapkit.protocols.transport.tcp', 'TCP', 1),
    ('UDP', 'pcapkit.protocols.transport.udp', 'UDP', 1),
)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class RegisterClassGuardTests(unittest.TestCase):
    def _sites(self):
        for label, module, name, code in SITES:
            yield label, getattr(importlib.import_module(module), name), code

    def test_non_class_raises_registry_error_from_the_guard(self) -> None:
        from pcapkit.utilities.exceptions import RegistryError

        for label, klass, code in self._sites():
            for bad in (1, "Raw", None, [int]):
                with self.subTest(site=label, bad=repr(bad)):
                    with mock.patch.dict(klass.__proto__):
                        with self.assertRaises(RegistryError) as caught:
                            klass.register(code, bad)  # type: ignore[arg-type]
                    self.assertIn('must be a class', str(caught.exception))
                    # ``RegistryError`` is a ``TypeError``, so callers catching
                    # the old exception keep working.
                    self.assertIsInstance(caught.exception, TypeError)

    def test_wrong_class_still_raises_registry_error(self) -> None:
        from pcapkit.utilities.exceptions import RegistryError

        for label, klass, code in self._sites():
            with self.subTest(site=label):
                with mock.patch.dict(klass.__proto__):
                    with self.assertRaises(RegistryError) as caught:
                        klass.register(code, dict)  # type: ignore[arg-type]
                self.assertIn('Protocol subclass', str(caught.exception))

    def test_descriptor_naming_a_non_class_raises_registry_error(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.utilities.exceptions import RegistryError

        # ``pcapkit.protocols.protocol.__name__`` is a ``str``.
        descriptor = ModuleDescriptor('pcapkit.protocols.protocol', '__name__')
        for label, klass, code in self._sites():
            with self.subTest(site=label):
                with mock.patch.dict(klass.__proto__):
                    with self.assertRaises(RegistryError) as caught:
                        klass.register(code, descriptor)  # type: ignore[arg-type]
                self.assertIn('must be a class', str(caught.exception))

    def test_descriptor_naming_a_wrong_class_still_raises_registry_error(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.utilities.exceptions import RegistryError

        descriptor = ModuleDescriptor('collections', 'OrderedDict')
        for label, klass, code in self._sites():
            with self.subTest(site=label):
                with mock.patch.dict(klass.__proto__):
                    with self.assertRaises(RegistryError) as caught:
                        klass.register(code, descriptor)  # type: ignore[arg-type]
                self.assertIn('Protocol subclass', str(caught.exception))

    def test_valid_class_and_descriptor_still_register(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.misc.raw import Raw

        for label, klass, code in self._sites():
            for arg in (Raw, ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw')):
                with self.subTest(site=label, arg=type(arg).__name__):
                    with mock.patch.dict(klass.__proto__), warnings.catch_warnings():
                        # Overwriting the built-in entry is expected here.
                        warnings.simplefilter('ignore')
                        klass.register(code, arg)
                        self.assertIs(klass.__proto__[code], Raw)

    def test_transport_itself_is_still_unsupported(self) -> None:
        from pcapkit.protocols.transport.transport import Transport
        from pcapkit.utilities.exceptions import UnsupportedCall

        with self.assertRaises(UnsupportedCall):
            Transport.register(1, 1)  # type: ignore[arg-type]


if __name__ == '__main__':
    unittest.main()
