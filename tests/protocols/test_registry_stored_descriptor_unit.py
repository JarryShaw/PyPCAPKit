# -*- coding: utf-8 -*-
"""GitHub issue #1364: re-registering a stored module descriptor keeps it.

``ProtocolBase.register`` and the ``Internet``, ``Link``, ``Transport``,
``SCTP`` (keyed by PPID), ``Frame`` and ``PCAPNG`` overrides resolved a
:class:`~pcapkit.corekit.module.ModuleDescriptor` argument to its class before
comparing it with the stored entry. Handing back the stored descriptor itself
therefore warned of an overwrite and replaced the deferred entry with the
class. The registrars now compare first: the stored entry, or a descriptor
equal to it, is a silent no-op that keeps the stored object, while a different
entry still warns. ``Extractor.register_dumper`` is pinned alongside; #1376
already keeps its shipped descriptors.

Every registry is process-wide, so each case runs under
:func:`unittest.mock.patch.dict`. Classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import importlib
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class

#: ``(module, class)`` for each registrar, picked so its ``__proto__`` ships
#: module descriptors. IPv4 and Ethernet reach the ``Internet`` and ``Link``
#: overrides; there is no class whose populated ``__proto__`` reaches
#: ``ProtocolBase.register`` itself, so that one is exercised on a scratch
#: subclass in its own test.
SITES = (
    ('pcapkit.protocols.internet.ipv4', 'IPv4'),
    ('pcapkit.protocols.link.ethernet', 'Ethernet'),
    ('pcapkit.protocols.transport.tcp', 'TCP'),
    ('pcapkit.protocols.transport.udp', 'UDP'),
    ('pcapkit.protocols.transport.sctp', 'SCTP'),
    ('pcapkit.protocols.misc.pcap.frame', 'Frame'),
    ('pcapkit.protocols.misc.pcapng', 'PCAPNG'),
)


class TestRegistryStoredDescriptor(unittest.TestCase):
    """Pin when a protocol registrar warns about a stored descriptor."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _count(self, call, *args) -> int:  # type: ignore[no-untyped-def]
        """Run ``call(*args)`` and return how many registry warnings it raised."""
        from pcapkit.utilities.warnings import RegistryWarning

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            call(*args)
        return sum(issubclass(item.category, RegistryWarning) for item in caught)

    def _each_site(self, check):  # type: ignore[no-untyped-def]
        """Run ``check(register, registry)`` for every site, each in its own ``subTest``."""
        from pcapkit.corekit.module import ModuleDescriptor

        for module, name in SITES:
            cls = getattr(importlib.import_module(module), name)
            registry = cls.__proto__
            self.assertTrue(any(isinstance(value, ModuleDescriptor) for value in registry.values()), name)
            with self.subTest(site=name), mock.patch.dict(registry):
                check(cls.register, registry)

    def test_reregistering_the_stored_descriptor_is_silent(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor

        def check(register, registry):  # type: ignore[no-untyped-def]
            for code, value in list(registry.items()):
                if not isinstance(value, ModuleDescriptor):
                    continue
                self.assertEqual(self._count(register, code, value), 0, code)
                self.assertIs(registry[code], value)
                # An equal descriptor built afresh is the same entry, and the
                # stored object is kept.
                self.assertEqual(self._count(register, code, ModuleDescriptor(*value)), 0, code)
                self.assertIs(registry[code], value)
        self._each_site(check)

    def test_reregistering_the_stored_class_is_silent(self) -> None:
        def check(register, registry):  # type: ignore[no-untyped-def]
            code, value = next(iter(registry.items()))
            klass = value.klass
            self.assertEqual(self._count(register, code, klass), 1)
            self.assertIs(registry[code], klass)
            self.assertEqual(self._count(register, code, klass), 0)
            self.assertIs(registry[code], klass)
        self._each_site(check)

    def test_a_different_entry_still_warns(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.misc.raw import Raw

        def check(register, registry):  # type: ignore[no-untyped-def]
            code = next(iter(registry))
            other = ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw')
            self.assertEqual(self._count(register, code, other), 1)
            self.assertIs(registry[code], Raw)
        self._each_site(check)

    def test_an_invalid_entry_equal_to_a_descriptor_still_raises(self) -> None:
        from pcapkit.utilities.exceptions import RegistryError

        def check(register, registry):  # type: ignore[no-untyped-def]
            code, value = next(iter(registry.items()))
            with self.assertRaisesRegex(RegistryError, r'^protocol must be a class, not '):
                register(code, tuple(value))
            self.assertIs(registry[code], value)
        self._each_site(check)

    def test_protocol_base_register_keeps_the_stored_descriptor(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.misc.raw import Raw

        descriptor = ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw')
        scratch = type('W1364Raw', (Raw,), {'__proto__': {1: descriptor}})
        self.assertEqual(self._count(scratch.register, 1, descriptor), 0)
        self.assertIs(scratch.__proto__[1], descriptor)
        self.assertEqual(self._count(scratch.register, 1, ModuleDescriptor(*descriptor)), 0)
        self.assertIs(scratch.__proto__[1], descriptor)
        other = ModuleDescriptor('pcapkit.protocols.misc.null', 'NoPayload')
        self.assertEqual(self._count(scratch.register, 1, other), 1)
        self.assertIs(scratch.__proto__[1], other.klass)

    def test_register_dumper_keeps_the_stored_descriptor(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.foundation.extraction import Extractor

        with mock.patch.dict(Extractor.__output__):
            entry = Extractor.__output__['json']
            self.assertIsInstance(entry[0], ModuleDescriptor)
            self.assertEqual(self._count(Extractor.register_dumper, 'json', *entry), 0)
            self.assertIs(Extractor.__output__['json'][0], entry[0])


if __name__ == '__main__':
    unittest.main()
