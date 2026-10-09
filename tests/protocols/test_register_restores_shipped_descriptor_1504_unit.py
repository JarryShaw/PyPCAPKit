# -*- coding: utf-8 -*-
"""GitHub issue #1504: restoring a shipped dispatch entry puts back its descriptor.

:meth:`ProtocolBase.register <pcapkit.protocols.protocol.ProtocolBase.register>`
and its ``Link``, ``Internet``, ``Transport`` (``TCP``, ``UDP``), ``SCTP`` and
``Frame`` overrides resolved a :class:`~pcapkit.corekit.module.ModuleDescriptor`
argument to its class before storing it. The #1364 guard returns early only when
the argument equals the *incumbent*, so after an override, handing back the
shipped descriptor stored the class it names: the round trip did not close, and
the restore imported the module the entry was meant to defer. A descriptor equal
to the one a code shipped with is now matched before it is resolved, and the
shipped object itself is stored.

``PCAPNG.register`` has the same defect and is not covered here; it stays
recorded under ``Gap(1504, ...)`` in
:file:`tests/foundation/registry/test_registry_symmetry_unit.py`.

Every registry is process-wide, so each case runs under
:func:`unittest.mock.patch.dict`. Classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import collections
import contextlib
import importlib
import sys
import types
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class

#: ``(module, class, code)`` per site family, ``code`` given as a
#: ``module:Enum.member`` path or a literal; each code ships a descriptor.
#: ``ProtocolBase.register`` has no populated registry of its own, so
#: :meth:`TestRestoreShippedDescriptor._sites` adds a scratch subclass for it.
SITES = (
    ('pcapkit.protocols.link.link', 'Link',
     'pcapkit.const.reg.ethertype:EtherType.Address_Resolution_Protocol'),
    ('pcapkit.protocols.internet.internet', 'Internet', 'pcapkit.const.reg.transtype:TransType.TCP'),
    ('pcapkit.protocols.transport.tcp', 'TCP', 80),
    ('pcapkit.protocols.transport.udp', 'UDP', 1701),
    ('pcapkit.protocols.transport.sctp', 'SCTP',
     'pcapkit.const.sctp.payload_protocol_identifier:PayloadProtocolIdentifier.'
     'PayloadProtocolIdentifier_3GPP_NG_Application_Protocol'),
    ('pcapkit.protocols.misc.pcap.frame', 'Frame', 'pcapkit.const.reg.linktype:LinkType.ETHERNET'),
)

#: A code no site ships an entry under.
UNSHIPPED = 0xFFFE


def _code(spec):  # type: ignore[no-untyped-def]
    if isinstance(spec, str):
        module, _, rest = spec.partition(':')
        enum, _, member = rest.partition('.')
        return getattr(getattr(importlib.import_module(module), enum), member)
    return spec


class _Blocker:
    """A :data:`sys.meta_path` finder that records and refuses one import."""

    def __init__(self, name: 'str') -> None:
        self.name = name
        self.attempts = []  # type: list[str]

    def find_spec(self, name, path=None, target=None):  # type: ignore[no-untyped-def]
        if name == self.name:
            self.attempts.append(name)
            raise ModuleNotFoundError(f'blocked by the #1504 test: {name}')
        return None


@contextlib.contextmanager
def _unimported(name: 'str'):  # type: ignore[no-untyped-def]
    """Run the block with ``name`` absent from :data:`sys.modules` and unimportable."""
    saved = sys.modules.pop(name)
    blocker = _Blocker(name)
    sys.meta_path.insert(0, blocker)
    try:
        yield blocker
    finally:
        sys.meta_path.remove(blocker)
        sys.modules[name] = saved


@contextlib.contextmanager
def _stand_in(name: 'str', **attrs):  # type: ignore[no-untyped-def]
    """Run the block with ``name`` in :data:`sys.modules` replaced by a stub module."""
    saved = sys.modules[name]
    stub = types.ModuleType(name)
    stub.__dict__.update(attrs)
    sys.modules[name] = stub
    try:
        yield stub
    finally:
        sys.modules[name] = saved


class TestRestoreShippedDescriptor(unittest.TestCase):
    """Override, then restore the shipped descriptor, at every site family."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _sites(self):  # type: ignore[no-untyped-def]
        """Yield ``(label, cls, code)``, the scratch ``ProtocolBase`` site last."""
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.misc.raw import Raw

        for module, name, code in SITES:
            yield name, getattr(importlib.import_module(module), name), _code(code)
        table = collections.defaultdict(lambda: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'),
                                        {1: ModuleDescriptor('pcapkit.protocols.misc.null', 'NoPayload')})
        yield 'ProtocolBase', type('W1504Scratch', (Raw,), {'__module__': __name__, '__proto__': table}), 1

    def _each_site(self, check):  # type: ignore[no-untyped-def]
        """Run ``check(cls, code, shipped, custom)`` per site, each under its own ``subTest``."""
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.misc.raw import Raw

        custom = type('W1504Custom', (Raw,), {'__module__': __name__})
        for label, cls, code in self._sites():
            registry = cls.__proto__
            shipped = registry[code]
            self.assertIsInstance(shipped, ModuleDescriptor, label)
            with self.subTest(site=label), mock.patch.dict(registry), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                check(cls, code, shipped, custom)

    def test_restoring_the_shipped_descriptor_stores_that_object(self) -> None:
        def check(cls, code, shipped, custom):  # type: ignore[no-untyped-def]
            cls.register(code, custom)
            self.assertIs(cls.__proto__[code], custom)
            cls.register(code, shipped)
            self.assertIs(cls.__proto__[code], shipped)
        self._each_site(check)

    def test_restoring_by_an_equal_descriptor_stores_the_shipped_object(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor

        def check(cls, code, shipped, custom):  # type: ignore[no-untyped-def]
            cls.register(code, custom)
            cls.register(code, ModuleDescriptor(shipped.module, shipped.name))
            self.assertIs(cls.__proto__[code], shipped)
        self._each_site(check)

    def test_restoring_warns_once_naming_the_override(self) -> None:
        from pcapkit.utilities.warnings import RegistryWarning

        def check(cls, code, shipped, custom):  # type: ignore[no-untyped-def]
            cls.register(code, custom)
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                cls.register(code, shipped)
            messages = [str(item.message) for item in caught if issubclass(item.category, RegistryWarning)]
            self.assertEqual(len(messages), 1, messages)
            self.assertIn('W1504Custom', messages[0])
        self._each_site(check)

    def test_restoring_imports_nothing(self) -> None:
        """The restore leaves the shipped module unimported, as shipped."""
        def check(cls, code, shipped, custom):  # type: ignore[no-untyped-def]
            cls.register(code, custom)
            with _unimported(shipped.module) as blocker:
                cls.register(code, shipped)
                self.assertNotIn(shipped.module, sys.modules)
            self.assertEqual(blocker.attempts, [])
            self.assertIs(cls.__proto__[code], shipped)
        self._each_site(check)

    def test_dispatch_resolves_the_restored_entry_when_it_runs(self) -> None:
        """After the round trip the class is looked up at dispatch, not at the restore."""
        from pcapkit.protocols.misc.raw import Raw

        def check(cls, code, shipped, custom):  # type: ignore[no-untyped-def]
            cls.register(code, custom)
            cls.register(code, shipped)
            marker = type('W1504Marker', (Raw,), {'__module__': __name__})
            with _stand_in(shipped.module, **{shipped.name: marker}):
                self.assertIs(cls._lookup_next_layer(cls.__proto__, code), marker)
        self._each_site(check)

    def test_a_shipped_descriptor_under_another_code_is_still_resolved(self) -> None:
        """Only the code a descriptor shipped under restores it unresolved."""
        def check(cls, code, shipped, custom):  # type: ignore[no-untyped-def]
            self.assertNotIn(UNSHIPPED, cls.__proto__)
            cls.register(UNSHIPPED, shipped)
            self.assertIs(cls.__proto__[UNSHIPPED], shipped.klass)
        self._each_site(check)


if __name__ == '__main__':
    unittest.main()
