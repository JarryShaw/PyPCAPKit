from __future__ import annotations

import importlib.util
import unittest
from unittest import mock

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class FoundationRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_engine_and_dumper_registration_wrappers(self) -> None:
        import pcapkit.foundation.registry as registry_pkg
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.dumpkit.null import NotImplementedIO
        from pcapkit.foundation.registry import foundation as registry

        self.assertIs(registry_pkg.register_dumper, registry.register_dumper)

        descriptor = ModuleDescriptor('pcapkit.foundation.engines', 'Engine')
        with mock.patch.object(registry.Extractor, 'register_engine') as register_engine:
            registry.register_extractor_engine('unit-engine-descriptor', descriptor)
        register_engine.assert_called_once_with('unit-engine-descriptor', descriptor)

        dumper = ModuleDescriptor('pcapkit.dumpkit', 'NotImplementedIO')
        with mock.patch.object(registry.Extractor, 'register_dumper') as extractor:
            with mock.patch.object(registry.TraceFlow, 'register_dumper') as traceflow:
                registry.register_dumper('unit', dumper, ext='.unit')
        extractor.assert_called_once_with('unit', dumper, '.unit')
        traceflow.assert_called_once_with('unit', dumper, ext='.unit')

        with mock.patch.object(registry.Extractor, 'register_dumper') as extractor:
            with mock.patch.object(registry.TraceFlow, 'register_dumper') as traceflow:
                registry.register_dumper('unit-class', NotImplementedIO, ext='.unit')
        extractor.assert_called_once_with('unit-class', NotImplementedIO, '.unit')
        traceflow.assert_called_once_with('unit-class', NotImplementedIO, ext='.unit')

        with mock.patch.object(registry.Extractor, 'register_dumper') as extractor:
            registry.register_extractor_dumper('unit-ext', NotImplementedIO, ext='.unit')
        extractor.assert_called_once_with('unit-ext', NotImplementedIO, '.unit')

        with mock.patch.object(registry.Extractor, 'register_dumper') as extractor:
            registry.register_extractor_dumper('unit-ext-string', dumper, ext='.unit')
        extractor.assert_called_once_with('unit-ext-string', dumper, '.unit')

        with mock.patch.object(registry.TraceFlow, 'register_dumper') as traceflow:
            registry.register_traceflow_dumper('unit-trace', dumper, ext='.unit')
        traceflow.assert_called_once_with('unit-trace', dumper, ext='.unit')

        with mock.patch.object(registry.TraceFlow, 'register_dumper') as traceflow:
            registry.register_traceflow_dumper('unit-trace-class', NotImplementedIO, ext='.unit')
        traceflow.assert_called_once_with('unit-trace-class', NotImplementedIO, ext='.unit')

    def test_dumper_registrars_reject_a_non_class_with_registry_error(self) -> None:
        """GitHub issue #1021: every dumper registrar raises ``RegistryError``.

        ``register_extractor_dumper`` and ``register_traceflow_dumper`` share a
        signature and a docstring, and ``TraceFlow.register_dumper`` carried the same
        bare ``issubclass`` guard as ``Extractor.register_dumper``, so a fix to one
        left the other leaking ``TypeError``. Nothing is mocked: the point is what the
        public wrappers really raise.
        """
        import sys
        import types

        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.registry import foundation as registry
        from pcapkit.foundation.traceflow.traceflow import TraceFlow
        from pcapkit.utilities.exceptions import RegistryError

        module = types.ModuleType('unit_foundation_non_class_mod')
        module.NOT_A_CLASS = 42
        sys.modules['unit_foundation_non_class_mod'] = module
        self.addCleanup(lambda: sys.modules.pop('unit_foundation_non_class_mod', None))
        descriptor = ModuleDescriptor('unit_foundation_non_class_mod', 'NOT_A_CLASS')

        registrars = {
            'Extractor.register_dumper':
                lambda value: Extractor.register_dumper('unit-bad', value, '.bad'),
            'TraceFlow.register_dumper':
                lambda value: TraceFlow.register_dumper('unit-bad', value, ext='.bad'),
            'register_extractor_dumper':
                lambda value: registry.register_extractor_dumper('unit-bad', value, ext='.bad'),
            'register_traceflow_dumper':
                lambda value: registry.register_traceflow_dumper('unit-bad', value, ext='.bad'),
        }
        for name, register in registrars.items():
            for label, value, expected in (
                ('instance', 42, 'must be a class'),
                ('descriptor to non-class', descriptor, 'must be a class'),
                ('wrong class', object, 'subclass'),
            ):
                with self.subTest(registrar=name, value=label):
                    with self.assertRaises(RegistryError) as caught:
                        register(value)
                    self.assertIn(expected, str(caught.exception))

    def test_callback_and_extractor_registration_wrappers(self) -> None:
        from pcapkit.foundation.reassembly import IPv4_Reassembly, TCP_Reassembly
        from pcapkit.foundation.registry import foundation as registry
        from pcapkit.foundation.traceflow import TCP_TraceFlow

        def callback(_: object) -> None:
            return None

        callback_routes = [
            (registry.register_reassembly_callback, 'ipv4', IPv4_Reassembly, 'register_callback'),
            (registry.register_reassembly_callback, 'TCP', TCP_Reassembly, 'register_callback'),
            (registry.register_traceflow_callback, 'tcp', TCP_TraceFlow, 'register_callback'),
        ]
        for func, protocol, target, method in callback_routes:
            with self.subTest(func=func.__name__, protocol=protocol):
                with mock.patch.object(target, method) as register:
                    func(protocol, callback, index=0)
                register.assert_called_once_with(callback, index=0)

        with mock.patch.object(registry.Extractor, 'register_reassembly') as register:
            descriptor = registry.ModuleDescriptor('pcapkit.foundation.reassembly', 'IPv4_Reassembly')
            registry.register_extractor_reassembly('ipv4', descriptor)
        register.assert_called_once_with('ipv4', descriptor)

        with mock.patch.object(registry.Extractor, 'register_reassembly') as register:
            registry.register_extractor_reassembly('tcp', TCP_Reassembly)
        register.assert_called_once_with('tcp', TCP_Reassembly)

        with mock.patch.object(registry.Extractor, 'register_traceflow') as register:
            registry.register_extractor_traceflow('tcp', TCP_TraceFlow)
        register.assert_called_once_with('tcp', TCP_TraceFlow)

        with mock.patch.object(registry.Extractor, 'register_traceflow') as register:
            descriptor = registry.ModuleDescriptor('pcapkit.foundation.traceflow', 'TCP_TraceFlow')
            registry.register_extractor_traceflow('tcp-string', descriptor)
        register.assert_called_once_with('tcp-string', descriptor)

    def test_engine_reassembly_wrapper(self) -> None:
        """#2814: the wrapper writes an engine's ``__reassembly__``, found by name or class."""
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.foundation.engines.dpkt import DPKT
        from pcapkit.foundation.engines.pcap import PCAP
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.registry import register_engine_reassembly
        from pcapkit.utilities.exceptions import RegistryError
        from pcapkit.utilities.warnings import RegistryWarning

        def adapter(frame: object) -> None:
            return None

        with mock.patch.dict(DPKT.__reassembly__), mock.patch.dict(PCAP.__reassembly__):
            shipped = DPKT.__reassembly__['ipv4']

            # by registered engine name, case-folded, as a module descriptor
            register_engine_reassembly('DPKT', 'unit-2814',
                                       ModuleDescriptor('pcapkit.toolkit.dpkt', 'tcp_reassembly'))
            self.assertEqual(DPKT.__reassembly__['unit-2814'],
                             ModuleDescriptor('pcapkit.toolkit.dpkt', 'tcp_reassembly'))

            # by class, as the nameless default-engine readers are given, and as a callable
            register_engine_reassembly(PCAP, 'unit-2814', adapter)
            self.assertIs(PCAP.__reassembly__['unit-2814'], adapter)

            # an override is undone by handing back an equal descriptor
            with self.assertWarns(RegistryWarning):
                register_engine_reassembly('dpkt', 'ipv4', adapter)
            register_engine_reassembly('dpkt', 'ipv4', ModuleDescriptor(shipped.module, shipped.name))
            self.assertEqual(DPKT.__reassembly__['ipv4'], shipped)

            before = dict(DPKT.__reassembly__)
            for engine in ('no-such-engine', 'default', Extractor, 'dpkt-not'):
                with self.subTest(engine=engine):
                    with self.assertRaisesRegex(RegistryError, 'registered engine name or an EngineBase'):
                        register_engine_reassembly(engine, 'unit-2814-bad', adapter)  # type: ignore[arg-type]
            with self.assertRaises(RegistryError):
                register_engine_reassembly('dpkt', 'unit-2814-bad', 42)  # type: ignore[arg-type]
            self.assertEqual(DPKT.__reassembly__, before)

    def test_registration_accepts_pcapkit_own_builtin_classes(self) -> None:
        """The built-ins pass the internal ``issubclass`` gate, and non-subclasses still fail.

        This is the regression for GitHub issue #513. A test that mocks
        ``Extractor.register_*`` away never reaches the validation in
        :mod:`pcapkit.foundation.extraction`, so it cannot catch the entry points
        rejecting pcapkit's *own* engines, reassembly and flow-tracing classes with
        :exc:`~pcapkit.utilities.exceptions.RegistryError`.

        Guards against a check that names the auto-registering public class
        (``Engine``, ``Reassembly``, ``TraceFlow``), while every built-in subclasses
        the ``*Base`` variant directly, specifically so that it is not
        auto-registered: ``issubclass(PCAP, Engine)`` is :data:`False` while
        ``issubclass(PCAP, EngineBase)`` is :data:`True`.

        Deliberately does **not** mock, because the point is to exercise the gate.

        """
        # NOTE: the public ``register_*`` refuse a built-in under any name but its own
        # (#1016, #1363), so #513's real gate goes through ``_register_internal_*``.
        # NOTE: imported locally, as every sibling is, since ``setUp`` puts the class's
        # own ``pcapkit`` import in ``sys.modules``.
        from pcapkit.foundation.engines.pcap import PCAP as PCAP_Engine
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.reassembly.ipv4 import IPv4 as IPv4_Reassembly
        from pcapkit.foundation.traceflow.tcp import TCP as TCP_TraceFlow
        from pcapkit.utilities.exceptions import RegistryError

        cases = (
            ('engine', Extractor._register_internal_engine, PCAP_Engine,
             Extractor.__engine__),
            ('reassembly', Extractor._register_internal_reassembly, IPv4_Reassembly,
             Extractor.__reassembly__),
            ('traceflow', Extractor._register_internal_traceflow, TCP_TraceFlow,
             Extractor.__traceflow__),
        )

        # NOTE: ``registry`` is one global table, so the writes are rolled back.
        with mock.patch.dict(Extractor.__engine__), \
                mock.patch.dict(Extractor.__reassembly__), \
                mock.patch.dict(Extractor.__traceflow__):
            for name, func, klass, store in cases:
                with self.subTest(kind=name, accepted=True):
                    # NOTE: a distinct key per call, so it neither collides with a built-in
                    # nor emits the ``already registered, overwriting`` warning.
                    key = f'unit-513-{name}'
                    func(key, klass)

                    # NOTE: read back, since a helper that runs the ``issubclass`` gate and
                    # then drops the class raises nothing.
                    self.assertIn(key, store)
                    self.assertIs(store[key], klass)

            # And the gate still rejects something that is genuinely not a subclass --
            # the internal path must not have turned the check into a no-op.
            for name, func, _klass, _store in cases:
                with self.subTest(kind=name, accepted=False):
                    with self.assertRaises(RegistryError):
                        func(f'unit-513-reject-{name}', int)  # type: ignore[arg-type]

    def test_public_registration_rejects_base_only_classes(self) -> None:
        """GitHub issue #1016: the public door takes the public class, not the ``*Base``.

        The built-ins derive from ``EngineBase``/``ReassemblyBase``/``TraceFlowBase``
        directly, and third parties extend ``Engine``/``Reassembly``/``TraceFlow``
        because those carry the registration hook. The ``register_extractor_*``
        wrappers therefore refuse a base-only class -- the real built-ins here --
        with a message naming the public class, and leave the registry untouched.
        Unmocked, for the same reason as the #513 test above.

        """
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.foundation.engines.pcap import PCAP as PCAP_Engine
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.reassembly.ipv4 import IPv4 as IPv4_Reassembly
        from pcapkit.foundation.registry.foundation import (register_extractor_engine,
                                                            register_extractor_reassembly,
                                                            register_extractor_traceflow)
        from pcapkit.foundation.traceflow.tcp import TCP as TCP_TraceFlow
        from pcapkit.utilities.exceptions import RegistryError

        with mock.patch.dict(Extractor.__engine__), \
                mock.patch.dict(Extractor.__reassembly__), \
                mock.patch.dict(Extractor.__traceflow__):
            for name, func, klass, store, message in (
                ('engine', register_extractor_engine, PCAP_Engine,
                 Extractor.__engine__, 'engine must be an Engine subclass'),
                ('reassembly', register_extractor_reassembly, IPv4_Reassembly,
                 Extractor.__reassembly__, 'reassembly must be a Reassembly subclass'),
                ('traceflow', register_extractor_traceflow, TCP_TraceFlow,
                 Extractor.__traceflow__, 'traceflow must be a TraceFlow subclass'),
            ):
                key = f'unit-1016-{name}'
                with self.subTest(kind=name, form='class'):
                    with self.assertRaisesRegex(RegistryError, message):
                        func(key, klass)  # type: ignore[arg-type]
                    self.assertNotIn(key, store)

                # A descriptor is unwrapped and then checked, not waved through.
                with self.subTest(kind=name, form='descriptor'):
                    descriptor = ModuleDescriptor(klass.__module__, klass.__name__)
                    with self.assertRaisesRegex(RegistryError, message):
                        func(key, descriptor)  # type: ignore[arg-type]
                    self.assertNotIn(key, store)


if __name__ == '__main__':
    unittest.main()
