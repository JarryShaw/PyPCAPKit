from __future__ import annotations

import importlib.util
import unittest
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class FoundationRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_engine_and_dumper_registration_wrappers(self) -> None:
        import pcapkit.foundation.registry as registry_pkg
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.dumpkit.null import NotImplementedIO
        from pcapkit.foundation.registry import foundation as registry

        self.assertIs(registry_pkg.register_dumper, registry.register_dumper)

        with mock.patch.object(registry.Extractor, 'register_engine') as register_engine:
            registry.register_extractor_engine('unit-engine', 'pcapkit.foundation.engines', 'Engine')
        register_engine.assert_called_once()
        self.assertIsInstance(register_engine.call_args.args[1], ModuleDescriptor)

        descriptor = ModuleDescriptor('pcapkit.foundation.engines', 'Engine')
        with mock.patch.object(registry.Extractor, 'register_engine') as register_engine:
            registry.register_extractor_engine('unit-engine-descriptor', descriptor)
        register_engine.assert_called_once_with('unit-engine-descriptor', descriptor)

        with mock.patch.object(registry.Extractor, 'register_dumper') as extractor:
            with mock.patch.object(registry.TraceFlow, 'register_dumper') as traceflow:
                registry.register_dumper('unit', 'pcapkit.dumpkit', 'NotImplementedIO',
                                         ext='.unit')
        self.assertIsInstance(extractor.call_args.args[1], ModuleDescriptor)
        self.assertIsInstance(traceflow.call_args.args[1], ModuleDescriptor)

        with mock.patch.object(registry.Extractor, 'register_dumper') as extractor:
            with mock.patch.object(registry.TraceFlow, 'register_dumper') as traceflow:
                registry.register_dumper('unit-class', NotImplementedIO, ext='.unit')
        extractor.assert_called_once_with('unit-class', NotImplementedIO, '.unit')
        traceflow.assert_called_once_with('unit-class', NotImplementedIO, '.unit')

        with mock.patch.object(registry.Extractor, 'register_dumper') as extractor:
            registry.register_extractor_dumper('unit-ext', NotImplementedIO, ext='.unit')
        extractor.assert_called_once_with('unit-ext', NotImplementedIO, '.unit')

        with mock.patch.object(registry.Extractor, 'register_dumper') as extractor:
            registry.register_extractor_dumper('unit-ext-string', 'pcapkit.dumpkit',
                                               'NotImplementedIO', ext='.unit')
        self.assertIsInstance(extractor.call_args.args[1], ModuleDescriptor)

        with mock.patch.object(registry.TraceFlow, 'register_dumper') as traceflow:
            registry.register_traceflow_dumper('unit-trace', 'pcapkit.dumpkit',
                                               'NotImplementedIO', ext='.unit')
        self.assertIsInstance(traceflow.call_args.args[1], ModuleDescriptor)

        with mock.patch.object(registry.TraceFlow, 'register_dumper') as traceflow:
            registry.register_traceflow_dumper('unit-trace-class', NotImplementedIO, ext='.unit')
        traceflow.assert_called_once_with('unit-trace-class', NotImplementedIO, '.unit')

    def test_callback_and_extractor_registration_wrappers(self) -> None:
        from pcapkit.foundation.registry import foundation as registry

        callback = object()
        callback_routes = [
            (registry.register_reassembly_ipv4_callback, registry.IPv4_Reassembly, 'register',
             'registered IPv4 reassembly callback: %r'),
            (registry.register_reassembly_ipv6_callback, registry.IPv6_Reassembly, 'register',
             'registered IPv6 reassembly callback: %r'),
            (registry.register_reassembly_tcp_callback, registry.TCP_Reassembly, 'register',
             'registered TCP reassembly callback: %r'),
            (registry.register_traceflow_tcp_callback, registry.TCP_TraceFlow, 'register_callback',
             'registered TCP flow tracing callback: %r'),
        ]
        for func, target, method, _message in callback_routes:
            with self.subTest(func=func.__name__):
                with mock.patch.object(target, method) as register:
                    func(callback)  # type: ignore[arg-type]
                register.assert_called_once_with(callback)

        with mock.patch.object(registry.Extractor, 'register_reassembly') as register:
            registry.register_extractor_reassembly('ipv4', 'pcapkit.foundation.reassembly',
                                                   'IPv4_Reassembly')
        self.assertEqual(register.call_args.args[0], 'ipv4')
        self.assertIsInstance(register.call_args.args[1], registry.ModuleDescriptor)

        with mock.patch.object(registry.Extractor, 'register_reassembly') as register:
            registry.register_extractor_reassembly('tcp', registry.TCP_Reassembly)
        register.assert_called_once_with('tcp', registry.TCP_Reassembly)

        with mock.patch.object(registry.Extractor, 'register_traceflow') as register:
            registry.register_extractor_traceflow('tcp', registry.TCP_TraceFlow)
        register.assert_called_once_with('tcp', registry.TCP_TraceFlow)

        with mock.patch.object(registry.Extractor, 'register_traceflow') as register:
            registry.register_extractor_traceflow('tcp-string', 'pcapkit.foundation.traceflow',
                                                  'TCP_TraceFlow')
        self.assertIsInstance(register.call_args.args[1], registry.ModuleDescriptor)

    def test_registration_accepts_pcapkit_own_builtin_classes(self) -> None:
        """The built-ins pass the internal ``issubclass`` gate, and non-subclasses still fail.

        This is the regression for GitHub issue #513. Every sibling test in this
        module mocks ``Extractor.register_*`` away, so none of them reaches the
        validation at :file:`pcapkit/foundation/extraction.py` -- which is why the
        defect survived: all three entry points rejected pcapkit's *own* engines,
        reassembly and flow-tracing classes with
        :exc:`~pcapkit.utilities.exceptions.RegistryError`.

        The cause was that each check named the auto-registering public class
        (``Engine``, ``Reassembly``, ``TraceFlow``) while every built-in subclasses
        the ``*Base`` variant -- imported under an alias, e.g.
        ``from ...engine import EngineBase as Engine`` at
        :file:`pcapkit/foundation/engines/pcap.py`, specifically so that it is not
        auto-registered. So ``issubclass(PCAP, Engine)`` was :data:`False` while
        ``issubclass(PCAP, EngineBase)`` was :data:`True`.

        Deliberately does **not** mock, because the point is to exercise the gate.

        """
        # NOTE: GitHub issue #1016 moved this assertion. #513 was fixed by widening the
        # public ``register_*`` guards to the ``*Base`` classes; #1016 narrowed them back
        # to ``Engine``/``Reassembly``/``TraceFlow`` (the registration surface third
        # parties extend), so the public door now refuses the built-ins -- see
        # ``test_public_registration_rejects_base_only_classes`` below. What #513 bought
        # -- that pcapkit's *own* classes are registrable through a real, unmocked gate --
        # is kept by pointing this test at the internal ``Extractor._register_internal_*``
        # path instead of the public wrappers. The subject classes and the read-back
        # are unchanged.
        #
        # NOTE: imported inside the test because ``setUp`` purges ``pcapkit`` from
        # ``sys.modules``, which is why every sibling test imports locally too.
        # ``Extractor`` is needed by name here so the registries can be read back.
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
                    # NOTE: a distinct key per call, so this neither collides with the
                    # built-in registrations already present nor emits the
                    # ``already registered, overwriting`` warning.
                    key = f'unit-513-{name}'
                    func(key, klass)

                    # NOTE: the registry is read back rather than merely asserting that
                    # no exception escaped. Without this, the test passes against a
                    # helper that runs the ``issubclass`` gate and then silently drops
                    # the class -- measured, not hypothetical: inserting a bare
                    # ``return`` after the check and before the registry write leaves
                    # this test reporting ``1 passed, 6 subtests passed``, exit 0.
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
