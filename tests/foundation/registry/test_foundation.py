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


if __name__ == '__main__':
    unittest.main()
