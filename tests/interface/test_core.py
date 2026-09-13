from __future__ import annotations

import unittest

from tests._support import load_module, purge_modules


class InterfaceCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _load_module(self):
        import sys
        import types

        foundation_extraction = types.ModuleType('pcapkit.foundation.extraction')

        class Extractor:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        foundation_extraction.Extractor = Extractor
        sys.modules['pcapkit.foundation.extraction'] = foundation_extraction

        def make_reassembly(name):
            class Reassembly:
                def __init__(self, strict=False):
                    self.strict = strict
            Reassembly.__name__ = name
            return Reassembly

        def make_trace(name):
            class TraceFlow:
                def __init__(self, **kwargs):
                    self.kwargs = kwargs
            TraceFlow.__name__ = name
            return TraceFlow

        for module_name, attr_name, klass in [
            ('pcapkit.foundation.reassembly.ipv4', 'IPv4', make_reassembly('IPv4')),
            ('pcapkit.foundation.reassembly.ipv6', 'IPv6', make_reassembly('IPv6')),
            ('pcapkit.foundation.reassembly.tcp', 'TCP', make_reassembly('TCP')),
            ('pcapkit.foundation.traceflow.tcp', 'TCP', make_trace('TCP')),
        ]:
            module = types.ModuleType(module_name)
            setattr(module, attr_name, klass)
            sys.modules[module_name] = module

        protocol_module = types.ModuleType('pcapkit.protocols.protocol')

        class ProtocolBase:
            __layer__ = 'transport'

            @classmethod
            def id(cls):
                return (cls.__name__,)

        protocol_module.ProtocolBase = ProtocolBase
        sys.modules['pcapkit.protocols.protocol'] = protocol_module

        exceptions = load_module('pcapkit.utilities.exceptions', 'pcapkit/utilities/exceptions.py')
        sys.modules['pcapkit.utilities.exceptions'] = exceptions

        return load_module('pcapkit.interface.core', 'pcapkit/interface/core.py'), ProtocolBase

    def test_extract_converts_protocol_type_layer(self) -> None:
        module, ProtocolBase = self._load_module()

        class DemoProtocol(ProtocolBase):
            __layer__ = 'internet'

        extractor = module.extract(fin='sample/in.pcap', layer=DemoProtocol, store=False)
        self.assertEqual(extractor.kwargs['layer'], 'internet')
        self.assertFalse(extractor.kwargs['store'])

        extractor = module.extract(fin='sample/in.pcap', layer='link', store=True)
        self.assertEqual(extractor.kwargs['layer'], 'link')
        self.assertTrue(extractor.kwargs['store'])

    def test_reassemble_dispatches_supported_protocols(self) -> None:
        module, ProtocolBase = self._load_module()

        class TCP(ProtocolBase):
            @classmethod
            def id(cls):
                return ('TCP',)

        result = module.reassemble(TCP, strict=True)
        self.assertEqual(type(result).__name__, 'TCP')
        self.assertTrue(result.strict)
        self.assertEqual(type(module.reassemble('IPv4')).__name__, 'IPv4')
        self.assertEqual(type(module.reassemble('IPv6')).__name__, 'IPv6')

    def test_trace_dispatches_supported_protocols(self) -> None:
        module, ProtocolBase = self._load_module()
        result = module.trace('TCP', fout='out.pcap', format='pcap')
        self.assertEqual(type(result).__name__, 'TCP')
        self.assertEqual(result.kwargs['fout'], 'out.pcap')

        class TCP(ProtocolBase):
            @classmethod
            def id(cls):
                return ('TCP',)

        result = module.trace(TCP, fout='class.pcap', format='pcap')
        self.assertEqual(type(result).__name__, 'TCP')
        self.assertEqual(result.kwargs['fout'], 'class.pcap')

    def test_interface_package_re_exports_core_symbols(self) -> None:
        module, _ = self._load_module()
        package = load_module('pcapkit.interface', 'pcapkit/interface/__init__.py')

        self.assertIs(package.extract, module.extract)
        self.assertEqual(package.PCAP, 'pcap')
        self.assertIn('trace', package.__all__)

    def test_unsupported_protocols_raise_format_error(self) -> None:
        module, _ = self._load_module()
        with self.assertRaises(module.FormatError):
            module.reassemble('UDP')
        with self.assertRaises(module.FormatError):
            module.trace('UDP', fout=None, format=None)


if __name__ == '__main__':
    unittest.main()
