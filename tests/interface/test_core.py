from __future__ import annotations

import importlib.util
import sys
import types
import unittest
import warnings
from unittest import mock

from tests._support import load_module, purge_modules, sample_path

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)
#: Whether the optional DPKT / Scapy engines can be selected. Both are extras
#: (``pypcapkit[DPKT]`` / ``[Scapy]``), absent from a plain ``[test]`` install.
HAS_DPKT = importlib.util.find_spec('dpkt') is not None
HAS_SCAPY = importlib.util.find_spec('scapy') is not None


class FakeHandle:
    """Stand-in for :class:`pcap.pcap`, yielding ``(timestamp, bytes)`` pairs.

    The engines construct this as ``pcap.pcap(name=..., promisc=False)``, so both
    keywords have to be accepted even though neither is used.
    """

    def __init__(self, name=None, promisc=False) -> None:
        self._iter = iter([(1.5, b'payload')])

    def datalink(self) -> int:
        return 1  # LINKTYPE_ETHERNET

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._iter)

    def close(self) -> None:
        pass


class FakePacket:
    """Stand-in for :class:`pcapfile.structs.pcap_packet`."""

    def __init__(self, header, timestamp, timestamp_us, capture_len, packet_len, packet) -> None:
        self.header = header
        self.timestamp = timestamp
        self.timestamp_us = timestamp_us
        self.capture_len = capture_len
        self.packet_len = packet_len
        self.packet = packet


class FakeSaveFile:
    """Stand-in for :class:`pcapfile.savefile.pcap_savefile`."""

    def __init__(self) -> None:
        self.header = types.SimpleNamespace(ll_type=1, ns_resolution=False)
        self.packets = [FakePacket(None, 1, 500000, 7, 7, b'payload')]


class FakeDecoded:
    """Stand-in for a decoded link layer frame."""

    def __init__(self, packet, layers=0) -> None:
        self.raw = packet
        self.layers = layers
        self.payload = b'decoded-payload'


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
                def __init__(self, strict=False, timeout=None):
                    self.strict = strict
                    self.timeout = timeout
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

        extractor = module.extract(fin=sample_path('in.pcap'), layer=DemoProtocol, store=False)
        self.assertEqual(extractor.kwargs['layer'], 'internet')
        self.assertFalse(extractor.kwargs['store'])

        extractor = module.extract(fin=sample_path('in.pcap'), layer='link', store=True)
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
        # ``None`` is passed straight through, so each reassembler picks its own
        # RFC default rather than having one imposed here
        self.assertIsNone(result.timeout)
        self.assertEqual(module.reassemble('IPv4', timeout=30.0).timeout, 30.0)
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


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class EngineConstantTests(unittest.TestCase):
    """The ``engine=`` constants, and whether each selects the engine it names.

    The constants are only worth having if they *work*, and a wrong one fails
    quietly: :meth:`Extractor.run <pcapkit.foundation.extraction.Extractor.run>`
    answers an unknown engine name with an :class:`EngineWarning
    <pcapkit.utilities.warnings.EngineWarning>` and the default engine, so an
    extraction driven by a misspelled constant still succeeds and still returns
    frames. Every case here therefore asserts on the engine that actually ran.
    """

    #: Constant name in :mod:`pcapkit.interface.core` -> the ``__engine_name__``
    #: of the engine it has to select.
    ENGINES = {
        'PCAPKit': 'PCAP',
        'DPKT': 'DPKT',
        'Scapy': 'Scapy',
        'PyShark': 'PyShark',
        'PyPCAP': 'PyPCAP',
        'PCAP_CT': 'PCAP_CT',
        'PyPCAPFile': 'PyPCAPFile',
    }

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_every_shipped_engine_has_a_constant(self) -> None:
        # The guard against the next engine landing without one. ``'default'`` is the
        # pcapkit-native engine, which Extractor.run handles directly rather than
        # looking up, so it is not a key in the registry; ``'pcapkit'`` is an accepted
        # alias for it and deliberately has no constant of its own.
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.interface import core

        declared = {}
        for name in self.ENGINES:
            self.assertIn(name, core.__all__,
                          f'{name} is not exported from pcapkit.interface.core')
            declared[name] = getattr(core, name)

        self.assertEqual(set(declared.values()), set(Extractor.__engine__) | {'default'},
                         'the engine constants and the engine registry have diverged')

    def test_constants_are_reachable_from_the_package_root(self) -> None:
        # ``pcapkit.DPKT`` has always worked, so ``pcapkit.PyPCAP`` has to as well --
        # a constant that exists only in the submodule is a constant nobody finds.
        # Both re-export lists name their symbols explicitly, so neither picks a new
        # one up on its own.
        import pcapkit
        from pcapkit.interface import core

        for name in self.ENGINES:
            with self.subTest(constant=name):
                for module in (pcapkit, pcapkit.interface):
                    self.assertIn(name, module.__all__,
                                  f'{name} missing from {module.__name__}.__all__')
                    self.assertEqual(getattr(module, name), getattr(core, name))

    def _extract(self, engine: str):
        """A real extraction of the committed capture, driven by ``engine``."""
        import pcapkit

        with warnings.catch_warnings():
            # An engine that cannot run warns and falls back; the caller asserts on
            # which engine ran, so the warning itself is noise here.
            warnings.simplefilter('ignore')
            return pcapkit.extract(fin=sample_path('in.pcap'), engine=engine,
                                   store=True, nofile=True)

    def _assert_selects(self, constant: str) -> None:
        from pcapkit.interface import core

        extraction = self._extract(getattr(core, constant))
        self.assertEqual(type(extraction.engine).__engine_name__, self.ENGINES[constant])

    def test_pcapkit_constant_selects_the_native_engine(self) -> None:
        # ``PCAPKit`` is 'default', which resolves by magic number rather than by
        # registry lookup -- in.pcap is a PCAP savefile, hence the 'PCAP' engine.
        self._assert_selects('PCAPKit')

    @unittest.skipUnless(HAS_DPKT, 'dpkt not installed')
    def test_dpkt_constant_selects_the_dpkt_engine(self) -> None:
        self._assert_selects('DPKT')

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_scapy_constant_selects_the_scapy_engine(self) -> None:
        self._assert_selects('Scapy')

    # NOTE: ``PyShark`` has no selection case of its own. It is covered by the two
    # tests above, but running it needs the :program:`tshark` *binary* as well as the
    # :mod:`pyshark` package, and the engine drives it as a subprocess -- so a
    # stand-in would be a stand-in for the whole extraction rather than for a module,
    # and would stop testing the routing this class is about. Its constant predates
    # this change and its value is asserted against the registry above, which is what
    # a wrong constant would break.

    def _fake_pcap_module(self, *, is_pcap_ct: bool):
        """A stand-in :mod:`pcap` module, as one distribution or the other.

        ``pcap-ct`` ships :mod:`pcap` as a package whose ``__init__`` does
        ``from ._pcap import *``, so the submodule ends up bound as an attribute;
        upstream ``pypcap`` ships a single extension module with no such attribute.
        That difference is what
        :func:`pcapkit.foundation.engines._pcap_backend.identify` keys on, so the
        stand-in only has to reproduce it.

        """
        module = types.ModuleType('pcap')
        module.pcap = FakeHandle                                    # type: ignore[attr-defined]
        module.__version__ = '1.3.0b3' if is_pcap_ct else '1.3.0'   # type: ignore[attr-defined]
        module.__file__ = ('/stub/site-packages/pcap/__init__.py' if is_pcap_ct
                           else '/stub/site-packages/pcap.cpython-310.so')
        modules = {'pcap': module}
        if is_pcap_ct:
            submodule = types.ModuleType('pcap._pcap')
            module._pcap = submodule                                # type: ignore[attr-defined]
            # ``PCAP_CT.__engine_module__`` is 'pcap._pcap', so the import test
            # resolves that name rather than 'pcap'.
            modules['pcap._pcap'] = submodule
        return modules

    def _assert_selects_with_stub_pcap(self, constant: str, *, distribution: str,
                                       is_pcap_ct: bool) -> None:
        """Select a ``pcap``-backed engine against a stand-in for :mod:`pcap`.

        Neither ``pypcap`` nor ``pcap-ct`` is installable everywhere -- upstream
        needs a compiler and 3.11 or older, ``pcap-ct`` needs a system
        :manpage:`libpcap(3)` -- so the routing is asserted against a stand-in.
        The metadata lookup is patched alongside the module because the engines
        decide *which* distribution owns :mod:`pcap` from both.

        """
        from pcapkit.foundation.engines import _pcap_backend

        with mock.patch.dict(sys.modules, self._fake_pcap_module(is_pcap_ct=is_pcap_ct)):
            with mock.patch.object(_pcap_backend, 'installed_distributions',
                                   return_value=(distribution,)):
                self._assert_selects(constant)

    def test_pypcap_constant_selects_the_pypcap_engine(self) -> None:
        self._assert_selects_with_stub_pcap('PyPCAP', distribution='pypcap',
                                            is_pcap_ct=False)

    def test_pcap_ct_constant_selects_the_pcap_ct_engine(self) -> None:
        self._assert_selects_with_stub_pcap('PCAP_CT', distribution='pcap-ct',
                                            is_pcap_ct=True)

    def test_pypcapfile_constant_selects_the_pypcapfile_engine(self) -> None:
        # ``pypcapfile`` 0.12.0 cannot run on Python 3.12+ at all -- its linklayer
        # module imports ``imp`` -- and PyPCAPFile.unsupported_reason refuses the
        # engine there, so the ceiling is lifted for the duration of the routing
        # check. Raising it is what keeps this test meaningful on a modern
        # interpreter; the ceiling itself has its own coverage in
        # tests/foundation/engines/test_pypcapfile_engine.py.
        from pcapkit.foundation.engines.pypcapfile import PyPCAPFile

        package = types.ModuleType('pcapfile')
        savefile = types.ModuleType('pcapfile.savefile')
        savefile.load_savefile = lambda *a, **kw: FakeSaveFile()  # type: ignore[attr-defined]
        linklayer = types.ModuleType('pcapfile.linklayer')
        linklayer.clookup = lambda linktype: FakeDecoded          # type: ignore[attr-defined]
        structs = types.ModuleType('pcapfile.structs')
        structs.pcap_packet = FakePacket                          # type: ignore[attr-defined]

        # Both bindings are needed: ``import pcapfile.savefile`` is satisfied by
        # sys.modules, but the engine then reaches the submodules as *attributes*
        # of the package it stored in ``_expkg``.
        package.savefile = savefile      # type: ignore[attr-defined]
        package.linklayer = linklayer    # type: ignore[attr-defined]
        package.structs = structs        # type: ignore[attr-defined]

        modules = {'pcapfile': package, 'pcapfile.savefile': savefile,
                   'pcapfile.linklayer': linklayer, 'pcapfile.structs': structs}
        with mock.patch.dict(sys.modules, modules):
            with mock.patch.object(PyPCAPFile, 'PYTHON_CEILING', (99, 0)):
                self._assert_selects('PyPCAPFile')


if __name__ == '__main__':
    unittest.main()
