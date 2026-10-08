# -*- coding: utf-8 -*-
"""PCAP output survives a fallback from an unavailable engine to the default one.

GitHub issue #1264: :class:`~pcapkit.foundation.extraction.Extractor` replaced
``format='pcap'`` with ``'json'`` from the *requested* engine name, before
:meth:`~pcapkit.foundation.extraction.Extractor.run` found the engine missing
and ran the default :class:`~pcapkit.foundation.engines.pcap.PCAP` engine --
which writes PCAP -- so ``out.json`` appeared where ``out.pcap`` was asked for.
The trace format was replaced the same way.

Each engine is made unavailable by patching its own check, so the result does
not depend on what this host has installed: ``unsupported_reason`` covers the
"not supported on this interpreter" path, and ``import_test`` the "not
installed" one.

"""

import contextlib
import importlib.util
import os
import sys
import tempfile
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class, sample_path

#: Every engine whose frames cannot be written as PCAP.
ENGINES = ('dpkt', 'scapy', 'pyshark', 'pypcap', 'pcap_ct', 'pypcapfile')


def _read(path: str) -> bytes:
    with open(path, 'rb') as file:
        return file.read()


class TestEngineFallbackKeepsPCAPOutput(unittest.TestCase):
    """The format check follows the engine that runs, not the one requested."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _engine_class(name: str):
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.foundation.extraction import Extractor

        eng = Extractor.__engine__[name]
        return eng.klass if isinstance(eng, ModuleDescriptor) else eng

    def _unavailable(self, name: str, how: str):
        """Context manager making engine ``name`` unavailable ``how``."""
        klass = self._engine_class(name)
        if how == 'unsupported':
            return mock.patch.object(klass, 'unsupported_reason', return_value='unit test')
        # A ``None`` entry in :data:`sys.modules` makes the import raise
        # :exc:`ImportError`, so the real ``import_test`` runs and warns.
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(klass, 'unsupported_reason', return_value=None))
        stack.enter_context(mock.patch.dict(sys.modules, {klass.module: None}))
        return stack

    def _extract(self, **kwargs):
        from pcapkit.interface import extract

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            extractor = extract(store=False, **kwargs)
        return extractor, [w.message for w in caught]

    def test_pcap_output_is_kept_and_byte_exact(self) -> None:
        from pcapkit.foundation.engines.pcap import PCAP
        from pcapkit.utilities.warnings import EngineWarning, FormatWarning

        fin = sample_path('in.pcap')
        for name in ENGINES:
            for how in ('unsupported', 'not-installed'):
                for fmt in ('pcap', 'cap'):
                    with self.subTest(engine=name, how=how, format=fmt), \
                            tempfile.TemporaryDirectory() as tmp, self._unavailable(name, how):
                        extractor, caught = self._extract(fin=fin, fout=os.path.join(tmp, 'out'),
                                                          format=fmt, engine=name)
                        self.assertIsInstance(extractor.engine, PCAP)
                        self.assertEqual(extractor.format, 'pcap')
                        self.assertEqual(os.listdir(tmp), ['out.pcap'])
                        self.assertEqual(_read(os.path.join(tmp, 'out.pcap')), _read(fin))
                        self.assertEqual([m for m in caught if isinstance(m, FormatWarning)], [])
                        # Settling the engine early must not report it twice.
                        engine_warnings = [str(m) for m in caught if isinstance(m, EngineWarning)]
                        self.assertEqual(len(engine_warnings), 1, engine_warnings)
                        self.assertIn('using default engine instead', engine_warnings[0])

    def test_unknown_engine_keeps_pcap_output(self) -> None:
        from pcapkit.utilities.warnings import EngineWarning

        fin = sample_path('in.pcap')
        with tempfile.TemporaryDirectory() as tmp:
            extractor, caught = self._extract(fin=fin, fout=os.path.join(tmp, 'out'),
                                              format='pcap', engine='no-such-engine')
            self.assertEqual(extractor.format, 'pcap')
            self.assertEqual(_read(os.path.join(tmp, 'out.pcap')), _read(fin))
        self.assertEqual([str(m) for m in caught if isinstance(m, EngineWarning)],
                         ['unsupported extraction engine: no-such-engine; using default engine instead'])

    def test_trace_format_is_kept(self) -> None:
        from pcapkit.utilities.warnings import FormatWarning

        fin = sample_path('in.pcap')
        for name in ('dpkt', 'scapy', 'pyshark', 'pypcapfile'):
            with self.subTest(engine=name), tempfile.TemporaryDirectory() as tmp, \
                    self._unavailable(name, 'unsupported'):
                extractor, caught = self._extract(fin=fin, fout=os.path.join(tmp, 'out'),
                                                  format='json', engine=name, trace=True, tcp=True,
                                                  trace_fout=os.path.join(tmp, 'trace'))
                self.assertEqual([m for m in caught if isinstance(m, FormatWarning)], [])
                flows = extractor.trace.tcp
                self.assertTrue(flows)
                for flow in flows:
                    self.assertTrue(flow.fpout.endswith('.pcap'), flow.fpout)

    def test_available_third_party_engine_still_falls_back_to_json(self) -> None:
        # The other half of the contract: an engine that really runs keeps the
        # existing replacement, and its warning names that engine.
        from pcapkit.utilities.warnings import FormatWarning

        if importlib.util.find_spec('dpkt') is None:
            self.skipTest('dpkt not installed')
        with tempfile.TemporaryDirectory() as tmp:
            extractor, caught = self._extract(fin=sample_path('in.pcap'),
                                              fout=os.path.join(tmp, 'out'), format='pcap', engine='DPKT')
            self.assertEqual(extractor.format, 'json')
            self.assertEqual(os.listdir(tmp), ['out.json'])
        self.assertEqual([str(m) for m in caught if isinstance(m, FormatWarning)],
                         ["'Extractor(engine=dpkt)' does not support 'format=pcap'; "
                          "using 'format=\"json\"' instead"])


if __name__ == '__main__':
    unittest.main()
