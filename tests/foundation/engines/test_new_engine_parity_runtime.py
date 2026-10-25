"""End-to-end runs of the ``pypcap`` and ``pypcapfile`` engines.

:class:`~pcapkit.foundation.extraction.Extractor` falls back to its own parser
with an :class:`~pcapkit.utilities.warnings.EngineWarning` when the engine module
is missing, so a test of an engine passes most loudly when the engine under test
never ran at all. Every test here therefore proves the engine ran first -- by the
recorded engine name, the engine class, and the absence of any
:class:`~pcapkit.utilities.warnings.EngineWarning` -- and only then checks what
it reports.

This module is named ``*_runtime.py`` deliberately, which puts it in the
fixture-dependent tier (see :mod:`tests._tiers`). It reads ``tcp.pcap``,
``ipv6.pcap`` and ``test.pcapng``, none of which git tracks --
:file:`examples/generators/make_samples.py` writes them -- so it cannot be
unit-tier. The static half of the guard from GitHub pull request #393 cannot see
that: the reads go through ``sample_path(capture)`` with a *variable*, which only
the runtime half catches, and that half is never reached on a machine where the
engine packages are absent and every test skips.

"""
from __future__ import annotations

import importlib
import importlib.util
import unittest
from unittest import mock

from tests._support import close_extractor, reimport_once_per_class, sample_path

#: Test tier (#1958): its engines install below Python 3.12 only, so the parity legs,
#: none of them latest, are where it runs.
__tier__ = 'ALL'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


def _importable(*modules: str) -> bool:
    """Test if every named module can actually be imported.

    :func:`importlib.util.find_spec` is not enough for ``pypcapfile``: its released
    0.12.0 imports the :mod:`imp` module, removed in Python 3.12, so it can be
    installed and still unusable.

    """
    for module in modules:
        try:
            importlib.import_module(module)
        except ImportError:
            return False
    return True


#: Whether upstream ``pypcap`` is installed, as opposed to ``pcap-ct``.
#:
#: Both distributions own the top-level :mod:`pcap` name, so ``_importable('pcap')``
#: alone is not the question these tests want to ask: ``pcap-ct`` is driven by
#: :class:`~pcapkit.foundation.engines.pcap_ct.PCAP_CT` and
#: :class:`~pcapkit.foundation.engines.pypcap.PyPCAP` refuses it outright, so
#: letting it satisfy this gate would run the ``pypcap`` tests against an engine
#: that declines to start. ``pcap-ct`` ships :mod:`pcap` as a package whose
#: ``__init__`` does ``from ._pcap import *``; upstream ships a single extension
#: module, which has no such submodule.
HAS_PYPCAP = _importable('pcap') and not _importable('pcap._pcap')
HAS_PYPCAPFILE = _importable('pcapfile.savefile', 'pcapfile.linklayer')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class NewEngineParityTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def extract(self, engine: str, capture: str, **kwargs):
        """Extract a capture, asserting that the requested engine really ran.

        Returns the extractor, having checked that
        :class:`~pcapkit.foundation.extraction.Extractor` neither rewrote the engine
        name nor warned about the engine being unavailable -- i.e. that the result
        is not the built-in parser wearing the requested engine's label.

        """
        from pcapkit.interface import extract
        from pcapkit.utilities.warnings import EngineWarning

        with mock.patch('pcapkit.foundation.extraction.warn') as warn:
            extractor = extract(fin=sample_path(capture), fout='/tmp/parity-out',
                                format='tree', store=True, nofile=True, engine=engine,
                                **kwargs)
        self.addCleanup(close_extractor, extractor)

        engines = [call.args[0] for call in warn.call_args_list
                   if len(call.args) > 1 and call.args[1] is EngineWarning]
        self.assertEqual(engines, [], f'{engine!r} was replaced by the fallback engine')
        self.assertEqual(extractor._exnam, engine)
        return extractor

    ##########################################################################
    # Proof that the engine ran.
    ##########################################################################

    @unittest.skipUnless(HAS_PYPCAP, 'pypcap not installed')
    def test_pypcap_engine_really_ran(self) -> None:
        from pcapkit.foundation.engines.pypcap import PyPCAP

        extractor = self.extract('pypcap', 'in.pcap')
        self.assertIsInstance(extractor.engine, PyPCAP)
        self.assertEqual(extractor.engine.name, 'PyPCAP')
        self.assertEqual(extractor.engine.module, 'pcap')
        # a fallback would have produced ``Frame`` objects, not bare tuples
        for frame in extractor.frame:
            self.assertIsInstance(frame, tuple)
            self.assertEqual(len(frame), 2)

    @unittest.skipUnless(HAS_PYPCAPFILE, 'pypcapfile not installed')
    def test_pypcapfile_engine_really_ran(self) -> None:
        from pcapfile.structs import pcap_packet

        from pcapkit.foundation.engines.pypcapfile import PyPCAPFile

        extractor = self.extract('pypcapfile', 'in.pcap')
        self.assertIsInstance(extractor.engine, PyPCAPFile)
        self.assertEqual(extractor.engine.name, 'PyPCAPFile')
        self.assertEqual(extractor.engine.module, 'pcapfile')
        for frame in extractor.frame:
            self.assertIsInstance(frame, pcap_packet)

    ##########################################################################
    # Capability gaps, asserted rather than described.
    ##########################################################################

    @unittest.skipUnless(HAS_PYPCAPFILE, 'pypcapfile not installed')
    def test_pypcapfile_reports_no_ipv6_reassembly(self) -> None:
        engine = self.extract('pypcapfile', 'ipv6.pcap', reassembly=True, ip=True)
        self.assertIsNone(engine.reassembly.ipv6)
        # ...whereas the default engine does reassemble it
        base = self.extract('default', 'ipv6.pcap', reassembly=True, ip=True)
        self.assertTrue(base.reassembly.ipv6)

    @unittest.skipUnless(HAS_PYPCAP, 'pypcap not installed')
    def test_pypcap_reports_neither_reassembly_nor_flow_tracing(self) -> None:
        from pcapkit.utilities.exceptions import UnsupportedCall

        engine = self.extract('pypcap', 'tcp.pcap', reassembly=True, ip=True, tcp=True,
                              trace=True)
        with self.assertRaises(UnsupportedCall):
            engine.reassembly  # pylint: disable=pointless-statement
        with self.assertRaises(UnsupportedCall):
            engine.trace  # pylint: disable=pointless-statement

    ##########################################################################
    # PCAP-NG.
    ##########################################################################

    @unittest.skipUnless(HAS_PYPCAP, 'pypcap not installed')
    def test_pypcap_rejects_pcapng_rather_than_reporting_zero_frames(self) -> None:
        from pcapkit.utilities.exceptions import FormatError

        # libpcap opens a PCAP-NG savefile without complaint and then yields no
        # frames at all, which would look like an empty capture; the engine gates
        # on the magic number so that it looks like an error instead.
        with self.assertRaises(FormatError):
            self.extract('pypcap', 'test.pcapng')

    @unittest.skipUnless(HAS_PYPCAPFILE, 'pypcapfile not installed')
    def test_pypcapfile_rejects_pcapng(self) -> None:
        from pcapkit.utilities.exceptions import FormatError

        with self.assertRaises(FormatError):
            self.extract('pypcapfile', 'test.pcapng')


if __name__ == '__main__':
    unittest.main()
