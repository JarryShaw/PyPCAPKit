"""Unit tests for :mod:`pcapkit.foundation.engines.pcap_ct`.

The engine is exercised with a stand-in for :class:`pcap.pcap`, so that the
routing decisions -- format gating, capability warnings, output, storage, close --
are covered whether or not `pcap-ct`_ is installed. One test at the end runs the
real backend against a committed capture, and skips when it is absent.

`pcap-ct`_ and upstream `pypcap`_ both install a top-level :mod:`pcap`, so the
tests here look almost exactly like :mod:`tests.foundation.engines.test_pypcap_engine`.
The shared bodies live in :mod:`tests.foundation.engines._libpcap_engine`. The two
cases are kept apart because the engines are: each names its own toolkit and its
own module marker, and a shared test could not tell which of the two it had
proved anything about.

.. _pcap-ct: https://pypi.org/project/pcap-ct/
.. _pypcap: https://github.com/pynetwork/pypcap

"""
from __future__ import annotations

import importlib
import types
import unittest
from unittest import mock

from tests._support import close_extractor, sample_path
from tests.foundation.engines._libpcap_engine import HAS_RUNTIME, IteratorHandle, LibpcapEngineMixin

#: Test tier (#1958): drives a third-party engine whose installable releases vary by
#: interpreter.
__tier__ = 'ALL'


def _importable(*modules: str) -> bool:
    """Test if every named module can be imported."""
    for module in modules:
        try:
            importlib.import_module(module)
        except ImportError:
            return False
    return True


#: Whether the `pcap-ct`_ backend is present. Gated on ``pcap._pcap`` rather than
#: on ``pcap``, for the same reason :attr:`PCAP_CT.__engine_module__
#: <pcapkit.foundation.engines.pcap_ct.PCAP_CT.__engine_module__>` names it:
#: upstream `pypcap`_ owns the ``pcap`` name just as legitimately and ships it as
#: a single extension module, so the submodule import is what tells the two
#: distributions apart. Importing rather than :func:`importlib.util.find_spec`,
#: since ``find_spec('pcap._pcap')`` has to import the ``pcap`` parent anyway and
#: raises rather than answering when that parent is not a package.
HAS_PCAP_CT = _importable('pcap._pcap')

#: Frame count of :file:`examples/captures/in.pcap`, and the timestamp and
#: capture length of its first frame. Committed capture, so these are fixed.
IN_PCAP_FRAMES = 6
IN_PCAP_FIRST_TIMESTAMP = 1511106545.471719
IN_PCAP_FIRST_LENGTH = 86


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PCAP_CTEngineTests(LibpcapEngineMixin, unittest.TestCase):
    MODULE = 'pcapkit.foundation.engines.pcap_ct'
    CLASS = 'PCAP_CT'
    OWN_DIST = 'pcap-ct'
    OWN_IS_PCAP_CT = True
    OTHER_DIST = 'pypcap'
    OTHER_ENGINE = 'engine=pypcap'
    OTHER_VERSION = '1.3.0'
    HANDLE = IteratorHandle

    def engine(self, extractor):
        from pcapkit.foundation.engines import _pcap_backend
        from pcapkit.foundation.engines.pcap_ct import PCAP_CT

        # ``__new__`` rather than the constructor: ``PCAP_CT.__init__`` insists on
        # the real ``pcap-ct`` being importable, and these tests are meant to run
        # with neither ``pcap-ct`` nor ``pypcap`` installed. The constructor gets
        # its own tests below, against a stand-in module.
        engine = PCAP_CT.__new__(PCAP_CT)
        engine._expkg = types.SimpleNamespace(pcap=IteratorHandle)
        engine._handle = None
        engine._extmp = None
        engine._dlink = None
        engine._closed = False
        engine._backend = _pcap_backend.Probe(
            _pcap_backend.PCAP_CT, '1.3.0b3', '/stub/site-packages/pcap/__init__.py',
            None, False, ('pcap-ct',),
        )
        engine._extractor = extractor
        return engine

    ##########################################################################
    # unsupported_reason() and __init__(); the rest is in the mixin
    ##########################################################################

    def test_unsupported_reason_reports_a_missing_system_libpcap(self) -> None:
        from pcapkit.foundation.engines.pcap_ct import PCAP_CT

        # The important case, and measured rather than hypothetical: ``pcap-ct``
        # imports the ``libpcap`` distribution, whose Linux loader raises
        # ``OSError: Cannot find libpcap.so library`` when no system libpcap is
        # findable. OSError is not an ImportError, so ``Extractor.import_test``
        # lets it through and the extraction dies. Reporting it here turns that
        # into the ordinary "engine unavailable" fall back.
        with mock.patch('importlib.import_module',
                        side_effect=OSError('Cannot find libpcap.so library')):
            with self.installed('pcap-ct'):
                reason = PCAP_CT.unsupported_reason()

        self.assertIsNotNone(reason)
        self.assertIn('installed but unusable', reason)
        self.assertIn('Cannot find libpcap.so library', reason)

    def test_unsupported_reason_declares_no_python_version_bound(self) -> None:
        from pcapkit.foundation.engines.pcap_ct import PCAP_CT

        # Verified against real installations on 3.10.20 and 3.14.7, both of which
        # read in.pcap identically, so this engine covers the whole supported
        # range and must not refuse either end of it.
        for version in ((3, 10, 0, 'final', 0), (3, 14, 0, 'final', 0)):
            with self.subTest(version=version):
                with mock.patch.dict('sys.modules',
                                     {'pcap': self.fake_pcap_module(is_pcap_ct=True)}):
                    with self.installed('pcap-ct'):
                        with mock.patch('sys.version_info', version):
                            self.assertIsNone(PCAP_CT.unsupported_reason())

    def test_init_accepts_pcap_ct_and_reports_the_backend(self) -> None:
        from pcapkit.foundation.engines.pcap_ct import PCAP_CT

        extractor, _ = self.make_extractor()
        module = self.fake_pcap_module(is_pcap_ct=True)
        with mock.patch.dict('sys.modules', {'pcap': module}):
            with self.installed('pcap-ct'):
                engine = PCAP_CT(extractor)

        self.assertIs(engine._expkg, module)
        self.assertIsNone(engine._handle)
        self.assertFalse(engine._closed)

        self.assertIn('pcap-ct', engine.backend)
        self.assertIn('1.3.0b3', engine.backend)
        self.assertIn('pcap/__init__.py', engine.backend)

    def test_init_warns_when_both_distributions_are_installed(self) -> None:
        from pcapkit.foundation.engines.pcap_ct import PCAP_CT
        from pcapkit.utilities.warnings import EngineWarning

        # This engine still works in that state -- ``pcap-ct`` is the one that wins
        # the import -- so it warns and carries on rather than refusing.
        extractor, _ = self.make_extractor()
        with mock.patch.dict('sys.modules', {'pcap': self.fake_pcap_module(is_pcap_ct=True)}):
            with self.installed('pypcap', 'pcap-ct'):
                with mock.patch('pcapkit.foundation.engines.pcap_ct.warn') as warn, \
                        mock.patch('pcapkit.foundation.engines.engine.warn', warn):
                    engine = PCAP_CT(extractor)

        collisions = [call.args[0] for call in warn.call_args_list
                      if len(call.args) > 1 and call.args[1] is EngineWarning]
        self.assertEqual(len(collisions), 1, warn.call_args_list)
        self.assertIn('pypcap', collisions[0])
        self.assertIn('pcap-ct', collisions[0])
        self.assertIn('shadowed', collisions[0])
        self.assertIn('pcap-ct', engine.backend)

    ##########################################################################
    # run()
    ##########################################################################

    def test_run_opens_handle_and_records_link_type(self) -> None:
        from pcapkit.const.reg.linktype import LinkType

        extractor, _ = self.make_extractor()
        engine = self.engine(extractor)

        handle = IteratorHandle()
        with mock.patch.object(engine._expkg, 'pcap', return_value=handle) as ctor:
            engine.run()

        ctor.assert_called_once_with(name=self.ifnm, promisc=False)
        self.assertEqual(engine.dlink, LinkType.ETHERNET)

        # the handle and the iterator are held separately, and it is the iterator
        # that frames are read through
        self.assertIs(engine._handle, handle)
        self.assertEqual(handle.setup, 1)
        self.assertIs(engine._extmp, handle.iterator)
        self.assertIsNot(engine._extmp, handle)
        self.assertEqual(next(engine._extmp), (1.5, b'payload'))

    ##########################################################################
    # close()
    ##########################################################################

    def test_close_is_idempotent_and_tolerates_an_unopened_engine(self) -> None:
        extractor, _, engine = self.prepared()
        handle = engine._handle

        engine.close()
        engine.close()
        self.assertEqual(handle.closed, 1)
        # the savefile belongs to the handle, not to the iterator read off it
        self.assertEqual(handle.iterator.closed, 0)

        extractor, _ = self.make_extractor()
        unopened = self.engine(extractor)
        unopened.close()  # must not raise

    ##########################################################################
    # The real backend.
    ##########################################################################

    @unittest.skipUnless(HAS_PCAP_CT, 'pcap-ct not installed')
    def test_the_real_backend_reads_a_committed_capture(self) -> None:
        from pcapkit.foundation.engines.pcap_ct import PCAP_CT
        from pcapkit.interface import extract
        from pcapkit.utilities.warnings import EngineWarning

        with mock.patch('pcapkit.foundation.extraction.warn') as warn:
            extractor = extract(fin=sample_path('in.pcap'), engine='pcap_ct', store=True)
        self.addCleanup(close_extractor, extractor)

        # A missing engine module only warns and falls back to pcapkit's own
        # parser, so a successful extraction proves nothing on its own -- it is the
        # absence of that warning, plus the engine on the extractor, that
        # says this ran through ``pcap-ct``.
        engines = [call.args[0] for call in warn.call_args_list
                   if len(call.args) > 1 and call.args[1] is EngineWarning]
        self.assertEqual(engines, [], "'pcap_ct' was replaced by the fallback engine")
        self.assertEqual(extractor._exnam, 'pcap_ct')
        self.assertIsInstance(extractor.engine, PCAP_CT)
        self.assertEqual(type(extractor.engine).__engine_name__, 'PCAP_CT')

        self.assertEqual(extractor.length, IN_PCAP_FRAMES)
        self.assertEqual(len(extractor.frame), IN_PCAP_FRAMES)

        # a fallback would have produced ``Frame`` objects, not bare pairs
        timestamp, packet = extractor.frame[0]
        self.assertEqual(timestamp, IN_PCAP_FIRST_TIMESTAMP)
        self.assertEqual(len(packet), IN_PCAP_FIRST_LENGTH)


if __name__ == '__main__':
    unittest.main()
