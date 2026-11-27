"""Unit tests for :mod:`pcapkit.foundation.engines.pypcap`.

The engine itself is exercised with a stand-in for :class:`pcap.pcap`, so that the
routing decisions -- format gating, capability warnings, output, storage, close --
are covered whether or not `pypcap`_ is installed. The bodies shared with
:mod:`tests.foundation.engines.test_pcap_ct_engine` live in
:mod:`tests.foundation.engines._libpcap_engine`. End-to-end agreement with the
``default`` engine lives in :mod:`tests.foundation.engines.test_new_engine_parity_runtime`.

.. _pypcap: https://github.com/pynetwork/pypcap

"""
from __future__ import annotations

import types
import unittest
from unittest import mock

from tests.foundation.engines._libpcap_engine import HAS_RUNTIME, FakeHandle, LibpcapEngineMixin

#: Test tier (#1958): drives a third-party engine whose installable releases vary by
#: interpreter.
__tier__ = 'ALL'


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PyPCAPEngineTests(LibpcapEngineMixin, unittest.TestCase):
    MODULE = 'pcapkit.foundation.engines.pypcap'
    CLASS = 'PyPCAP'
    OWN_DIST = 'pypcap'
    OWN_IS_PCAP_CT = False
    OTHER_DIST = 'pcap-ct'
    OTHER_ENGINE = 'engine=pcap_ct'
    OTHER_VERSION = '1.3.0b3'
    HANDLE = FakeHandle

    def engine(self, extractor):
        from pcapkit.foundation.engines.pypcap import PyPCAP

        engine = PyPCAP.__new__(PyPCAP)
        engine._expkg = types.SimpleNamespace(pcap=FakeHandle)
        engine._extmp = None
        engine._dlink = None
        engine._closed = False
        engine._extractor = extractor
        return engine

    ##########################################################################
    # unsupported_reason() and __init__(); the rest is in the mixin
    ##########################################################################

    def test_unsupported_reason_is_not_a_python_version_check(self) -> None:
        from pcapkit.foundation.engines.pypcap import PyPCAP

        # Upstream cannot be *installed* on 3.12+, but the verdict is about which
        # distribution is present rather than which interpreter is running: an
        # upstream build that somebody got working on a newer Python must not be
        # refused, and on 3.10/3.11 the version says nothing useful because either
        # distribution could be the one in place.
        with mock.patch.dict('sys.modules', {'pcap': self.fake_pcap_module(is_pcap_ct=False)}):
            with self.installed('pypcap'):
                with mock.patch('sys.version_info', (3, 14, 0, 'final', 0)):
                    self.assertIsNone(PyPCAP.unsupported_reason())

    def test_init_accepts_upstream_pypcap_and_reports_the_backend(self) -> None:
        from pcapkit.foundation.engines.pypcap import PyPCAP

        extractor, _ = self.make_extractor()
        module = self.fake_pcap_module(is_pcap_ct=False)
        with mock.patch.dict('sys.modules', {'pcap': module}):
            with self.installed('pypcap'):
                engine = PyPCAP(extractor)

        self.assertIs(engine._expkg, module)
        self.assertIsNone(engine._extmp)
        self.assertFalse(engine._closed)

        # "the PyPCAP engine" is not a complete statement of what ran, since two
        # distributions answer to it -- ``backend`` says which one did
        self.assertIn('pypcap', engine.backend)
        self.assertIn('1.3.0', engine.backend)
        self.assertIn('pcap.cpython-310.so', engine.backend)

    def test_init_warns_when_both_distributions_are_installed(self) -> None:
        from pcapkit.foundation.engines.pypcap import PyPCAP
        from pcapkit.utilities.exceptions import UnsupportedCall
        from pcapkit.utilities.warnings import EngineWarning

        # Measured on Python 3.10 with both installed: the ``pcap-ct`` package
        # wins the import and upstream's extension module is shadowed, so this
        # engine becomes permanently unselectable. Nothing else would say why.
        extractor, _ = self.make_extractor()
        with mock.patch.dict('sys.modules', {'pcap': self.fake_pcap_module(is_pcap_ct=True)}):
            with self.installed('pypcap', 'pcap-ct'):
                with mock.patch('pcapkit.foundation.engines.pypcap.warn') as warn, \
                        mock.patch('pcapkit.foundation.engines.engine.warn', warn):
                    with self.assertRaises(UnsupportedCall):
                        PyPCAP(extractor)

        collisions = [call.args[0] for call in warn.call_args_list
                      if len(call.args) > 1 and call.args[1] is EngineWarning]
        self.assertEqual(len(collisions), 1, warn.call_args_list)
        self.assertIn('pypcap', collisions[0])
        self.assertIn('pcap-ct', collisions[0])
        self.assertIn('shadowed', collisions[0])

    ##########################################################################
    # run()
    ##########################################################################

    def test_run_opens_handle_and_records_link_type(self) -> None:
        from pcapkit.const.reg.linktype import LinkType

        extractor, _ = self.make_extractor()
        engine = self.engine(extractor)

        handle = FakeHandle()
        with mock.patch.object(engine._expkg, 'pcap', return_value=handle) as ctor:
            engine.run()

        ctor.assert_called_once_with(name=self.ifnm, promisc=False)
        self.assertIs(engine._extmp, handle)
        self.assertEqual(handle.setup, 1)
        self.assertEqual(engine.dlink, LinkType.ETHERNET)

    ##########################################################################
    # close()
    ##########################################################################

    def test_close_is_idempotent_and_tolerates_an_unopened_engine(self) -> None:
        extractor, _, engine = self.prepared()
        handle = engine._extmp

        engine.close()
        engine.close()
        self.assertEqual(handle.closed, 1)

        extractor, _ = self.make_extractor()
        unopened = self.engine(extractor)
        unopened.close()  # must not raise


if __name__ == '__main__':
    unittest.main()
