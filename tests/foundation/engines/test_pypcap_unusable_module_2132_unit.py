"""The pypcap engine falls back when the ``pcap`` module cannot load (#2132).

A ``pcap`` module can be installed and still fail to import with something other
than :exc:`ImportError` -- ``OSError: Cannot find libpcap.so library`` with no
system libpcap, for one. :meth:`Extractor.import_test
<pcapkit.foundation.extraction.Extractor.import_test>` lets that through, so the
engine's ``unsupported_reason()`` has to report it. ``PCAP_CT`` did and ``PyPCAP``
did not, so ``extract(engine='pypcap')`` raised the loader's error where
``engine='pcap_ct'`` warned and fell back. Both ask
:func:`pcapkit.foundation.engines._pcap_backend.engine_reason`.

"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess  # nosec: B404
import sys
import tempfile
import types
import unittest
from unittest import mock

from tests._support import scale_timeout
from tests._tiers import ROOT

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: What the fake ``pcap`` package raises on import: the libpcap loader's message.
LOADER_ERROR = 'Cannot find libpcap.so library'
#: The verdict ``PCAP_CT`` already gave on that failure, which ``PyPCAP`` shares.
REASON = f'the `pcap` module is installed but unusable -- OSError: {LOADER_ERROR}'
#: Hang guard for the child interpreter, in seconds.
TIMEOUT = 120

#: Child script: run one extraction with the fake ``pcap`` first on the path and
#: report, as JSON, which ``pcapkit`` ran, what was warned and what happened.
CHILD = '''
import json, sys, warnings
engine, capture = sys.argv[1], sys.argv[2]
import pcapkit
from pcapkit.foundation.engines.pcap_ct import PCAP_CT
from pcapkit.foundation.engines.pypcap import PyPCAP
result = {
    'pcapkit': pcapkit.__file__,
    'pypcap_reason': PyPCAP.unsupported_reason(),
    'pcap_ct_reason': PCAP_CT.unsupported_reason(),
}
with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter('always')
    try:
        extractor = pcapkit.extract(fin=capture, engine=engine, nofile=True)
    except BaseException as exc:
        result['error'] = f'{type(exc).__name__}: {exc}'
    else:
        result['engine'] = extractor._exnam
        result['frames'] = len(extractor.frame)
result['warnings'] = [f'{w.category.__name__}: {w.message}' for w in caught]
print(json.dumps(result))
'''


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class EngineReasonTests(unittest.TestCase):
    """The shared verdict, and both engines giving it."""

    def probe(self, **overrides):
        from pcapkit.foundation.engines import _pcap_backend

        values = dict(name=None, version=None, origin=None,
                      failure=f'OSError: {LOADER_ERROR}', missing=False, installed=())
        values.update(overrides)
        return _pcap_backend.Probe(**values)

    def test_an_installed_but_unusable_module_is_a_reason_for_either_engine(self) -> None:
        from pcapkit.foundation.engines import _pcap_backend

        for wanted in _pcap_backend.DISTRIBUTIONS:
            with self.subTest(wanted=wanted):
                self.assertEqual(_pcap_backend.engine_reason(wanted, self.probe()), REASON)

    def test_an_absent_module_is_left_to_the_import_test(self) -> None:
        from pcapkit.foundation.engines import _pcap_backend

        found = self.probe(failure='no module named `pcap`', missing=True)
        self.assertIsNone(_pcap_backend.engine_reason(_pcap_backend.PYPCAP, found))

    def test_the_wrong_backend_keeps_its_own_reason(self) -> None:
        from pcapkit.foundation.engines import _pcap_backend

        found = self.probe(name=_pcap_backend.PCAP_CT, version='1.3.0b3',
                           origin='/stub/pcap/__init__.py', failure=None)
        self.assertEqual(_pcap_backend.engine_reason(_pcap_backend.PYPCAP, found),
                         _pcap_backend.wrong_backend_reason(_pcap_backend.PYPCAP, found))

    def broken_import(self):
        from pcapkit.foundation.engines import _pcap_backend

        return (mock.patch('importlib.import_module', side_effect=OSError(LOADER_ERROR)),
                mock.patch.object(_pcap_backend, 'installed_distributions',
                                  return_value=(_pcap_backend.PYPCAP,)))

    def test_pypcap_reports_the_module_that_cannot_load(self) -> None:
        from pcapkit.foundation.engines.pcap_ct import PCAP_CT
        from pcapkit.foundation.engines.pypcap import PyPCAP

        importer, installed = self.broken_import()
        with importer, installed:
            reason = PyPCAP.unsupported_reason()
            peer = PCAP_CT.unsupported_reason()

        self.assertEqual(reason, REASON)
        self.assertEqual(reason, peer)

    def test_pypcap_constructor_refuses_instead_of_raising_the_oserror(self) -> None:
        from pcapkit.foundation.engines.pypcap import PyPCAP
        from pcapkit.utilities.exceptions import UnsupportedCall

        importer, installed = self.broken_import()
        with importer, installed:
            with self.assertRaises(UnsupportedCall) as caught:
                PyPCAP(types.SimpleNamespace())  # type: ignore[arg-type]

        self.assertIn(REASON, str(caught.exception))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class FakePcapPackageTests(unittest.TestCase):
    """End to end, with a real ``pcap`` package on :data:`sys.path` that cannot load.

    Run in a child interpreter so that the fake package never reaches this
    process's :data:`sys.modules` or import caches.

    """

    @classmethod
    def setUpClass(cls) -> None:
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        package = pathlib.Path(tmp.name) / 'pcap'
        package.mkdir()
        (package / '__init__.py').write_text(f'raise OSError({LOADER_ERROR!r})\n')
        cls.site = tmp.name

    def extract(self, engine: str) -> dict:
        env = dict(os.environ)
        env.pop('PYTHONSAFEPATH', None)  # cwd must win, so the tree under test runs
        env['PYTHONPATH'] = os.pathsep.join(
            filter(None, (self.site, env.get('PYTHONPATH'))))
        capture = str(ROOT / 'examples' / 'captures' / 'in.pcap')
        completed = subprocess.run(  # nosec: B603
            [sys.executable, '-c', CHILD, engine, capture],
            cwd=str(ROOT), env=env, capture_output=True, text=True,
            timeout=scale_timeout(TIMEOUT), check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout.strip().splitlines()[-1])
        loaded = os.path.realpath(result['pcapkit'])
        self.assertEqual(os.path.commonpath([loaded, str(ROOT)]), str(ROOT), loaded)
        return result

    def assert_falls_back(self, engine: str, name: str) -> None:
        result = self.extract(engine)

        self.assertNotIn('error', result)
        self.assertEqual(result['engine'], 'default')
        self.assertGreater(result['frames'], 0)
        self.assertIn(f'EngineWarning: engine {name} is not supported on this '
                      f'interpreter ({REASON}); using default engine instead',
                      result['warnings'])

    def test_pcap_ct_falls_back(self) -> None:
        self.assert_falls_back('pcap_ct', 'PCAP_CT')

    def test_pypcap_falls_back_like_pcap_ct(self) -> None:
        self.assert_falls_back('pypcap', 'PyPCAP')

    def test_pypcap_unsupported_reason_names_the_loader_error(self) -> None:
        result = self.extract('pypcap')

        self.assertEqual(result['pypcap_reason'], REASON)
        self.assertEqual(result['pypcap_reason'], result['pcap_ct_reason'])


if __name__ == '__main__':
    unittest.main()
