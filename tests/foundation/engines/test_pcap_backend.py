"""Unit tests for :mod:`pcapkit.foundation.engines._pcap_backend`.

Two unrelated distributions -- upstream `pypcap`_ and `pcap-ct`_ -- both install a
top-level :mod:`pcap` module, so an engine cannot know which one it got without
asking. This module tests the asking.

Nothing here needs either distribution installed: every case is built from a
stand-in module or a patched import, which is the only way to cover the
combinations that cannot all exist in one environment at once. The combinations
*were* also exercised against real installations -- pcap-ct alone on 3.10 and
3.14, upstream pypcap alone on 3.10, both together on 3.10, neither, and pcap-ct
with no system libpcap -- and the expectations below are what those runs produced.

.. _pypcap: https://github.com/pynetwork/pypcap
.. _pcap-ct: https://pypi.org/project/pcap-ct/

"""
from __future__ import annotations

import importlib.util
import types
import unittest
from unittest import mock

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


def pcap_ct_module():
    """A stand-in for `pcap-ct`_'s :mod:`pcap`, which is a package.

    Its ``__init__`` does ``from ._pcap import *``, so the submodule is bound as
    an attribute -- that binding is the discriminator.

    """
    module = types.ModuleType('pcap')
    module.__version__ = '1.3.0b3'  # type: ignore[attr-defined]
    module.__file__ = '/somewhere/site-packages/pcap/__init__.py'
    module.__path__ = ['/somewhere/site-packages/pcap']  # type: ignore[attr-defined]
    module._pcap = types.ModuleType('pcap._pcap')  # type: ignore[attr-defined]
    return module


def pypcap_module():
    """A stand-in for upstream `pypcap`_'s :mod:`pcap`, a single extension module."""
    module = types.ModuleType('pcap')
    module.__version__ = '1.3.0'  # type: ignore[attr-defined]
    module.__file__ = '/somewhere/site-packages/pcap.cpython-310-x86_64-linux-gnu.so'
    return module


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IdentifyTests(unittest.TestCase):
    def test_identifies_pcap_ct_by_its_submodule_attribute(self) -> None:
        from pcapkit.foundation.engines import _pcap_backend

        self.assertEqual(_pcap_backend.identify(pcap_ct_module()), _pcap_backend.PCAP_CT)

    def test_identifies_upstream_pypcap_by_the_absence_of_it(self) -> None:
        from pcapkit.foundation.engines import _pcap_backend

        self.assertEqual(_pcap_backend.identify(pypcap_module()), _pcap_backend.PYPCAP)

    def test_does_not_key_on_ex_name_which_both_distributions_have(self) -> None:
        from pcapkit.foundation.engines import _pcap_backend

        # Measured on upstream pypcap 1.3.0: ``pcap.ex_name`` is present there
        # too, so it looks like a pcap-ct marker and is not one. Guard against
        # anybody "simplifying" the check to use it.
        upstream = pypcap_module()
        upstream.ex_name = lambda name: name  # type: ignore[attr-defined]
        self.assertEqual(_pcap_backend.identify(upstream), _pcap_backend.PYPCAP)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ProbeTests(unittest.TestCase):
    def probe_with(self, module=None, *, error=None, installed=()):
        """Probe with the ``pcap`` import and the metadata both under control."""
        from pcapkit.foundation.engines import _pcap_backend

        if error is not None:
            target = mock.patch('importlib.import_module', side_effect=error)
        else:
            target = mock.patch('importlib.import_module', return_value=module)

        with mock.patch.object(_pcap_backend, 'installed_distributions',
                               return_value=tuple(installed)):
            with target:
                return _pcap_backend.probe()

    def test_reports_pcap_ct_with_its_version_and_origin(self) -> None:
        from pcapkit.foundation.engines import _pcap_backend

        found = self.probe_with(pcap_ct_module(), installed=('pcap-ct',))
        self.assertEqual(found.name, _pcap_backend.PCAP_CT)
        self.assertEqual(found.version, '1.3.0b3')
        self.assertEqual(found.origin, '/somewhere/site-packages/pcap/__init__.py')
        self.assertIsNone(found.failure)
        self.assertFalse(found.missing)
        self.assertIn('pcap-ct 1.3.0b3', found.describe())

    def test_reports_upstream_pypcap(self) -> None:
        from pcapkit.foundation.engines import _pcap_backend

        found = self.probe_with(pypcap_module(), installed=('pypcap',))
        self.assertEqual(found.name, _pcap_backend.PYPCAP)
        self.assertEqual(found.version, '1.3.0')
        self.assertIn('pypcap 1.3.0', found.describe())

    def test_an_absent_module_is_missing_rather_than_broken(self) -> None:
        found = self.probe_with(error=ImportError("No module named 'pcap'"))

        self.assertIsNone(found.name)
        self.assertTrue(found.missing)
        self.assertIn('pcap', found.failure)

    def test_an_oserror_is_broken_rather_than_missing(self) -> None:
        # The case this distinction exists for: with no system libpcap,
        # ``import pcap`` raises OSError, which is *not* an ImportError, so
        # ``Extractor.import_test`` does not catch it. Recording it as "installed
        # but unusable" is what lets an engine report it instead of dying.
        found = self.probe_with(error=OSError('Cannot find libpcap.so library'),
                                installed=('pcap-ct',))

        self.assertIsNone(found.name)
        self.assertFalse(found.missing)
        self.assertIn('OSError', found.failure)
        self.assertIn('Cannot find libpcap.so library', found.failure)
        self.assertEqual(found.installed, ('pcap-ct',))

    def test_a_failed_probe_leaves_no_residue_for_the_next_one(self) -> None:
        import sys

        from pcapkit.foundation.engines import _pcap_backend

        # Both distributions' package initialisers open with
        # ``from .__about__ import * ; del __about__``, which cannot be re-run: a
        # part-way failure leaves the ``__about__`` submodule cached and the retry
        # dies with ``NameError`` instead of the real cause. Measured, and the
        # reason ``probe`` purges both module trees on failure.
        sys.modules['pcap.__about__'] = types.ModuleType('pcap.__about__')
        sys.modules['libpcap.__about__'] = types.ModuleType('libpcap.__about__')
        self.addCleanup(lambda: [sys.modules.pop(name, None)
                                 for name in ('pcap.__about__', 'libpcap.__about__')])

        with mock.patch.object(_pcap_backend, 'installed_distributions', return_value=()):
            with mock.patch('importlib.import_module',
                            side_effect=OSError('Cannot find libpcap.so library')):
                _pcap_backend.probe()

        self.assertNotIn('pcap.__about__', sys.modules)
        self.assertNotIn('libpcap.__about__', sys.modules)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class InstalledDistributionsTests(unittest.TestCase):
    def installed(self, present):
        import importlib.metadata

        from pcapkit.foundation.engines import _pcap_backend

        def distribution(name):
            if name in present:
                return mock.Mock(version='stub')
            raise importlib.metadata.PackageNotFoundError(name)

        with mock.patch('importlib.metadata.distribution', side_effect=distribution):
            return _pcap_backend.installed_distributions()

    def test_reports_only_what_is_installed_in_a_fixed_order(self) -> None:
        self.assertEqual(self.installed(()), ())
        self.assertEqual(self.installed({'pcap-ct'}), ('pcap-ct',))
        self.assertEqual(self.installed({'pypcap'}), ('pypcap',))
        # order comes from DISTRIBUTIONS, not from the argument, so messages
        # naming both read the same way every time
        self.assertEqual(self.installed({'pcap-ct', 'pypcap'}), ('pypcap', 'pcap-ct'))

    def test_an_unreadable_dist_info_is_treated_as_absent_not_fatal(self) -> None:
        from pcapkit.foundation.engines import _pcap_backend

        # Detection is a courtesy; a corrupt ``dist-info`` must not be able to
        # fail an extraction.
        with mock.patch('importlib.metadata.distribution', side_effect=ValueError('corrupt')):
            self.assertEqual(_pcap_backend.installed_distributions(), ())


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ReasonTests(unittest.TestCase):
    def make_probe(self, **overrides):
        from pcapkit.foundation.engines import _pcap_backend

        values = {
            'name': _pcap_backend.PCAP_CT,
            'version': '1.3.0b3',
            'origin': '/somewhere/pcap/__init__.py',
            'failure': None,
            'missing': False,
            'installed': ('pcap-ct',),
        }
        values.update(overrides)
        return _pcap_backend.Probe(**values)

    def test_wrong_backend_names_the_engine_that_wants_what_is_installed(self) -> None:
        from pcapkit.foundation.engines import _pcap_backend

        reason = _pcap_backend.wrong_backend_reason(_pcap_backend.PYPCAP, self.make_probe())
        self.assertIsNotNone(reason)
        self.assertIn('pcap-ct', reason)
        self.assertIn("engine=pcap_ct", reason)

        reason = _pcap_backend.wrong_backend_reason(
            _pcap_backend.PCAP_CT,
            self.make_probe(name=_pcap_backend.PYPCAP, version='1.3.0'),
        )
        self.assertIsNotNone(reason)
        self.assertIn('pypcap', reason)
        self.assertIn("engine=pypcap", reason)

    def test_the_right_backend_and_an_absent_one_are_both_no_reason(self) -> None:
        from pcapkit.foundation.engines import _pcap_backend

        self.assertIsNone(
            _pcap_backend.wrong_backend_reason(_pcap_backend.PCAP_CT, self.make_probe()))
        # an absent module is the import test's business, not this function's --
        # reporting it here would produce two warnings for one problem
        self.assertIsNone(
            _pcap_backend.wrong_backend_reason(_pcap_backend.PCAP_CT,
                                               self.make_probe(name=None, missing=True)))

    def test_collision_is_reported_only_when_both_are_installed(self) -> None:
        from pcapkit.foundation.engines import _pcap_backend

        self.assertIsNone(_pcap_backend.collision_reason(self.make_probe(installed=())))
        self.assertIsNone(
            _pcap_backend.collision_reason(self.make_probe(installed=('pcap-ct',))))

        reason = _pcap_backend.collision_reason(
            self.make_probe(installed=('pypcap', 'pcap-ct')))
        self.assertIsNotNone(reason)
        self.assertIn('pypcap', reason)
        self.assertIn('pcap-ct', reason)
        # it has to say which one won, since that is what the user cannot see
        self.assertIn('/somewhere/pcap/__init__.py', reason)
        self.assertIn('shadowed', reason)


if __name__ == '__main__':
    unittest.main()
