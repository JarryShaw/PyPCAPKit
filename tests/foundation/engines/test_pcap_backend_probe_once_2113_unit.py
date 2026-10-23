# -*- coding: utf-8 -*-
"""An extraction probes the pcap backend once, not three times (#2113).

Engine selection asked ``unsupported_reason`` in the constructor and again in
``run``, and the engine's constructor probed a third time; each probe scans the
installed distributions. The probe is shared within one extraction only, so a
later extraction, or a direct ``unsupported_reason`` call, still asks afresh.

"""

from __future__ import annotations

import importlib.util
import sys
import types
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class, sample_path

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class FakeHandle:
    """Stand-in for :class:`pcap.pcap`, yielding one ``(timestamp, bytes)`` pair."""

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


def fake_pcap_modules(*, is_pcap_ct: bool) -> 'dict[str, types.ModuleType]':
    """A stand-in :mod:`pcap`, shaped as ``pcap-ct`` or as upstream ``pypcap``."""
    module = types.ModuleType('pcap')
    module.pcap = FakeHandle  # type: ignore[attr-defined]
    module.__version__ = '1.3.0b3' if is_pcap_ct else '1.3.0'  # type: ignore[attr-defined]
    module.__file__ = ('/stub/site-packages/pcap/__init__.py' if is_pcap_ct
                       else '/stub/site-packages/pcap.cpython-310.so')
    modules = {'pcap': module}
    if is_pcap_ct:
        submodule = types.ModuleType('pcap._pcap')
        module._pcap = submodule  # type: ignore[attr-defined]
        modules['pcap._pcap'] = submodule
    return modules


@unittest.skipUnless(HAS_RUNTIME, 'pcapkit runtime dependencies are not installed')
class TestProbeOnce(unittest.TestCase):
    """One ``installed_distributions`` scan per extraction through a pcap engine."""

    CASES = (
        ('pypcap', 'PyPCAP', ('pypcap',), False),
        ('pcap_ct', 'PCAP_CT', ('pcap-ct',), True),
    )

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _extract(self, engine: str, installed: 'tuple[str, ...]', is_pcap_ct: bool):
        """Extract ``in.pcap`` with ``engine``; return it, the scan count, and warnings."""
        import pcapkit
        from pcapkit.foundation.engines import _pcap_backend

        with mock.patch.dict(sys.modules, fake_pcap_modules(is_pcap_ct=is_pcap_ct)), \
                mock.patch.object(_pcap_backend, 'installed_distributions',
                                  return_value=installed) as scan, \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            extraction = pcapkit.extract(fin=sample_path('in.pcap'), engine=engine,
                                         store=True, nofile=True)
        return extraction, scan.call_count, [str(w.message) for w in caught]

    def test_one_extraction_probes_once(self) -> None:
        for engine, name, installed, is_pcap_ct in self.CASES:
            with self.subTest(engine=engine):
                extraction, scans, _ = self._extract(engine, installed, is_pcap_ct)
                self.assertEqual(type(extraction.engine).__engine_name__, name)
                self.assertEqual(scans, 1)

    def test_collision_is_still_warned_once(self) -> None:
        # The engine's constructor warns from the shared probe, not a fresh one.
        _, scans, messages = self._extract('pcap_ct', ('pypcap', 'pcap-ct'), True)
        self.assertEqual(scans, 1)
        collisions = [m for m in messages if 'installed together' in m]
        self.assertEqual(len(collisions), 1, messages)
        self.assertTrue(collisions[0].startswith("'Extractor(engine=pcap_ct)': pypcap and "
                                                 'pcap-ct are installed together'))

    def test_probe_is_not_cached_across_extractions(self) -> None:
        from pcapkit.foundation.engines import _pcap_backend
        from pcapkit.foundation.engines.pcap_ct import PCAP_CT

        for _ in range(2):
            self.assertEqual(self._extract('pcap_ct', ('pcap-ct',), True)[1], 1)
        # Outside an extraction the public hook asks afresh every time.
        with mock.patch.dict(sys.modules, fake_pcap_modules(is_pcap_ct=True)), \
                mock.patch.object(_pcap_backend, 'installed_distributions',
                                  return_value=('pcap-ct',)) as scan:
            PCAP_CT.unsupported_reason()
            PCAP_CT.unsupported_reason()
        self.assertEqual(scan.call_count, 2)


if __name__ == '__main__':
    unittest.main()
