# -*- coding: utf-8 -*-
"""What #1337 changed in :file:`examples/generators/options.py`.

Two comments there justified code by limitations that no longer hold.

* ``_httpv2_rebuild`` withheld ``flags``, on the grounds that ``HTTP.make``
  ignored it. Since #1341 ``make`` ORs ``flags`` into the bits the frame
  constructor derives, and that constructor knows only the bits its frame type
  defines. So a parsed frame with an undefined flag bit, or the reserved bit,
  lost it on the generator's rebuild although ``HTTP.from_data`` keeps it.
* ``SKIP`` left out TCP ``EOOL`` and ``NOP`` as "dropped by
  ``_make_tcp_options``". Since #1163 that maker emits them as given, so each is
  a distinct header that round-trips, and both now have a case.

This module is unit tier: it builds everything in memory and reads no capture.

"""

from __future__ import annotations

import importlib.util
import sys
import types
import unittest
import warnings

from tests._support import time_limit
from tests._tiers import ROOT

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Parsed HTTP/2 frames whose flags octet or reserved bit the frame constructor
#: cannot derive. Each is ``(label, frame octets)``.
HTTPV2_FRAMES = (
    # DATA defines END_STREAM (0x01) and PADDED (0x08) only.
    ('DATA, undefined flag 0x02', '000003000200000001616263'),
    ('DATA, undefined flag 0x80', '000003008000000001616263'),
    # PING defines ACK (0x01) only.
    ('PING, undefined flag 0x40', '0000080640000000000000000000000000'),
    # WINDOW_UPDATE defines no flags at all.
    ('WINDOW_UPDATE, flag 0x02', '00000408020000000100000000'),
    # The reserved bit is the top bit of the stream identifier.
    ('DATA, reserved bit set', '000003000080000001616263'),
)

#: TCP header octets a TCP padding case must carry after the fixed 20-octet
#: header: the option as given, then alignment to 32 bits.
TCP_PADDING = {
    'End_of_Option_List': '00000000',
    'No_Operation': '01010100',
}


def _load_generator() -> 'types.ModuleType':
    """Load :file:`examples/generators/options.py` by path, under a name of its own.

    Returns:
        The generator module.

    Raises:
        RuntimeError: If the module cannot be found or loaded.

    """
    path = ROOT / 'examples' / 'generators' / 'options.py'
    spec = importlib.util.spec_from_file_location('pcapkit_samples_options_1337', path)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise RuntimeError(f'cannot load the option generator from {path}')

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class OptionGenerator1337Tests(unittest.TestCase):
    """The generator code the stale #1337 comments used to justify."""

    options = None  # type: types.ModuleType

    @classmethod
    def setUpClass(cls) -> None:
        cls.options = _load_generator()

    def test_httpv2_rebuild_keeps_the_flags_octet_and_reserved_bit(self) -> None:
        """A parsed frame rebuilds byte-exact through ``_httpv2_rebuild``."""
        family = self.options.FAMILY_MAP['httpv2-frame']
        for label, hexstr in HTTPV2_FRAMES:
            with self.subTest(frame=label):
                octets = bytes.fromhex(hexstr)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    with time_limit():
                        info = family.extract(family.parse(octets))
                        rebuilt = family.rebuild(info).data
                self.assertEqual(rebuilt.hex(), hexstr)

    def test_tcp_padding_codes_have_cases(self) -> None:
        """``EOOL`` and ``NOP`` are cases, not ``SKIP`` entries."""
        for name in TCP_PADDING:
            with self.subTest(code=name):
                self.assertNotIn(('tcp-option', name), self.options.SKIP)

    def test_tcp_padding_cases_round_trip_as_distinct_headers(self) -> None:
        """Each TCP padding case is ``OK`` and carries its own option octets."""
        family = self.options.FAMILY_MAP['tcp-option']
        cases = {case.name: case for case in self.options.cases((family,))}
        for name, tail in TCP_PADDING.items():
            with self.subTest(code=name):
                self.assertIn(name, cases)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    outcome = self.options.roundtrip(cases[name])
                self.assertEqual(outcome.status, 'OK', outcome.detail)
                self.assertEqual(outcome.octets[20:].hex(), tail)


if __name__ == '__main__':
    unittest.main()
