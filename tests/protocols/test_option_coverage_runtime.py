# -*- coding: utf-8 -*-
"""The ``options-*.pcap`` fixtures decode, and the octets in them are pcapkit's own.

:file:`examples/generators/options.py` constructs one item of every option-like
code the library registers, and writes the ones that survive a construct ->
parse -> construct cycle into five captures. This module reads them back through
the public extraction interface.

The point is not to re-assert the round trip --
:file:`tests/protocols/test_option_roundtrip_unit.py` does that, and does it
without needing a fixture. The point is that these captures go through the
*whole* stack: the pcap reader, the link and internet layer dispatch, the
option-area walk, and the dumpers. A defect that only shows up once an option is
inside a real frame -- an option area whose length disagrees with the header, a
next-layer lookup that fires on the wrong protocol number -- is invisible to a
direct round trip and lands here.

This module is fixture tier, so it may read generated captures; it is named
``*_runtime.py`` for exactly that reason, and it handles the captures being
absent so that a checkout which has not run ``make samples`` skips rather than
fails. See :mod:`tests._tiers` for the rule.

Every extraction is wrapped in :func:`tests._support.time_limit`. That is not
belt-and-braces: the generator deliberately leaves out the cases whose parse does
not terminate -- ``HOPOPT``'s ``SMF_DPD`` is one -- and this deadline is what
turns a regression that puts one back into a failure rather than a wedged CI run.

"""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from typing import TYPE_CHECKING

from tests._support import close_extractor, purge_modules, time_limit
from tests._tiers import SAMPLE_ROOT

if TYPE_CHECKING:
    from typing import Any, Optional

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Whole seconds one capture may take to extract. The largest of them is a few
#: hundred frames of a few dozen octets, so this is orders of magnitude of slack;
#: it exists for the non-terminating case, not for slowness.
EXTRACT_TIMEOUT = 30

#: The captures, and the outermost protocol chain every frame in each should
#: decode to. Spelled as a prefix rather than the whole chain because the
#: interesting part is that the envelope dispatched to the right layer -- what
#: the option itself decodes to is the round-trip test's business.
CAPTURES = {
    'options-tcp.pcap': 'Ethernet:IPv4:TCP',
    'options-ipv4.pcap': 'Ethernet:IPv4',
    'options-ipv6.pcap': 'Ethernet:IPv6',
    'options-transport.pcap': 'Ethernet:IPv4',
    'options-internet.pcap': 'Ethernet:IPv6',
}


def _capture(name: str) -> 'Optional[str]':
    """Path to a generated option capture, or :data:`None` if it is not there.

    Deliberately not :func:`tests._support.sample_path`: that raises
    :exc:`FileNotFoundError` for a missing capture, and every caller here wants
    to skip instead. The tier guard is satisfied either way, since this module is
    fixture tier and may read a generated capture at all.

    Args:
        name: Bare capture file name.

    Returns:
        The absolute path, or :data:`None` if the capture has not been generated.

    """
    path = SAMPLE_ROOT / name
    return str(path) if path.is_file() else None


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class OptionCoverageCaptureTests(unittest.TestCase):
    """The generated option captures extract cleanly."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_every_option_capture_extracts(self) -> None:
        """Each capture reads back, with every frame reaching its expected layer.

        One subtest per capture, so a single broken fixture names itself rather
        than stopping at the first one.

        """
        import pcapkit

        found = 0
        for name, chain in sorted(CAPTURES.items()):
            path = _capture(name)
            if path is None:
                continue
            found += 1

            with self.subTest(capture=name):
                with time_limit(EXTRACT_TIMEOUT):
                    extractor = pcapkit.extract(fin=path, nofile=True, format='tree',
                                                store=True, ip=True, tcp=True)
                self.addCleanup(close_extractor, extractor)

                self.assertGreater(extractor.length, 0,
                                   f'{name} carries no frames')
                self.assertEqual(len(extractor.frame), extractor.length)

                # ``Extractor.frame`` is annotated as a union that includes the
                # raw ``(timestamp, bytes)`` tuple the ``pcap_ct``-style engines
                # yield; the default engine always gives a protocol object.
                frames = list(extractor.frame)  # type: list[Any]
                for index, frame in enumerate(frames):
                    protochain = str(frame.protochain)
                    self.assertTrue(
                        protochain.startswith(chain),
                        f'{name} frame {index}: expected a {chain} envelope, '
                        f'got {protochain}'
                    )

        if not found:
            self.skipTest(
                'no options-*.pcap fixtures present; run '
                'examples/generators/make_samples.py to build them'
            )

    def test_option_captures_dump_to_tree_and_json(self) -> None:
        """Each capture survives both dumpers, with reassembly turned on.

        The dumpers walk every field of every parsed option, so this reaches
        representation code that extraction alone does not -- a field whose value
        cannot be rendered fails here and nowhere else.

        """
        import pcapkit

        found = 0
        for name in sorted(CAPTURES):
            path = _capture(name)
            if path is None:
                continue
            found += 1

            for fmt, suffix in (('tree', 'txt'), ('json', 'json')):
                with self.subTest(capture=name, format=fmt):
                    with tempfile.TemporaryDirectory() as tmpdir:
                        out = os.path.join(tmpdir, f'{name}.{suffix}')
                        # ``extract`` types ``format`` as a Literal, and a value
                        # read out of a loop is a plain ``str`` to a checker.
                        fmt_arg = fmt  # type: Any
                        with time_limit(EXTRACT_TIMEOUT):
                            extractor = pcapkit.extract(
                                fin=path, fout=out, format=fmt_arg, store=False,
                                ip=True, tcp=True, reassembly=True)
                        self.addCleanup(close_extractor, extractor)
                        self.assertGreater(extractor.length, 0)
                        self.assertTrue(os.path.isfile(out),
                                        f'{fmt} dump of {name} wrote no file')
                        self.assertGreater(os.path.getsize(out), 0,
                                           f'{fmt} dump of {name} is empty')

        if not found:
            self.skipTest('no options-*.pcap fixtures present')

    def test_option_captures_are_what_the_generator_says_they_are(self) -> None:
        """Frame counts match the case table, so a stale fixture is caught.

        A capture regenerated from a different revision of the case table would
        otherwise sit on disk indefinitely and quietly test the wrong thing. The
        count is derived from the same table the generator uses, not written down
        here.

        """
        from tests._tiers import ROOT

        spec = importlib.util.spec_from_file_location(
            'pcapkit_samples_options_runtime',
            ROOT / 'examples' / 'generators' / 'options.py')
        if spec is None or spec.loader is None:  # pragma: no cover
            self.skipTest('cannot load the option case table')
        options = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(options)

        import pcapkit

        expected = {}  # type: dict[str, int]
        for outcome in options.outcomes():
            family = options.FAMILY_MAP[outcome.case.family]
            if family.capture is None or outcome.status not in options.CAPTURABLE:
                continue
            expected[family.capture] = expected.get(family.capture, 0) + 1

        found = 0
        for name, count in sorted(expected.items()):
            path = _capture(name)
            if path is None:
                continue
            found += 1
            with self.subTest(capture=name):
                with time_limit(EXTRACT_TIMEOUT):
                    extractor = pcapkit.extract(fin=path, nofile=True, format='tree',
                                                store=False)
                self.addCleanup(close_extractor, extractor)
                self.assertEqual(
                    extractor.length, count,
                    f'{name} holds {extractor.length} frames but the case table '
                    f'yields {count}; regenerate it with '
                    f'examples/generators/make_samples.py'
                )

        if not found:
            self.skipTest('no options-*.pcap fixtures present')


if __name__ == '__main__':
    unittest.main()
