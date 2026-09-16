"""Unit tests for :class:`pcapkit.foundation.engines.scapy.Scapy`'s import contract.

`Scapy`_ builds its dissection tables as *import side effects* of its layer
modules. Two matter here, and neither is populated by ``scapy/__init__.py``:

* ``conf.l2types`` maps a capture's link type onto a link-layer class. Without it
  :class:`~scapy.utils.PcapReader` cannot tell what it is reading, writes
  ``unknown LL type [1]/[0x1]`` to stderr and returns each frame as one opaque
  :class:`~scapy.packet.Raw` layer.
* the ``bind_layers`` table maps each layer onto its payload. Without it a frame
  dissects down as far as the loaded modules reach and then stops at ``Raw``.

So this engine's *import statement* is load-bearing in a way an engine's usually
is not, and #406 is what happens when it is wrong: the engine imported only
:mod:`scapy.sendrecv`, and every frame of every capture came back as ``Raw`` --
no exception, no :mod:`pcapkit` warning, and a stderr line from `Scapy`_ that a
library consumer never sees. ``follow_tcp_stream`` quietly reported no streams.

**Why these tests use a subprocess.** The tables live on `Scapy`_'s process-wide
``conf`` singleton, and once any module has populated them they stay populated: no
public API resets them, and ``sys.modules`` surgery does not un-run a
``bind_layers`` call. So an in-process assertion here would pass whenever
something earlier in the run had imported a `Scapy`_ layer -- which is exactly
what happened before #406 was found. :mod:`tests.toolkit.test_scapy_unit` imports
:mod:`scapy.layers.l2`, :mod:`~scapy.layers.inet` and :mod:`~scapy.layers.inet6`
to build its fixtures, so ``pytest tests/toolkit tests/interface/test_misc.py``
saw correct dissection while ``pytest tests/interface/test_misc.py`` alone did
not. A fresh interpreter is the only place the engine's own import can be held
responsible for the outcome, so that is where it is asserted.

The end-to-end behaviour these guard is asserted through the public interface in
:meth:`tests.interface.test_misc.FollowTCPStreamTests.test_scapy_engine_matches_the_default_engine`;
this module pins the cause rather than the symptom.

.. _Scapy: https://scapy.net

"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import unittest

from tests._support import sample_path

#: Repository root, which the child interpreter needs on :data:`sys.path` to
#: import the :mod:`pcapkit` under test rather than an installed copy.
ROOT = pathlib.Path(__file__).resolve().parents[3]

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)
HAS_SCAPY = importlib.util.find_spec('scapy') is not None

#: Marker the child prefixes its one JSON line with. `Scapy`_ writes to stderr on
#: an unmapped link type and :mod:`pcapkit` warns on EOF, so the result is picked
#: out by prefix rather than by assuming a clean stream.
RESULT = '@@RESULT@@'

#: Run in a fresh interpreter, with nothing imported that could have populated
#: `Scapy`_'s tables beforehand. Reports what the engine produced *and* what the
#: link-type table looked like afterwards, so a failure distinguishes "the engine
#: did not import enough" from "the capture is not what the test thinks".
CHILD = f'''
import json, sys, warnings

sys.path.insert(0, {str(ROOT)!r})
warnings.simplefilter('ignore')

import pcapkit

extractor = pcapkit.extract(fin=sys.argv[1], engine='scapy', store=True, nofile=True)

# Imported only now, and from ``scapy.config`` rather than ``scapy.all``, so that
# reading the table cannot be what filled it in.
from scapy.config import conf

print({RESULT!r} + json.dumps({{
    'frames': [type(frame).__name__ for frame in extractor.frame],
    'chain': extractor.frame[0].summary(),
    'has_tcp': any(frame.haslayer('TCP') for frame in extractor.frame),
    'l2types': len(conf.l2types.num2layer),
    'dlt1': getattr(conf.l2types.num2layer.get(1), '__name__', None),
}}))
'''


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
@unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
class ScapyLayerRegistryTests(unittest.TestCase):
    """What the Scapy engine dissects in an interpreter it did not warm up."""

    def dissect(self, capture: str) -> dict:
        """Extract ``capture`` with the Scapy engine in a fresh interpreter.

        Args:
            capture: Absolute path to the capture to read.

        Returns:
            The child's decoded report -- frame class names, frame 0's protocol
            chain, whether any frame holds a TCP layer, and the size and DLT-1
            entry of `Scapy`_'s link-type table.

        """
        completed = subprocess.run(
            [sys.executable, '-c', CHILD, capture],
            capture_output=True, text=True, timeout=300, check=False,
        )
        self.assertEqual(
            completed.returncode, 0,
            f'child interpreter failed\nstdout:\n{completed.stdout}\n'
            f'stderr:\n{completed.stderr}',
        )
        for line in completed.stdout.splitlines():
            if line.startswith(RESULT):
                return json.loads(line[len(RESULT):])
        self.fail(f'child printed no result line\nstdout:\n{completed.stdout}\n'
                  f'stderr:\n{completed.stderr}')

    def test_engine_populates_the_link_type_table_by_itself(self) -> None:
        # The engine's own import has to be sufficient. Asserted on the table
        # rather than on the frames so that a regression names its cause: an empty
        # ``l2types`` is the missing import, nothing else.
        report = self.dissect(sample_path('in.pcap'))

        self.assertGreater(
            report['l2types'], 0,
            "scapy's conf.l2types was empty after the engine ran, so the engine "
            'imported no layer module -- see #406: it must import scapy.all',
        )
        self.assertEqual(
            report['dlt1'], 'Ether',
            'link type 1 (Ethernet) did not map to scapy.layers.l2.Ether, so '
            'PcapReader cannot dissect even an ordinary Ethernet capture',
        )

    def test_frames_are_dissected_not_returned_as_raw(self) -> None:
        # in.pcap is six Ethernet frames: two ICMPv6 neighbour-discovery, three
        # TCP, one UDP. Under #406 all six came back as ``Raw``.
        report = self.dissect(sample_path('in.pcap'))

        self.assertNotIn(
            'Raw', report['frames'],
            f"scapy returned undissected Raw frames from in.pcap: {report['frames']} "
            '-- the layer registry was not populated; see #406',
        )
        self.assertEqual(report['frames'], ['Ether'] * 6)
        self.assertTrue(report['chain'].startswith('Ether / IPv6 / ICMPv6ND_NS'),
                        f"unexpected chain for frame 0: {report['chain']}")
        self.assertTrue(report['has_tcp'],
                        'no TCP layer found, though in.pcap holds three TCP frames')


if __name__ == '__main__':
    unittest.main()
