# -*- coding: utf-8 -*-
"""The generator's HTTP/2 frames decode as HTTP/2. C.f. #1156.

:file:`examples/captures/options-transport.pcap` carries one TCP segment to port
80 per HTTP/2 frame type, built by ``_httpv2_build`` in
:file:`examples/generators/options.py`. That function put every frame on stream
0. :rfc:`9113#section-6` makes ``DATA``, ``HEADERS``, ``PRIORITY``,
``RST_STREAM``, ``PUSH_PROMISE`` and ``CONTINUATION`` on stream 0 a connection
error, and since #1153 :meth:`HTTP._guess_version
<pcapkit.protocols.application.http.HTTP._guess_version>` declines a frame no
conforming sender writes, so six of the ten segments decoded as ``TCP:Raw``.
:mod:`tests.protocols.test_option_coverage_runtime` checks only the
``Ethernet:IPv4`` prefix, so nothing noticed.

:data:`EXPECTED_STREAM` spells each type's stream out rather than reading it from
the generator, so a wrong generator constant fails here as ``0 != 1``.

This module is unit tier: it builds its segments in memory from the generator's
own cases and reads no capture, so it runs on a fresh checkout.

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

#: A 20-octet TCP header, data offset 5, ACK set, from port 50000 to port 80 --
#: the ports ``_frame`` gives the ``tcp`` envelope.
_TCP_TO_80 = bytes.fromhex('c350005000000001000000015010ffff00000000')

#: Frame type -> whether :rfc:`9113#section-6` puts it on a non-zero stream
#: (``True``) or on stream 0 (``False``). ``WINDOW_UPDATE`` may use either; the
#: generator puts it on a stream.
EXPECTED_STREAM = {
    0x0: True,    # DATA (Section 6.1)
    0x1: True,    # HEADERS (Section 6.2)
    0x2: True,    # PRIORITY (Section 6.3)
    0x3: True,    # RST_STREAM (Section 6.4)
    0x4: False,   # SETTINGS (Section 6.5)
    0x5: True,    # PUSH_PROMISE (Section 6.6)
    0x6: False,   # PING (Section 6.7)
    0x7: False,   # GOAWAY (Section 6.8)
    0x8: True,    # WINDOW_UPDATE (Section 6.9)
    0x9: True,    # CONTINUATION (Section 6.10)
}


def _load_generator() -> 'types.ModuleType':
    """Load :file:`examples/generators/options.py` by path, under a name of its own.

    Returns:
        The generator module.

    Raises:
        RuntimeError: If the module cannot be found or loaded.

    """
    path = ROOT / 'examples' / 'generators' / 'options.py'
    spec = importlib.util.spec_from_file_location(
        'pcapkit_samples_options_httpv2_stream', path)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise RuntimeError(f'cannot load the option generator from {path}')

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HTTPv2GeneratedFrameTests(unittest.TestCase):
    """Each ``httpv2-frame`` case, as the capture carries it."""

    @classmethod
    def setUpClass(cls) -> None:
        options = _load_generator()
        family = options.FAMILY_MAP['httpv2-frame']
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            cls.frames = {int(outcome.case.code): outcome
                          for outcome in options.outcomes((family,))}

    def test_every_frame_type_is_generated(self) -> None:
        """The ten :rfc:`9113` frame types are the ten cases, all capturable."""
        self.assertEqual(sorted(self.frames), sorted(EXPECTED_STREAM))
        for code, outcome in self.frames.items():
            with self.subTest(type=code):
                self.assertEqual(outcome.status, 'OK', outcome.detail)

    def test_each_frame_is_on_a_stream_its_type_allows(self) -> None:
        """Octets 5-8 are non-zero exactly where :data:`EXPECTED_STREAM` says."""
        for code, outcome in self.frames.items():
            with self.subTest(type=code):
                sid = int.from_bytes(outcome.octets[5:9], 'big') & 0x7FFFFFFF
                self.assertEqual(sid != 0, EXPECTED_STREAM[code], f'stream {sid}')

    def test_push_promise_promises_a_server_initiated_stream(self) -> None:
        """The promised stream is even and non-zero (:rfc:`9113#section-5.1.1`)."""
        octets = self.frames[0x5].octets
        promised = int.from_bytes(octets[9:13], 'big') & 0x7FFFFFFF
        self.assertTrue(promised and promised % 2 == 0, f'promised stream {promised}')

    def test_each_length_counts_the_payload_only(self) -> None:
        """The 24-bit Length excludes the 9-octet header (:rfc:`9113#section-4.1`)."""
        for code, outcome in self.frames.items():
            with self.subTest(type=code):
                length = int.from_bytes(outcome.octets[:3], 'big')
                self.assertEqual(length, len(outcome.octets) - 9)

    def test_each_frame_decodes_as_http2_over_tcp(self) -> None:
        """A port-80 segment carrying the frame decodes ``TCP:HTTP/2``, not ``TCP:Raw``."""
        from pcapkit.protocols.transport.tcp import TCP

        for code, outcome in self.frames.items():
            with self.subTest(type=code):
                raw = _TCP_TO_80 + outcome.octets
                with warnings.catch_warnings():
                    # An in-memory segment carries no checksum; the chain is
                    # what is under test.
                    warnings.simplefilter('ignore')
                    with time_limit():
                        proto = TCP(raw, len(raw))
                self.assertEqual(str(proto.protochain), 'TCP:HTTP/2')


if __name__ == '__main__':
    unittest.main()
