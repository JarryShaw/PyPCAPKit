# -*- coding: utf-8 -*-
"""HTTP/2 ``SETTINGS`` frames parse their setting pairs without warnings.

GitHub issue #1140. ``SettingsFrame.settings`` built each item as a
``SchemaField`` with no length, so every ``SettingPair`` was unpacked with a
``__length__`` of ``-1`` and warned ``packet length < 0`` twice, at ``-3`` and
``-7``, once per pair. The frames below are packed by scapy's independent
:mod:`scapy.contrib.http2`, which serves as the oracle for the round trip.

"""

from __future__ import annotations

import importlib.util
import io
import unittest
import warnings

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper', 'scapy')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: ``name -> (setting pairs, ACK flag)``.
CASES = {
    '0 pairs': ([], False),
    '1 pair': ([(1, 4096)], False),
    '2 pairs': ([(1, 4096), (3, 100)], False),
    '6 pairs': ([(1, 4096), (2, 0), (3, 100), (4, 65535), (5, 16384), (6, 8192)], False),
    'ACK': ([], True),
}


def scapy_frame(pairs: 'list[tuple[int, int]]', ack: 'bool') -> 'bytes':
    """Pack a ``SETTINGS`` frame with scapy."""
    from scapy.contrib import http2

    frame = http2.H2Frame(type=4, flags={'A'} if ack else set(), stream_id=0)
    return bytes(frame / http2.H2SettingsFrame(
        settings=[http2.H2Setting(id=id, value=value) for id, value in pairs],
    ))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HTTPv2SettingsListUnitTests(unittest.TestCase):
    """``SETTINGS`` parses quietly and round-trips byte for byte."""

    def test_settings_parse_without_warnings(self) -> None:
        """No warning of any kind is emitted, and every pair is read."""
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2

        for name, (pairs, ack) in CASES.items():
            raw = scapy_frame(pairs, ack)
            with self.subTest(frame=name):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    info = HTTPv2(io.BytesIO(raw), len(raw)).info
                self.assertEqual([str(w.message) for w in caught], [])
                self.assertEqual(info.flags.ACK, ack)
                self.assertEqual([(int(k), v) for k, v in info.settings.items(multi=True)], pairs)

    def test_settings_round_trip_to_the_scapy_octets(self) -> None:
        """parse -> ``make`` reproduces scapy's octets exactly."""
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2

        for name, (pairs, ack) in CASES.items():
            raw = scapy_frame(pairs, ack)
            with self.subTest(frame=name):
                info = HTTPv2(io.BytesIO(raw), len(raw)).info
                self.assertEqual(bytes(HTTPv2(type=info.type, sid=info.sid, frame=info)), raw)


if __name__ == '__main__':
    unittest.main()
