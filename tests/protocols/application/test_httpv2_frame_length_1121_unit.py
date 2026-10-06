# -*- coding: utf-8 -*-
"""HTTP/2 frame Length counts the payload only, per :rfc:`9113#section-4.1`.

GitHub issue #1121. ``HTTP.make`` wrote Length as payload + 9 and the readers
checked the same, so every RFC-conformant frame with a fixed-size payload was
rejected, and ``_read_http_priority`` checked ``!= 9`` and so rejected even the
14 that ``make`` wrote for it.

The fixtures below are real HTTP/2 octets, not a re-statement of pcapkit's own
arithmetic: each one is byte-identical to what scapy's independent
:mod:`scapy.contrib.http2` packs for the same frame (checked when this module
was written; scapy is not a test dependency, so it is not imported here).

"""

from __future__ import annotations

import importlib.util
import io
import unittest

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: ``name -> (wire octets, make() keyword arguments)``. Length is the first
#: three octets and counts the payload alone.
RFC_FRAMES = {
    'PRIORITY': (
        bytes.fromhex('000005' '02' '00' '00000003' '00000001' '0f'),
        {'type': 0x02, 'sid': 3, 'frame': {'sid_dep': 1, 'weight': 16}},
    ),
    'RST_STREAM': (
        bytes.fromhex('000004' '03' '00' '00000003' '00000008'),
        {'type': 0x03, 'sid': 3, 'frame': {'error': 8}},
    ),
    'SETTINGS': (
        bytes.fromhex('000006' '04' '00' '00000000' '0001' '00001000'),
        {'type': 0x04, 'sid': 0, 'frame': {'settings': [(1, 4096)]}},
    ),
    'SETTINGS/ACK': (
        bytes.fromhex('000000' '04' '01' '00000000'),
        {'type': 0x04, 'sid': 0, 'frame': {'ack': True, 'settings': []}},
    ),
    'PING': (
        bytes.fromhex('000008' '06' '00' '00000000' '0102030405060708'),
        {'type': 0x06, 'sid': 0, 'frame': {'opaque_data': bytes.fromhex('0102030405060708')}},
    ),
    'GOAWAY': (
        bytes.fromhex('00000a' '07' '00' '00000000' '00000005' '00000000' 'dead'),
        {'type': 0x07, 'sid': 0, 'frame': {'last_sid': 5, 'error': 0, 'debug_data': b'\xde\xad'}},
    ),
    'WINDOW_UPDATE': (
        bytes.fromhex('000004' '08' '00' '00000001' '000003e8'),
        {'type': 0x08, 'sid': 1, 'frame': {'incr': 1000}},
    ),
    'DATA': (
        bytes.fromhex('000005' '00' '00' '00000001') + b'hello',
        {'type': 0x00, 'sid': 1, 'frame': {'data': b'hello'}},
    ),
    'PUSH_PROMISE': (
        bytes.fromhex('000004' '05' '04' '00000001' '00000002'),
        {'type': 0x05, 'sid': 1, 'frame': {'end_headers': True, 'promised_sid': 2}},
    ),
}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HTTPv2FrameLengthUnitTests(unittest.TestCase):
    """Read and write both treat Length as the payload length."""

    def test_rfc_frames_parse_and_report_the_payload_length(self) -> None:
        """Each RFC frame parses, and ``info.length`` is its payload length."""
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2

        for name, (raw, _) in RFC_FRAMES.items():
            with self.subTest(frame=name):
                info = HTTPv2(io.BytesIO(raw), len(raw)).info
                self.assertEqual(info.length, len(raw) - 9)

    def test_make_writes_the_rfc_octets(self) -> None:
        """``make`` packs exactly the RFC octets, Length included."""
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2

        for name, (raw, kwargs) in RFC_FRAMES.items():
            with self.subTest(frame=name):
                self.assertEqual(bytes(HTTPv2(**kwargs)), raw)

    def test_parsed_frames_rebuild_to_the_same_octets(self) -> None:
        """parse -> ``make`` reproduces the wire octets."""
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2

        for name, (raw, _) in RFC_FRAMES.items():
            with self.subTest(frame=name):
                info = HTTPv2(io.BytesIO(raw), len(raw)).info
                self.assertEqual(bytes(HTTPv2(type=info.type, sid=info.sid, frame=info)), raw)

    def test_the_old_header_inclusive_length_is_rejected(self) -> None:
        """A fixed-size frame declaring payload + 9 is now a size error."""
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
        from pcapkit.utilities.exceptions import ProtocolError

        for name in ('PRIORITY', 'RST_STREAM', 'PING', 'WINDOW_UPDATE'):
            raw, _ = RFC_FRAMES[name]
            # Declare payload + 9, and pad the buffer so it still backs that.
            wrong = (len(raw)).to_bytes(3, 'big') + raw[3:] + b'\x00' * 9
            with self.subTest(frame=name):
                with self.assertRaises(ProtocolError):
                    HTTPv2(io.BytesIO(wrong), len(wrong))

    def test_declared_payload_must_fit_after_the_header(self) -> None:
        """The buffer has to back the 9-octet header plus the declared payload."""
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
        from pcapkit.utilities.exceptions import ProtocolError

        raw, _ = RFC_FRAMES['DATA']
        with self.assertRaises(ProtocolError):
            HTTPv2(io.BytesIO(raw[:-1]), len(raw) - 1)


if __name__ == '__main__':
    unittest.main()
