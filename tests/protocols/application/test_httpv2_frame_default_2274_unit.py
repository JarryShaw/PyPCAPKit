# -*- coding: utf-8 -*-
"""``HTTP.make`` builds every HTTP/2 frame type without a ``frame`` argument.

GitHub issue #2274: ``make`` defaulted ``frame`` to ``b''``, which is packed as
raw octets with Length 0. A frame type whose payload is of fixed or minimum size
is longer than that, so ``HTTP(type=<T>, sid=...)`` could not build one at all:
``PRIORITY``, ``RST_STREAM``, ``PING`` and ``WINDOW_UPDATE`` raised
``HTTP/2: [Type <T>] invalid format`` and ``PUSH_PROMISE`` and ``GOAWAY`` raised
``Field <f> resolved to a negative length``, each after a ``SchemaWarning:
packet length < 0``. ``frame={}``, which dispatches to the frame type's own
constructor, built them.

``frame`` now defaults to :data:`None` and takes that dispatch, so the default
call and ``frame={}`` give the same octets for every frame type. An explicit
:obj:`bytes` value, ``b''`` included, is still packed raw. ``SETTINGS`` needed
the other half of the fix: ``_make_http_settings`` rejected its own
``settings=None`` default, so ``frame={}`` raised there instead, and
:data:`None` now builds the parameterless ``SETTINGS`` frame
:rfc:`9113#section-6.5` permits.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import unittest
from typing import Any

from tests._support import reimport_once_per_class

#: Octets ``HTTP(type=<name>, sid=<sid>)`` builds, by frame type name and Stream
#: Identifier. Every one of them is also what ``frame={}`` builds.
DEFAULT_FRAMES = {
    'DATA': (1, bytes.fromhex('000000000000000001')),
    'HEADERS': (1, bytes.fromhex('000000010000000001')),
    'PRIORITY': (1, bytes.fromhex('000005020000000001' '00000000' '00')),
    'RST_STREAM': (1, bytes.fromhex('000004030000000001' '00000000')),
    'SETTINGS': (0, bytes.fromhex('000000040000000000')),
    'PUSH_PROMISE': (1, bytes.fromhex('000004050000000001' '00000000')),
    'PING': (0, bytes.fromhex('000008060000000000' '0000000000000000')),
    'GOAWAY': (0, bytes.fromhex('000008070000000000' '00000000' '00000000')),
    'WINDOW_UPDATE': (1, bytes.fromhex('000004080000000001' '00000000')),
    'CONTINUATION': (1, bytes.fromhex('000000090000000001')),
}

#: An unassigned frame type, whose payload has no fixed size, so the default and
#: ``frame={}`` agreed on it before the fix as well.
UNASSIGNED_TYPE = 0xfa


class TestHTTPv2DefaultFrame(unittest.TestCase):
    """Pin what ``make`` builds when ``frame`` is left out."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def build(self, type: 'Any', sid: 'int', **kwargs: 'Any') -> 'Any':
        """Build the HTTP/2 frame of ``type`` on stream ``sid``."""
        from pcapkit.protocols.application.httpv2 import HTTPv2

        return HTTPv2(type=type, sid=sid, **kwargs)

    def test_default_builds_every_frame_type(self) -> None:
        from pcapkit.const.http.frame import Frame

        for name, (sid, wire) in DEFAULT_FRAMES.items():
            with self.subTest(frame=name):
                self.assertEqual(bytes(self.build(Frame[name], sid)).hex(), wire.hex())

    def test_default_agrees_with_an_empty_mapping(self) -> None:
        from pcapkit.const.http.frame import Frame

        for name, (sid, _) in DEFAULT_FRAMES.items():
            with self.subTest(frame=name):
                self.assertEqual(bytes(self.build(Frame[name], sid)).hex(),
                                 bytes(self.build(Frame[name], sid, frame={})).hex())

    def test_default_frames_round_trip(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTPv2

        for name, (sid, wire) in DEFAULT_FRAMES.items():
            with self.subTest(frame=name):
                made = bytes(self.build(Frame[name], sid))
                parsed = HTTPv2(made, len(made))
                self.assertEqual(parsed.info.type, Frame[name])
                self.assertEqual(parsed.info.sid, sid)
                self.assertEqual(bytes(HTTPv2.from_data(parsed.info)).hex(), wire.hex())

    def test_an_unassigned_type_is_unchanged(self) -> None:
        wire = bytes.fromhex('000000fa0000000001')
        for label, kwargs in (('default', {}), ('mapping', {'frame': {}}), ('bytes', {'frame': b''})):
            with self.subTest(frame=label):
                self.assertEqual(bytes(self.build(UNASSIGNED_TYPE, 1, **kwargs)).hex(), wire.hex())

    def test_explicit_bytes_are_still_packed_raw(self) -> None:
        from pcapkit.const.http.frame import Frame

        # Raw octets are packed as given, rather than through the frame type's
        # constructor, so they need not be the payload that type would build.
        made = bytes(self.build(Frame.RST_STREAM, 1, frame=b'\x00\x00\x00\x08'))
        self.assertEqual(made.hex(), '000004030000000001' '00000008')
        self.assertEqual(bytes(self.build(Frame.DATA, 1, frame=b'abc')).hex(),
                         '000003000000000001' '616263')

    def test_empty_bytes_still_build_a_zero_length_frame(self) -> None:
        from pcapkit.const.http.frame import Frame

        # ``b''`` is an explicit request for no payload, which is what a frame
        # type of no fixed size builds anyway.
        for name in ('DATA', 'HEADERS', 'SETTINGS', 'CONTINUATION'):
            with self.subTest(frame=name):
                sid, wire = DEFAULT_FRAMES[name]
                self.assertEqual(bytes(self.build(Frame[name], sid, frame=b'')).hex(), wire.hex())

    def test_explicit_empty_bytes_stay_raw_on_a_fixed_size_type(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTPv2

        # An explicit ``b''`` is still packed raw, even on a frame type whose
        # default (``None``) dispatches to a constructor with a non-empty
        # payload -- it must not be swept into that dispatch. Built via
        # ``make`` directly, bypassing the round-trip parse that a length-0
        # PING would legitimately fail (PING's payload is a fixed 8 octets).
        schema = HTTPv2.__new__(HTTPv2).make(type=Frame.PING, frame=b'')
        self.assertEqual(int(schema.length), 0)
        self.assertEqual(schema.frame, b'')


class TestHTTPv2EmptySettings(unittest.TestCase):
    """Pin the ``SETTINGS`` frame ``_make_http_settings`` builds from ``None``."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_none_builds_a_parameterless_settings_frame(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTPv2

        for label, frame in (('default', {}), ('explicit', {'settings': None})):
            with self.subTest(settings=label):
                made = bytes(HTTPv2(type=Frame.SETTINGS, sid=0, frame=frame))
                self.assertEqual(made.hex(), DEFAULT_FRAMES['SETTINGS'][1].hex())
                self.assertEqual(HTTPv2(made, len(made)).info.length, 0)

    def test_the_schema_carries_no_entries(self) -> None:
        from pcapkit.protocols.application.httpv2 import HTTPv2

        schema, flags = HTTPv2.__new__(HTTPv2)._make_http_settings()
        self.assertEqual(list(schema.settings), [])
        self.assertEqual(int(flags), 0)

    def test_an_empty_settings_frame_still_takes_the_ack_flag(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTPv2

        made = bytes(HTTPv2(type=Frame.SETTINGS, sid=0, frame={'ack': True}))
        self.assertEqual(made.hex(), '000000040100000000')

    def test_other_settings_types_are_still_rejected(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTPv2
        from pcapkit.utilities.exceptions import ProtocolError

        for settings, tail in ((42, '42'), ('x', "'x'"), (4.5, '4.5')):
            with self.subTest(settings=settings):
                with self.assertRaises(ProtocolError) as ctx:
                    bytes(HTTPv2(type=Frame.SETTINGS, frame={'settings': settings}))
                self.assertEqual(str(ctx.exception),
                                 f'HTTP/2: [Type 4] invalid settings: {tail}')


if __name__ == '__main__':
    unittest.main()
