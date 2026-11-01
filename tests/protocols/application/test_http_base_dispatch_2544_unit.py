# -*- coding: utf-8 -*-
"""The HTTP family base dispatches on both paths. C.f. #2544.

A versioned family's base never yields an instance of itself: parsing octets
through :class:`~pcapkit.protocols.application.http.HTTP`, constructing it from
fields, and its ``from_data`` all give ``HTTPv1`` or ``HTTPv2``. On the read path
the member is the one an explicit ``version`` names or ``_dispatch_version``
identifies; on the make path the one ``version`` names or the fields describe.
Octets neither version takes raise, as they do through either member.

This module is unit-tier: every packet is built in memory.

"""

from __future__ import annotations

import importlib
import importlib.util
import io
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: The HTTP/2 connection preface (RFC 9113, section 3.4).
_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

#: Octets, with the member that parses them.
OCTETS = {
    'request': (b'GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n', 'HTTPv1'),
    'response': (b'HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nhi', 'HTTPv1'),
    'frame': (bytes.fromhex('000000000000000001'), 'HTTPv2'),
    'preface': (_PREFACE + bytes.fromhex('000000040000000000'), 'HTTPv2'),
}

#: Octets neither version takes, with the refusal's message.
UNRECOGNISED = {
    'zeros': (b'\x00' * 9, 'HTTP: unknown version'),
    'text': (b'not an http message', 'HTTP: unknown version'),
    'preface alone': (_PREFACE, 'HTTP/2: connection preface with no frame'),
}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HTTPBaseDispatchTests(unittest.TestCase):
    """``HTTP(...)`` and ``HTTP.from_data`` give the member, never the base."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def classes() -> 'tuple[Any, Any, Any]':
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.protocols.application.httpv1 import HTTPv1
        from pcapkit.protocols.application.httpv2 import HTTPv2

        return HTTP, HTTPv1, HTTPv2

    def member(self, name: str) -> 'Any':
        return dict(zip(('HTTP', 'HTTPv1', 'HTTPv2'), self.classes()))[name]

    def test_parsing_through_the_base_gives_the_member(self) -> None:
        HTTP, _, _ = self.classes()
        for label, (octets, name) in OCTETS.items():
            for source in ('bytes', 'stream'):
                with self.subTest(octets=label, source=source):
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        layer = (HTTP(octets) if source == 'bytes'
                                 else HTTP(io.BytesIO(octets), len(octets)))
                    self.assertIs(type(layer), self.member(name))
                    self.assertEqual(layer.info_name, name.lower())
                    self.assertEqual(layer.data, octets)

    def test_an_explicit_version_names_the_member_on_the_read_path(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        HTTP, _, HTTPv2 = self.classes()
        octets = OCTETS['frame'][0]
        self.assertIs(type(HTTP(octets, version=2)), HTTPv2)
        with self.assertRaisesRegex(ProtocolError, 'invalid format'):
            HTTP(octets, version=1)
        with self.assertRaisesRegex(ProtocolError, 'invalid version'):
            HTTP(octets, version=3)

    def test_octets_neither_version_takes_raise(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        HTTP, _, _ = self.classes()
        for label, (octets, message) in UNRECOGNISED.items():
            with self.subTest(octets=label):
                with self.assertRaisesRegex(ProtocolError, message):
                    HTTP(octets)

    def test_building_through_the_base_gives_the_member_the_fields_describe(self) -> None:
        from pcapkit.const.http.frame import Frame

        HTTP, HTTPv1, HTTPv2 = self.classes()
        cases = {
            'version 1': ({'version': 1, 'method': 'GET', 'uri': '/'}, HTTPv1),
            'HTTP/1 fields': ({'method': 'GET', 'uri': '/'}, HTTPv1),
            'version 2': ({'version': 2, 'type': Frame.DATA, 'sid': 1}, HTTPv2),
            'HTTP/2 fields': ({'type': Frame.DATA, 'sid': 1, 'frame': {'data': b'x'}}, HTTPv2),
            'preface': ({'version': 2, 'preface': True, 'type': Frame.SETTINGS}, HTTPv2),
        }
        for label, (fields, klass) in cases.items():
            with self.subTest(fields=label):
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    layer = HTTP(**fields)
                    direct = klass(**{key: val for key, val in fields.items() if key != 'version'})
                self.assertIs(type(layer), klass)
                self.assertEqual(layer.data, direct.data)
        self.assertTrue(HTTP(version=2, preface=True, type=Frame.SETTINGS).data.startswith(_PREFACE))

    def test_a_false_preface_names_no_version(self) -> None:
        """``preface=False`` is the default, so it names no version.

        HTTP/1 fields beside it still build HTTP/1, as without it, and on its own it
        picks HTTPv1, the version ``make`` defaults to; only a true ``preface`` means
        HTTP/2.
        """
        from pcapkit.const.http.frame import Frame
        from pcapkit.utilities.exceptions import ProtocolError

        HTTP, HTTPv1, HTTPv2 = self.classes()
        self.assertIs(HTTP._dispatch_fields({'preface': False}), HTTPv1)
        self.assertIs(HTTP._dispatch_fields({'preface': True}), HTTPv2)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with_false = HTTP(method='GET', uri='/', preface=False)
            without = HTTP(method='GET', uri='/')
            frame = HTTP(type=Frame.DATA, sid=1, preface=False)
        self.assertIs(type(with_false), HTTPv1)
        self.assertEqual(with_false.data, without.data)
        self.assertIs(type(frame), HTTPv2)
        self.assertFalse(frame.data.startswith(_PREFACE))
        # Alone it builds what ``HTTP()`` builds: an HTTP/1 message with no start
        # line, which HTTPv1 refuses.
        with self.assertRaisesRegex(ProtocolError, 'invalid start line'):
            HTTP(preface=False)

    def test_fields_no_one_version_builds_raise(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        HTTP, _, _ = self.classes()
        for fields, message in (({'method': 'GET', 'sid': 1}, 'fields of both'),
                                ({'version': 1, 'preface': True}, 'HTTP/2 only'),
                                ({'method': 'GET', 'uri': '/', 'preface': True},
                                 r'^HTTP/1: connection preface is HTTP/2 only$'),
                                ({'method': 'GET', 'preface': True, 'sid': 1},
                                 r'^HTTP: fields of both HTTP/1 \(method\) and HTTP/2 \(preface, sid\)$'),
                                ({'version': 3}, 'invalid version')):
            with self.subTest(fields=fields):
                with self.assertRaisesRegex(ProtocolError, message):
                    HTTP(**fields)

    def test_from_data_on_the_base_gives_the_member(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        HTTP, _, _ = self.classes()
        for label, (octets, name) in OCTETS.items():
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                parsed = HTTP(octets)
            for form in ('info', 'dict'):
                with self.subTest(octets=label, form=form):
                    data = parsed.info if form == 'info' else parsed.info.to_dict()
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        rebuilt = HTTP.from_data(data)
                    self.assertIs(type(rebuilt), self.member(name))
                    self.assertEqual(rebuilt.data, octets)
        with self.assertRaisesRegex(ProtocolError, 'invalid data'):
            HTTP.from_data({'neither': 'version'})

    def test_built_packets_parse_back_through_the_base(self) -> None:
        """make -> parse through the base gives the same member and octets."""
        from pcapkit.const.http.frame import Frame

        HTTP, _, _ = self.classes()
        for fields in ({'method': 'GET', 'uri': '/'}, {'type': Frame.DATA, 'sid': 1},
                       {'version': 2, 'preface': True, 'type': Frame.SETTINGS}):
            with self.subTest(fields=fields):
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    made = HTTP(**fields)
                    parsed = HTTP(made.data)
                self.assertIs(type(parsed), type(made))
                self.assertEqual(parsed.data, made.data)


if __name__ == '__main__':
    unittest.main()
