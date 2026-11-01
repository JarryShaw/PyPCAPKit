# -*- coding: utf-8 -*-
"""HTTP's version, data, start-line and ``SETTINGS`` errors carry the ``HTTP:`` prefix. C.f. #2298.

The rest of HTTP's messages read ``HTTP: invalid format``, the house
``<prefix>: <lowercase description>: … {value!r}`` form (#2232, #2257). Before
the fix these read ``invalid HTTP version: 3``, ``invalid HTTP data: dict`` and
``unknown HTTP version`` from :class:`~pcapkit.protocols.application.http.HTTP`,
and ``HTTP request must have URI.`` and
``HTTP packet must be either request or response.`` from
:meth:`httpv1.HTTPv1._make_start_line
<pcapkit.protocols.application.httpv1.HTTPv1._make_start_line>`, capitalised, with
a closing full stop and without the values that were rejected. The
``SETTINGS`` one read ``HTTP/2 : [Type 4] invalid settings`` from
:meth:`httpv2.HTTPv2._make_http_settings
<pcapkit.protocols.application.httpv2.HTTPv2._make_http_settings>`, a space before
the colon and no rejected value either.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, so they match the live
:mod:`pcapkit` import.

"""

import io
import unittest

from tests._support import reimport_once_per_class


class TestHTTPDispatcherMessages(unittest.TestCase):
    """Pin the dispatcher's version and data messages."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_make_names_the_rejected_version(self) -> None:
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError) as ctx:
            HTTP.make(HTTP.__new__(HTTP), version=3)  # type: ignore[arg-type]
        self.assertEqual(str(ctx.exception), 'HTTP: invalid version: 3')

    def test_read_names_the_rejected_version(self) -> None:
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        raw = b'GET / HTTP/1.1\r\n\r\n'
        with self.assertRaises(ProtocolError) as ctx:
            HTTP(io.BytesIO(raw), len(raw), version='3')
        self.assertEqual(str(ctx.exception), "HTTP: invalid version: '3'")

    def test_make_data_names_the_rejected_type(self) -> None:
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError) as ctx:
            HTTP._make_data({'version': 1})  # type: ignore[arg-type]
        self.assertEqual(str(ctx.exception),
                         'HTTP: invalid data: must be HTTP/1.* or HTTP/2 data, not dict')

    def test_guess_version_has_the_prefix(self) -> None:
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        raw = b'\x00' * 3
        with self.assertRaises(ProtocolError) as ctx:
            HTTP(io.BytesIO(raw), len(raw))
        self.assertEqual(str(ctx.exception), 'HTTP: unknown version')


class TestHTTPv1StartLineMessages(unittest.TestCase):
    """Pin ``httpv1.HTTPv1._make_start_line``'s messages."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_request_without_uri(self) -> None:
        from pcapkit.protocols.application.httpv1 import HTTPv1
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError) as ctx:
            HTTPv1(method='GET', http_version='1.1')
        self.assertEqual(str(ctx.exception), 'HTTP: invalid start line: a request needs a URI')

    def test_neither_or_both_of_method_and_status(self) -> None:
        from pcapkit.protocols.application.httpv1 import HTTPv1
        from pcapkit.utilities.exceptions import ProtocolError

        cases = (
            ({}, 'not method=None and status=None'),
            ({'method': 'GET', 'status': 200}, "not method='GET' and status=200"),
        )
        for kwargs, tail in cases:
            with self.subTest(**kwargs):
                with self.assertRaises(ProtocolError) as ctx:
                    HTTPv1.__new__(HTTPv1)._make_start_line(http_version='1.1', **kwargs)
                self.assertEqual(str(ctx.exception),
                                 'HTTP: invalid start line: must have either a method or a '
                                 f'status, {tail}')


class TestHTTPv2SettingsMessage(unittest.TestCase):
    """Pin ``httpv2.HTTPv2._make_http_settings``'s rejection message."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_settings_names_the_rejected_value(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTPv2
        from pcapkit.utilities.exceptions import ProtocolError

        # ``None`` is no longer rejected: it builds a parameterless ``SETTINGS``
        # frame (#2274), pinned in test_httpv2_frame_default_2274_unit.py.
        for settings, tail in ((42, '42'), ('x', "'x'"), (4.5, '4.5')):
            with self.subTest(settings=settings):
                with self.assertRaises(ProtocolError) as ctx:
                    bytes(HTTPv2(type=Frame.SETTINGS, frame={'settings': settings}))
                self.assertEqual(str(ctx.exception),
                                 f'HTTP/2: [Type 4] invalid settings: {tail}')


if __name__ == '__main__':
    unittest.main()
