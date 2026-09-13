from __future__ import annotations

import importlib.util
import unittest
from types import SimpleNamespace
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class DummyData(dict):
    __getattr__ = dict.__getitem__


def http2_header(length: int, type_: object, flags: int = 0, sid: int = 1) -> SimpleNamespace:
    return SimpleNamespace(
        length=length,
        type=type_,
        flags={f'bit_{bit}': (flags & (1 << bit)) >> bit for bit in range(8)},
        stream={'sid': sid},
    )


def http2_schema(**kwargs: object) -> SimpleNamespace:
    flags = kwargs.pop('__flags__', 0)
    schema = SimpleNamespace(**kwargs)
    setattr(schema, '__flags__', flags)
    return schema


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HTTPUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_http_read_rejects_unknown_version_selector(self) -> None:
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        http = object.__new__(HTTP)

        with self.assertRaises(ProtocolError):
            HTTP.read(http, length=0, version=3)

    def test_http_make_rejects_unknown_version_selector(self) -> None:
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        http = object.__new__(HTTP)

        with self.assertRaises(ProtocolError):
            HTTP.make(http, version=3)

    def test_http_make_data_rejects_unknown_version_selector(self) -> None:
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError):
            HTTP._make_data({'version': 9})

    def test_http_base_id_and_cached_properties_are_stable(self) -> None:
        from pcapkit.protocols.application.http import HTTP

        http = object.__new__(HTTP)
        http._version = '1.1'
        http._length = 42

        self.assertEqual(HTTP.id(), ('HTTP', 'HTTPv1', 'HTTPv2'))
        self.assertEqual(http.name, 'Hypertext Transfer Protocol')
        self.assertEqual(http.alias, 'HTTP/1.1')
        self.assertEqual(http.version, '1.1')
        self.assertEqual(http.length, 42)

    def test_http_read_make_and_guess_version_delegation_paths(self) -> None:
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        class FakeHTTPv1:
            version = '1.1'
            length = 11
            info = 'v1-info'

            def __init__(self, file, length, **kwargs):
                self.file = file
                self.init_length = length
                self.kwargs = kwargs

            @staticmethod
            def make(**kwargs):
                return ('v1-made', kwargs)

        class FakeHTTPv2:
            version = '2'
            length = 22
            info = 'v2-info'

            def __init__(self, file, length, **kwargs):
                self.file = file
                self.init_length = length
                self.kwargs = kwargs

            @staticmethod
            def make(**kwargs):
                return ('v2-made', kwargs)

        http = object.__new__(HTTP)
        http._data = b'GET / HTTP/1.1\r\n\r\n'
        http._file = object()
        http.__cached__ = {}

        with mock.patch('pcapkit.protocols.application.httpv1.HTTP', FakeHTTPv1):
            self.assertEqual(http.read(version=1, marker=True), 'v1-info')
        self.assertEqual(http.version, '1.1')
        self.assertEqual(http.length, 11)

        with mock.patch('pcapkit.protocols.application.httpv2.HTTP', FakeHTTPv2):
            self.assertEqual(http.read(length=9, version=2), 'v2-info')
        self.assertEqual(http.version, '2')
        self.assertEqual(http.length, 22)

        guessed = SimpleNamespace(version='1.1', length=11, info='v1-info')
        with mock.patch.object(HTTP, '_guess_version', return_value=guessed) as guess:
            self.assertEqual(http.read(), 'v1-info')
        guess.assert_called_once_with(len(http._data))

        with mock.patch('pcapkit.protocols.application.httpv1.HTTP', FakeHTTPv1):
            self.assertEqual(http.make(version=1, path='/'), ('v1-made', {'path': '/'}))
        with mock.patch('pcapkit.protocols.application.httpv2.HTTP', FakeHTTPv2):
            self.assertEqual(http.make(version=2, sid=1), ('v2-made', {'sid': 1}))

        with mock.patch('pcapkit.protocols.application.httpv1.HTTP',
                        mock.Mock(side_effect=ProtocolError('bad v1'))), \
                mock.patch('pcapkit.protocols.application.httpv2.HTTP', FakeHTTPv2):
            self.assertIsInstance(HTTP._guess_version(http, 9), FakeHTTPv2)
        with mock.patch('pcapkit.protocols.application.httpv1.HTTP', FakeHTTPv1):
            self.assertIsInstance(HTTP._guess_version(http, 9), FakeHTTPv1)
        with mock.patch('pcapkit.protocols.application.httpv1.HTTP',
                        mock.Mock(side_effect=ProtocolError('bad v1'))), \
                mock.patch('pcapkit.protocols.application.httpv2.HTTP',
                           mock.Mock(side_effect=ProtocolError('bad v2'))):
            with self.assertRaises(ProtocolError):
                HTTP._guess_version(http, 9)

    def test_http_make_data_delegates_to_httpv1(self) -> None:
        from pcapkit.const.http.method import Method
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.application.http import HTTP

        data = DummyData(
            version=1,
            receipt=SimpleNamespace(version='1.1', method=Method.GET, uri='/index.html'),
            header=OrderedMultiDict([('Host', 'example.test')]),
            body=b'body',
        )

        values = HTTP._make_data(data)
        self.assertEqual(values['http_version'], '1.1')
        self.assertEqual(values['method'], Method.GET)
        self.assertEqual(values['uri'], '/index.html')
        self.assertEqual(values['headers']['Host'], 'example.test')
        self.assertEqual(values['body'], b'body')

    def test_http_make_data_delegates_to_httpv2(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.http import HTTP

        flags = SimpleNamespace(__value__=0x01)
        data = DummyData(
            version=2,
            length=13,
            type=Frame.DATA,
            flags=flags,
            sid=1,
            __next_type__=None,
        )

        values = HTTP._make_data(data)
        self.assertEqual(values['length'], 13)
        self.assertEqual(values['type'], Frame.DATA)
        self.assertEqual(values['flags'], 0x01)
        self.assertEqual(values['sid'], 1)
        self.assertIs(values['frame'], data)

    def test_http_guess_version_propagates_malformed_payload_value_error(self) -> None:
        from pcapkit.protocols.application.http import HTTP

        http = object.__new__(HTTP)
        http._data = b'not http at all'

        with self.assertRaises(ValueError):
            HTTP._guess_version(http, len(http._data))

    def test_httpv1_id_make_data_and_request_construction(self) -> None:
        from pcapkit.const.http.method import Method
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.application.httpv1 import HTTP as HTTPv1
        from pcapkit.protocols.schema.application.httpv1 import HTTP as Schema_HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(HTTPv1)
        proto._info = SimpleNamespace(receipt=SimpleNamespace(version='1.0'))
        headers = OrderedMultiDict([('Host', 'example.test')])
        schema = proto.make(method='GET', uri='/index.html', headers=headers, body=b'body')
        bytes_schema = proto.make(method=b'POST', uri=b'/submit')
        enum_schema = proto.make(method=Method.HEAD, uri='/head')
        object_schema = proto.make(method=SimpleNamespace(value='TRACE'), uri='/trace')
        data = DummyData(
            receipt=SimpleNamespace(version='1.1', method=Method.GET, uri='/index.html'),
            header=headers,
            body=b'body',
        )

        self.assertEqual(HTTPv1.id(), ('HTTP', 'HTTPv1'))
        self.assertEqual(proto.version, '1.0')
        self.assertEqual(proto.alias, 'HTTP/1.0')
        self.assertIn(b'GET /index.html HTTP/1.1\r\n', schema.data)
        self.assertIn(b'Host: example.test\r\n', schema.data)
        self.assertTrue(schema.data.endswith(b'\r\nbody'))
        self.assertIn(b'POST /submit HTTP/1.1\r\n', bytes_schema.data)
        self.assertIn(b'HEAD /head HTTP/1.1\r\n', enum_schema.data)
        self.assertIn(b'TRACE /trace HTTP/1.1\r\n', object_schema.data)
        self.assertEqual(HTTPv1._make_data(data)['uri'], '/index.html')

        proto.__header__ = Schema_HTTP(data=b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\nbody')
        proto._data = proto.__header__.data
        proto.__cached__ = {}
        parsed = proto.read()
        self.assertEqual(parsed.receipt.version, '1.1')
        self.assertEqual(parsed.body, b'body')

        proto.__header__ = Schema_HTTP(data=b'HTTP/1.1 404 Not Found\r\nServer: example\r\n\r\nbody')
        response = proto.read()
        self.assertEqual(response.receipt.status, 404)
        self.assertEqual(response.receipt.message, 'Not Found')
        self.assertEqual(response.header['Server'], 'example')
        with self.assertRaises(ProtocolError):
            proto._read_http_header(b'BAD nope nope\r\nHost: example')

    def test_httpv1_response_construction_and_missing_request_uri_error(self) -> None:
        from pcapkit.const.http.status_code import StatusCode
        from pcapkit.protocols.application.httpv1 import HTTP as HTTPv1
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(HTTPv1)
        schema = proto.make(status=StatusCode.CODE_200, message='OK')
        default_message = proto.make(status=StatusCode.CODE_404)

        self.assertIn(b'HTTP/1.1 200 OK\r\n\r\n', schema.data)
        self.assertIn(b'HTTP/1.1 404 Not Found\r\n\r\n', default_message.data)
        with self.assertRaises(ProtocolError):
            proto.make(method='GET')
        with self.assertRaises(ProtocolError):
            proto.make()
        with self.assertRaises(ProtocolError):
            proto.make(method='GET', uri='/', status=StatusCode.CODE_200)

    def test_httpv2_id_length_make_bytes_and_register_frame_warning(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2

        proto = object.__new__(HTTPv2)
        original = HTTPv2.__dict__['__frame__'][Frame.DATA]
        try:
            schema = proto.make(type=Frame.DATA, flags=0x01, sid=3, frame=b'data')
            with mock.patch('pcapkit.protocols.application.httpv2.warn') as warn:
                HTTPv2.register_frame(Frame.DATA, 'data')

            self.assertEqual(HTTPv2.id(), ('HTTP', 'HTTPv2'))
            self.assertEqual(proto.alias, 'HTTP/2')
            self.assertEqual(proto.version, '2')
            self.assertEqual(proto.length, 9)
            self.assertEqual(proto.__length_hint__(), 9)
            self.assertEqual(schema.length, 13)
            self.assertEqual(schema.type, Frame.DATA)
            self.assertEqual(schema.flags['bit_0'], 1)
            self.assertEqual(schema.stream['sid'], 3)
            self.assertEqual(schema.frame, b'data')
            warn.assert_called_once()
        finally:
            HTTPv2.__dict__['__frame__'][Frame.DATA] = original

    def test_httpv2_frame_readers_cover_successful_frames(self) -> None:
        from pcapkit.const.http.error_code import ErrorCode
        from pcapkit.const.http.frame import Frame
        from pcapkit.const.http.setting import Setting
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2

        proto = object.__new__(HTTPv2)

        with mock.patch('pcapkit.protocols.application.httpv2.warn') as warn:
            none = proto._read_http_none(
                http2_schema(data=b'unknown'),
                header=http2_header(10, 250, flags=0x01, sid=3),
            )
        self.assertEqual(none.to_dict()['data'], b'unknown')
        self.assertIsNone(none.flags)
        warn.assert_called_once()

        with mock.patch('pcapkit.protocols.application.httpv2.warn') as warn:
            none_clean = proto._read_http_none(
                http2_schema(data=b'clean'),
                header=SimpleNamespace(length=9, type=251, flags={}, stream={'sid': 4}),
            )
        self.assertEqual(none_clean.data, b'clean')
        warn.assert_not_called()

        data = proto._read_http_data(
            http2_schema(pad_len=2, data=b'data', __flags__=0x09),
            header=http2_header(16, Frame.DATA, flags=0x09, sid=1),
        )
        self.assertTrue(data.flags.to_dict()['END_STREAM'])
        self.assertTrue(data.flags.to_dict()['PADDED'])
        self.assertEqual(data.to_dict()['pad_len'], 2)
        self.assertEqual(data.to_dict()['data'], b'data')

        headers = proto._read_http_headers(
            http2_schema(
                pad_len=1,
                stream_dep={'exclusive': 1, 'sid': 7},
                weight=4,
                fragment=b'headers',
                __flags__=0x2D,
            ),
            header=http2_header(22, Frame.HEADERS, flags=0x2D, sid=1),
        )
        self.assertTrue(headers.flags.to_dict()['END_STREAM'])
        self.assertTrue(headers.flags.to_dict()['END_HEADERS'])
        self.assertTrue(headers.flags.to_dict()['PADDED'])
        self.assertTrue(headers.flags.to_dict()['PRIORITY'])
        self.assertEqual(headers.to_dict()['stream_dependency'], 7)
        self.assertEqual(headers.to_dict()['weight'], 5)
        self.assertEqual(headers.to_dict()['fragment'], b'headers')

        priority = proto._read_http_priority(
            http2_schema(stream={'exclusive': 1, 'sid': 5}, weight=9),
            header=http2_header(9, Frame.PRIORITY, sid=1),
        )
        self.assertTrue(priority.to_dict()['excl_dependency'])
        self.assertEqual(priority.to_dict()['stream_dependency'], 5)
        self.assertEqual(priority.to_dict()['weight'], 10)

        rst = proto._read_http_rst_stream(
            http2_schema(error=ErrorCode.NO_ERROR),
            header=http2_header(13, Frame.RST_STREAM, sid=1),
        )
        self.assertEqual(rst.to_dict()['error'], ErrorCode.NO_ERROR)

        settings = proto._read_http_settings(
            http2_schema(settings=[
                SimpleNamespace(id=Setting.HEADER_TABLE_SIZE, value=4096),
                SimpleNamespace(id=Setting.ENABLE_PUSH, value=0),
            ], __flags__=0),
            header=http2_header(21, Frame.SETTINGS, sid=0),
        )
        self.assertFalse(settings.flags.to_dict()['ACK'])
        self.assertEqual(settings.settings[Setting.HEADER_TABLE_SIZE], 4096)
        self.assertEqual(settings.settings[Setting.ENABLE_PUSH], 0)

        push = proto._read_http_push_promise(
            http2_schema(pad_len=1, stream={'sid': 11}, fragment=b'push', __flags__=0x0C),
            header=http2_header(18, Frame.PUSH_PROMISE, flags=0x0C, sid=1),
        )
        self.assertTrue(push.flags.to_dict()['END_HEADERS'])
        self.assertTrue(push.flags.to_dict()['PADDED'])
        self.assertEqual(push.to_dict()['promised_sid'], 11)
        self.assertEqual(push.to_dict()['fragment'], b'push')

        ping = proto._read_http_ping(
            http2_schema(data=b'12345678', __flags__=0x01),
            header=http2_header(17, Frame.PING, flags=0x01, sid=0),
        )
        self.assertTrue(ping.flags.to_dict()['ACK'])
        self.assertEqual(ping.to_dict()['data'], b'12345678')

        goaway = proto._read_http_goaway(
            http2_schema(stream={'sid': 13}, error=ErrorCode.NO_ERROR, debug=b'bye'),
            header=http2_header(20, Frame.GOAWAY, sid=0),
        )
        self.assertEqual(goaway.to_dict()['last_sid'], 13)
        self.assertEqual(goaway.to_dict()['debug_data'], b'bye')

        window = proto._read_http_window_update(
            http2_schema(size={'incr': 65535}),
            header=http2_header(13, Frame.WINDOW_UPDATE, sid=1),
        )
        self.assertEqual(window.to_dict()['increment'], 65535)

        continuation = proto._read_http_continuation(
            http2_schema(fragment=b'cont', __flags__=0x04),
            header=http2_header(13, Frame.CONTINUATION, flags=0x04, sid=1),
        )
        self.assertTrue(continuation.flags.to_dict()['END_HEADERS'])
        self.assertEqual(continuation.to_dict()['fragment'], b'cont')

    def test_httpv2_frame_readers_reject_malformed_lengths(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(HTTPv2)

        with self.assertRaises(ProtocolError):
            proto._read_http_priority(http2_schema(stream={'exclusive': 0, 'sid': 1}, weight=1),
                                      header=http2_header(10, Frame.PRIORITY))
        with self.assertRaises(ProtocolError):
            proto._read_http_rst_stream(http2_schema(error=0),
                                        header=http2_header(12, Frame.RST_STREAM))
        with self.assertRaises(ProtocolError):
            proto._read_http_settings(http2_schema(settings=[], __flags__=0),
                                      header=http2_header(14, Frame.SETTINGS, sid=0))
        with self.assertRaises(ProtocolError):
            proto._read_http_settings(http2_schema(settings=[], __flags__=0x01),
                                      header=http2_header(15, Frame.SETTINGS, flags=0x01, sid=0))
        with self.assertRaises(ProtocolError):
            proto._read_http_push_promise(http2_schema(pad_len=0, stream={'sid': 1}, fragment=b''),
                                          header=http2_header(12, Frame.PUSH_PROMISE))
        with self.assertRaises(ProtocolError):
            proto._read_http_ping(http2_schema(data=b'bad', __flags__=0),
                                  header=http2_header(16, Frame.PING, sid=0))
        with self.assertRaises(ProtocolError):
            proto._read_http_window_update(http2_schema(size={'incr': 1}),
                                           header=http2_header(12, Frame.WINDOW_UPDATE))

    def test_httpv2_read_validates_common_frame_header_rules(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(HTTPv2)

        proto.__header__ = http2_header(8, Frame.DATA, sid=1)
        with self.assertRaises(ProtocolError):
            proto.read(length=8)

        proto.__header__ = http2_header(17, Frame.PING, sid=1)
        with self.assertRaises(ProtocolError):
            proto.read(length=17)

        proto.__header__ = http2_header(9, Frame.DATA, sid=1)
        proto.__header__.frame = http2_schema(pad_len=0, data=b'', __flags__=0)
        self.assertEqual(proto.read(length=9).to_dict()['type'], Frame.DATA)
        proto._data = b'\x00' * 9
        proto.__cached__ = {}
        self.assertEqual(proto.read().to_dict()['type'], Frame.DATA)

    def test_httpv2_frame_constructors_cover_all_frame_types_and_branches(self) -> None:
        from pcapkit.const.http.error_code import ErrorCode
        from pcapkit.const.http.frame import Frame
        from pcapkit.const.http.setting import Setting
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
        from pcapkit.protocols.data.application.httpv2 import PingFrame, PingFrameFlags
        from pcapkit.protocols.schema.application import httpv2 as schema_httpv2
        from pcapkit.protocols.schema.application.httpv2 import DataFrame, SettingPair
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(HTTPv2)

        none_schema, none_flags = proto._make_http_none(SimpleNamespace(data=b'unknown'))
        self.assertEqual(none_schema.data, b'unknown')
        self.assertEqual(none_flags, 0)
        none_direct_schema, none_direct_flags = proto._make_http_none(data=b'direct')
        self.assertEqual(none_direct_schema.data, b'direct')
        self.assertEqual(none_direct_flags, 0)

        data_schema, data_flags = proto._make_http_data(end_stream=True, pad_len=2, data=b'data')
        self.assertTrue(data_flags & DataFrame.Flags.END_STREAM)
        self.assertTrue(data_flags & DataFrame.Flags.PADDED)
        self.assertEqual(data_schema.pad_len, 2)
        data_plain_schema, data_plain_flags = proto._make_http_data(data=b'plain')
        self.assertEqual(data_plain_schema.data, b'plain')
        self.assertEqual(data_plain_flags, 0)
        frame_schema, frame_flags = proto._make_http_data(SimpleNamespace(pad_len=3, data=b'from-frame'))
        self.assertEqual(frame_schema.data, b'from-frame')
        self.assertTrue(frame_flags & DataFrame.Flags.PADDED)

        headers_schema, headers_flags = proto._make_http_headers(
            end_stream=True,
            end_headers=True,
            pad_len=1,
            excl_dep=True,
            sid_dep=7,
            weight=5,
            fragment=b'headers',
        )
        self.assertEqual(headers_schema.stream_dep['sid'], 7)
        self.assertEqual(headers_schema.weight, 4)
        self.assertEqual(headers_flags, 0x2D)
        headers_frame_schema, headers_frame_flags = proto._make_http_headers(SimpleNamespace(
            flags=SimpleNamespace(PRIORITY=True, END_HEADERS=True, END_STREAM=False),
            pad_len=0,
            excl_dependency=False,
            stream_dependency=9,
            weight=1,
            fragment=b'from-frame',
        ))
        self.assertEqual(headers_frame_schema.fragment, b'from-frame')
        self.assertEqual(headers_frame_flags, 0x24)
        headers_plain_schema, headers_plain_flags = proto._make_http_headers(fragment=b'plain')
        self.assertEqual(headers_plain_schema.fragment, b'plain')
        self.assertEqual(headers_plain_flags, 0)

        priority_schema, _ = proto._make_http_priority(sid_dep=3, excl_dep=True, weight=10)
        self.assertEqual(priority_schema.stream['sid'], 3)
        self.assertEqual(priority_schema.weight, 9)
        priority_frame_schema, _ = proto._make_http_priority(SimpleNamespace(
            excl_dependency=False,
            stream_dependency=4,
            weight=1,
        ))
        self.assertEqual(priority_frame_schema.stream['sid'], 4)

        rst_schema, _ = proto._make_http_rst_stream(error=ErrorCode.CANCEL)
        self.assertEqual(rst_schema.error, ErrorCode.CANCEL)
        rst_frame_schema, _ = proto._make_http_rst_stream(SimpleNamespace(error=ErrorCode.NO_ERROR))
        self.assertEqual(rst_frame_schema.error, ErrorCode.NO_ERROR)

        settings_list_schema, settings_list_flags = proto._make_http_settings(
            ack=True,
            settings=[
                SettingPair(id=Setting.HEADER_TABLE_SIZE, value=4096),
                (Setting.ENABLE_PUSH, 0),
            ],
        )
        self.assertEqual(settings_list_flags, 0x01)
        self.assertEqual([item.id for item in settings_list_schema.settings],
                         [Setting.HEADER_TABLE_SIZE, Setting.ENABLE_PUSH])
        settings_bytes_schema, _ = proto._make_http_settings(settings=b'\x00\x01\x00\x00\x10\x00')
        self.assertEqual(settings_bytes_schema.settings, b'\x00\x01\x00\x00\x10\x00')
        settings_dict_schema, _ = proto._make_http_settings(
            SimpleNamespace(flags=SimpleNamespace(ACK=False),
                            settings=OrderedMultiDict([(Setting.MAX_FRAME_SIZE, 16384)])),
        )
        self.assertEqual(settings_dict_schema.settings[0].id, Setting.MAX_FRAME_SIZE)
        with self.assertRaises(ProtocolError):
            proto._make_http_settings(settings=None)

        push_schema, push_flags = proto._make_http_push_promise(
            end_headers=True,
            pad_len=1,
            promised_sid=11,
            fragment=b'push',
        )
        self.assertEqual(push_schema.stream['sid'], 11)
        self.assertEqual(push_flags, 0x0C)
        push_frame_schema, push_frame_flags = proto._make_http_push_promise(SimpleNamespace(
            flags=SimpleNamespace(END_HEADERS=False),
            pad_len=2,
            promised_sid=12,
            fragment=b'from-frame',
        ))
        self.assertEqual(push_frame_schema.stream['sid'], 12)
        self.assertEqual(push_frame_flags, 0x08)
        push_plain_schema, push_plain_flags = proto._make_http_push_promise(
            promised_sid=13,
            fragment=b'plain',
        )
        self.assertEqual(push_plain_schema.stream['sid'], 13)
        self.assertEqual(push_plain_flags, 0)

        ping_schema, ping_flags = proto._make_http_ping(ack=True, opaque_data=b'12345678')
        self.assertEqual(ping_schema.data, b'12345678')
        self.assertEqual(ping_flags, 0x01)
        ping_frame_schema, ping_frame_flags = proto._make_http_ping(SimpleNamespace(
            flags=SimpleNamespace(ACK=False),
            data=b'abcdefgh',
        ))
        self.assertEqual(ping_frame_schema.data, b'abcdefgh')
        self.assertEqual(ping_frame_flags, 0)

        goaway_schema, _ = proto._make_http_goaway(
            last_sid=13,
            error=ErrorCode.NO_ERROR,
            debug_data=b'bye',
        )
        self.assertEqual(goaway_schema.stream['sid'], 13)
        self.assertEqual(goaway_schema.debug, b'bye')
        goaway_frame_schema, _ = proto._make_http_goaway(SimpleNamespace(
            last_sid=14,
            error=ErrorCode.PROTOCOL_ERROR,
            debug_data=b'frame',
        ))
        self.assertEqual(goaway_frame_schema.stream['sid'], 14)

        window_schema, _ = proto._make_http_window_update(incr=65535)
        self.assertEqual(window_schema.size['incr'], 65535)
        window_frame_schema, _ = proto._make_http_window_update(SimpleNamespace(increment=7))
        self.assertEqual(window_frame_schema.size['incr'], 7)

        continuation_schema, continuation_flags = proto._make_http_continuation(
            end_headers=True,
            fragment=b'cont',
        )
        self.assertEqual(continuation_schema.fragment, b'cont')
        self.assertEqual(continuation_flags, 0x04)
        continuation_frame_schema, continuation_frame_flags = proto._make_http_continuation(SimpleNamespace(
            flags=SimpleNamespace(END_HEADERS=False),
            fragment=b'from-frame',
        ))
        self.assertEqual(continuation_frame_schema.fragment, b'from-frame')
        self.assertEqual(continuation_frame_flags, 0)

        made_from_dict = proto.make(type=Frame.HEADERS, sid=1, frame={
            'end_headers': True,
            'sid_dep': 0,
            'fragment': b'h',
        })
        self.assertEqual(made_from_dict.type, Frame.HEADERS)
        self.assertEqual(made_from_dict.flags['bit_2'], 1)
        made_from_bytes = proto.make(type=Frame.DATA, sid=1, frame=b'raw')
        self.assertEqual(made_from_bytes.length, 12)
        self.assertEqual(made_from_bytes.frame, b'raw')
        made_from_schema = proto.make(type=Frame.DATA, sid=1,
                                      frame=schema_httpv2.UnassignedFrame(data=b'schema'))
        self.assertEqual(made_from_schema.length, 15)
        ping_data = PingFrame(
            length=17,
            type=Frame.PING,
            flags=PingFrameFlags(ACK=True),
            sid=0,
            data=b'12345678',
        )
        ping_data.flags.__update__({'__value__': 0x01})
        made_from_data = proto.make(type=Frame.PING, sid=0, frame=ping_data)
        self.assertEqual(made_from_data.type, Frame.PING)
        self.assertEqual(made_from_data.flags['bit_0'], 1)
        self.assertEqual(proto._make_http_length(schema_httpv2.UnassignedFrame(data=b'xx'), 0), 2)
        self.assertEqual(proto._make_http_length(data_schema, data_flags), 7)
        self.assertEqual(proto._make_http_length(headers_schema, headers_flags), 14)
        self.assertEqual(proto._make_http_length(priority_schema, 0), 5)
        self.assertEqual(proto._make_http_length(rst_schema, 0), 4)
        self.assertEqual(proto._make_http_length(settings_list_schema, settings_list_flags), 12)
        self.assertEqual(proto._make_http_length(settings_bytes_schema, 0), 6)
        self.assertEqual(proto._make_http_length(push_schema, push_flags), 10)
        self.assertEqual(proto._make_http_length(ping_schema, ping_flags), 8)
        self.assertEqual(proto._make_http_length(goaway_schema, 0), 11)
        self.assertEqual(proto._make_http_length(window_schema, 0), 4)
        self.assertEqual(proto._make_http_length(continuation_schema, continuation_flags), 4)
        self.assertEqual(proto._make_http_length(SimpleNamespace(pack=lambda: b'abc'), 0), 3)
        with self.assertRaises(ProtocolError):
            proto.make(type=Frame.DATA, frame=object())

    def test_httpv2_callable_frame_registry_paths(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2
        from pcapkit.protocols.schema.application import httpv2 as schema_httpv2

        custom = Frame.get(250)
        frame_registry = HTTPv2.__dict__['__frame__']
        original = frame_registry.get(custom)

        def read_frame(frame, *, header):
            return SimpleNamespace(type=header.type, length=header.length,
                                   sid=header.stream['sid'], data=frame.data)

        def make_frame(frame=None, *, data=b''):
            if frame is not None:
                data = frame.data
            return schema_httpv2.UnassignedFrame(data=data), 0

        proto = object.__new__(HTTPv2)
        try:
            with mock.patch('pcapkit.protocols.application.httpv2.warn') as warn:
                HTTPv2.register_frame(custom, (read_frame, make_frame))
            warn.assert_not_called()

            proto.__header__ = http2_header(9, custom, sid=3)
            proto.__header__.frame = SimpleNamespace(data=b'read')
            parsed = proto.read(length=9)
            self.assertEqual(parsed.data, b'read')
            self.assertEqual(parsed.sid, 3)

            made = proto.make(type=custom, sid=3, frame={'data': b'made'})
            self.assertEqual(made.frame.data, b'made')
            self.assertEqual(made.length, 13)
        finally:
            if original is None:
                frame_registry.pop(custom, None)
            else:
                frame_registry[custom] = original

    def test_httpv2_schema_selector_and_frame_post_process_flags(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.schema.application import httpv2 as schema_httpv2
        from pcapkit.protocols.schema.application.httpv2 import DataFrame

        field = schema_httpv2.http_frame_selector({
            'type': Frame.DATA,
            '__length__': 4,
        })
        self.assertIs(field.schema, DataFrame)
        self.assertEqual(field.length, 4)

        frame = DataFrame(pad_len=0, data=b'data')
        frame.post_process({
            'flags': {
                'bit_0': 1,
                'bit_1': 0,
                'bit_2': 0,
                'bit_3': 1,
                'bit_4': 0,
                'bit_5': 0,
                'bit_6': 0,
                'bit_7': 0,
            },
        })

        self.assertTrue(frame.__flags__ & DataFrame.Flags.END_STREAM)
        self.assertTrue(frame.__flags__ & DataFrame.Flags.PADDED)

        plain = DataFrame(pad_len=0, data=b'plain')
        plain.post_process({
            'flags': {f'bit_{bit}': 0 for bit in range(8)},
        })
        self.assertEqual(plain.__flags__, 0)

    def test_application_base_rejects_next_layer_operations(self) -> None:
        from pcapkit.protocols.application.application import Application
        from pcapkit.utilities.exceptions import IntError, UnsupportedCall

        class DemoApplication(Application):
            @property
            def name(self) -> str:
                return 'Demo Application'

            @property
            def length(self) -> int:
                return 0

            def read(self, length: int | None = None, **kwargs: object) -> object:
                raise NotImplementedError

            def make(self, **kwargs: object) -> object:
                raise NotImplementedError

        app = object.__new__(DemoApplication)

        with self.assertRaises(IntError):
            DemoApplication.__index__()
        with self.assertRaises(UnsupportedCall):
            DemoApplication._decode_next_layer(app, object())
        with self.assertRaises(UnsupportedCall):
            DemoApplication._import_next_layer(app, 80)


if __name__ == '__main__':
    unittest.main()
