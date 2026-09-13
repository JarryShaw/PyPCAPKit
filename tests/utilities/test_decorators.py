from __future__ import annotations

import io
import unittest

from tests._support import bootstrap_core_modules, install_fake_payload_protocols, purge_modules


class DecoratorTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])
        modules = bootstrap_core_modules()
        self.decorators = modules['decorators']
        self.exceptions = modules['exceptions']

    def test_seekset_restores_original_offset(self) -> None:
        class DemoProtocol:
            def __init__(self) -> None:
                self._file = io.BytesIO(b'abcdef')
                self._seekset = 2

            @self.decorators.seekset
            def read_two(self) -> bytes:
                return self._file.read(2)

        protocol = DemoProtocol()
        protocol._file.seek(5)

        self.assertEqual(protocol.read_two(), b'cd')
        self.assertEqual(protocol._file.tell(), 5)

    def test_prepare_converts_bytes_and_populates_packet_metadata(self) -> None:
        class DemoSchema:
            @classmethod
            def pre_unpack(cls, packet: dict[str, object]) -> None:
                packet['prepped'] = True

            def __init__(self, data: bytes) -> None:
                self.data = data

            def post_process(self, packet: dict[str, object]) -> dict[str, object]:
                packet['data'] = self.data
                return packet

            @classmethod
            @self.decorators.prepare
            def unpack(cls, data, length=None, packet=None):
                return cls(data.read())

        packet = DemoSchema.unpack(b'payload', None, None)

        self.assertEqual(packet['__length__'], 7)
        self.assertTrue(packet['prepped'])
        self.assertEqual(packet['data'], b'payload')

    def test_prepare_infers_length_for_stream_and_preserves_packet(self) -> None:
        class DemoSchema:
            @classmethod
            def pre_unpack(cls, packet: dict[str, object]) -> None:
                packet['prepped'] = True

            def __init__(self, data: bytes) -> None:
                self.data = data

            def post_process(self, packet: dict[str, object]) -> dict[str, object]:
                packet['data'] = self.data
                return packet

            @classmethod
            @self.decorators.prepare
            def unpack(cls, data, length=None, packet=None):
                return cls(data.read(length))

        stream = io.BytesIO(b'xxpayload')
        stream.seek(2)
        packet = {'existing': True}
        result = DemoSchema.unpack(stream, None, packet)

        self.assertEqual(result['__length__'], 7)
        self.assertTrue(result['existing'])
        self.assertTrue(result['prepped'])
        self.assertEqual(result['data'], b'payload')

        stream = io.BytesIO(b'payload-extra')
        result = DemoSchema.unpack(stream, 7, None)
        self.assertEqual(result['__length__'], 7)
        self.assertEqual(result['data'], b'payload')

    def test_prepare_raises_eof_for_empty_payloads(self) -> None:
        class DemoSchema:
            @classmethod
            def pre_unpack(cls, packet):
                return None

            def post_process(self, packet):
                return packet

            @classmethod
            @self.decorators.prepare
            def unpack(cls, data, length=None, packet=None):
                return cls()

        with self.assertRaises(EOFError):
            DemoSchema.unpack(b'', None, None)

    def test_beholder_wraps_struct_eof_with_no_payload(self) -> None:
        exceptions = self.exceptions

        class NoPayload:
            def __init__(self, file_, length, error=None) -> None:
                self.file = file_
                self.length = length
                self.error = error

        class Raw(NoPayload):
            pass

        install_fake_payload_protocols(Raw, NoPayload)

        class Header:
            def get_payload(self) -> bytes:
                return b'payload-bytes'

        class DemoProtocol:
            __header__ = Header()

            @self.decorators.beholder
            def decode(self, proto, length=None):
                raise exceptions.StructError('unexpected eof', eof=True)

        result = DemoProtocol().decode(1, 10)

        self.assertIsInstance(result, NoPayload)
        self.assertEqual(result.file, b'payload-bytes')
        self.assertEqual(result.length, 10)
        self.assertEqual(result.error, 'unexpected eof')

    def test_beholder_wraps_other_errors_with_raw(self) -> None:
        class NoPayload:
            def __init__(self, file_, length, error=None) -> None:
                self.file = file_
                self.length = length
                self.error = error

        class Raw(NoPayload):
            pass

        install_fake_payload_protocols(Raw, NoPayload)

        class Header:
            def get_payload(self) -> bytes:
                return b'raw-bytes'

        class DemoProtocol:
            __header__ = Header()

            @self.decorators.beholder
            def decode(self, proto, length=None):
                raise ValueError('broken parser')

        result = DemoProtocol().decode(1, 3)

        self.assertIsInstance(result, Raw)
        self.assertEqual(result.file, b'raw-bytes')
        self.assertEqual(result.length, 3)
        self.assertEqual(result.error, 'broken parser')

    def test_beholder_verbose_mode_prints_traceback(self) -> None:
        class NoPayload:
            def __init__(self, file_, length, error=None) -> None:
                self.file = file_
                self.length = length
                self.error = error

        class Raw(NoPayload):
            pass

        install_fake_payload_protocols(Raw, NoPayload)

        class Header:
            def get_payload(self) -> bytes:
                return b'raw-bytes'

        class DemoProtocol:
            __header__ = Header()

            @self.decorators.beholder
            def decode(self, proto, length=None):
                raise ValueError('broken parser')

        from unittest import mock

        with mock.patch.object(self.decorators, 'VERBOSE', True):
            with mock.patch.object(self.decorators.traceback, 'print_exc') as print_exc:
                result = DemoProtocol().decode(1, 3)

        self.assertIsInstance(result, Raw)
        print_exc.assert_called_once()

    def test_beholder_defaults_length_when_argument_is_missing(self) -> None:
        class NoPayload:
            def __init__(self, file_, length, error=None) -> None:
                self.file = file_
                self.length = length
                self.error = error

        class Raw(NoPayload):
            pass

        install_fake_payload_protocols(Raw, NoPayload)

        class Header:
            def get_payload(self) -> bytes:
                return b'raw-bytes'

        class DemoProtocol:
            __header__ = Header()

            @self.decorators.beholder
            def decode(self, proto):
                raise ValueError('broken parser')

        result = DemoProtocol().decode(1)

        self.assertIsInstance(result, Raw)
        self.assertIsNone(result.length)


if __name__ == '__main__':
    unittest.main()
