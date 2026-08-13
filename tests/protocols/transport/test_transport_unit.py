from __future__ import annotations

import collections
import importlib.util
import io
import unittest
from unittest import mock

from tests._support import install_fake_payload_protocols, purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TransportUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_register_validates_protocols_and_abstract_base(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport.transport import Transport
        from pcapkit.utilities.exceptions import UnsupportedCall

        class DummyTransport(Transport):
            __proto__ = collections.defaultdict(lambda: Raw, {80: Raw})

            @property
            def name(self) -> str:
                return 'Dummy Transport'

            @property
            def length(self) -> int:
                return 0

            def read(self, length: int | None = None, **kwargs: object) -> object:
                raise NotImplementedError

            def make(self, **kwargs: object) -> object:
                raise NotImplementedError

            @classmethod
            def __index__(cls) -> int:
                return 250

        inst = object.__new__(DummyTransport)
        self.assertEqual(inst.layer, 'Transport')

        with self.assertRaises(UnsupportedCall):
            Transport.register(1, Raw)
        with self.assertRaises(TypeError):
            DummyTransport.register(81, object)  # type: ignore[arg-type]

        DummyTransport.register(82, ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'))
        self.assertIs(DummyTransport.__dict__['__proto__'][82], Raw)
        with mock.patch('pcapkit.protocols.transport.transport.warn') as warn:
            DummyTransport.register(80, Raw)
        warn.assert_called_once()

    def test_analyze_prefers_source_port_match(self) -> None:
        from pcapkit.protocols.transport.transport import Transport

        class SourceProtocol:
            def __init__(self, payload_io: io.BytesIO, length: int, **kwargs: object) -> None:
                self.payload = payload_io.read()
                self.length = length
                self.kwargs = kwargs

        class DestinationProtocol:
            def __init__(self, payload_io: io.BytesIO, length: int, **kwargs: object) -> None:
                self.payload = payload_io.read()
                self.length = length
                self.kwargs = kwargs

        class DummyTransport(Transport):
            __proto__ = collections.defaultdict(lambda: DestinationProtocol, {
                53: SourceProtocol,
                5353: DestinationProtocol,
            })

            @property
            def name(self) -> str:
                return 'Dummy Transport'

            @property
            def length(self) -> int:
                return 0

            def read(self, length: int | None = None, **kwargs: object) -> object:
                raise NotImplementedError

            def make(self, **kwargs: object) -> object:
                raise NotImplementedError

        report = DummyTransport.analyze((53, 5353), b'payload', marker=True)

        self.assertIsInstance(report, SourceProtocol)
        self.assertEqual(report.payload, b'payload')
        self.assertEqual(report.length, 7)
        self.assertEqual(report.kwargs['marker'], True)

    def test_analyze_falls_back_to_destination_port_match(self) -> None:
        from pcapkit.protocols.transport.transport import Transport

        class DestinationProtocol:
            def __init__(self, payload_io: io.BytesIO, length: int, **kwargs: object) -> None:
                self.payload = payload_io.read()
                self.length = length

        class DummyTransport(Transport):
            __proto__ = collections.defaultdict(lambda: DestinationProtocol, {
                80: DestinationProtocol,
            })

            @property
            def name(self) -> str:
                return 'Dummy Transport'

            @property
            def length(self) -> int:
                return 0

            def read(self, length: int | None = None, **kwargs: object) -> object:
                raise NotImplementedError

            def make(self, **kwargs: object) -> object:
                raise NotImplementedError

        report = DummyTransport.analyze((54321, 80), b'hello')

        self.assertIsInstance(report, DestinationProtocol)
        self.assertEqual(report.payload, b'hello')
        self.assertEqual(report.length, 5)

    def test_analyze_uses_no_payload_after_eof_struct_error(self) -> None:
        from pcapkit.protocols.transport.transport import Transport
        from pcapkit.utilities.exceptions import StructError

        class EOFProtocol:
            def __init__(self, payload_io: io.BytesIO, length: int, **kwargs: object) -> None:
                raise StructError('truncated payload', eof=True, quiet=True)

        class FakeRaw:
            def __init__(self, payload_io: io.BytesIO, length: int, **kwargs: object) -> None:
                self.payload = payload_io.read()
                self.length = length

        class FakeNoPayload:
            def __init__(self, payload_io: io.BytesIO, length: int, **kwargs: object) -> None:
                self.payload = payload_io.read()
                self.length = length

        class DummyTransport(Transport):
            __proto__ = collections.defaultdict(lambda: EOFProtocol, {80: EOFProtocol})

            @property
            def name(self) -> str:
                return 'Dummy Transport'

            @property
            def length(self) -> int:
                return 0

            def read(self, length: int | None = None, **kwargs: object) -> object:
                raise NotImplementedError

            def make(self, **kwargs: object) -> object:
                raise NotImplementedError

        install_fake_payload_protocols(FakeRaw, FakeNoPayload)

        with mock.patch('pcapkit.protocols.transport.transport.logger.error') as logger_error:
            report = DummyTransport.analyze((80, 60000), b'data')

        self.assertIsInstance(report, FakeNoPayload)
        self.assertEqual(report.payload, b'data')
        self.assertGreaterEqual(logger_error.call_count, 1)
        self.assertEqual(logger_error.call_args_list[-1].args[0], 'truncated payload')

    def test_analyze_uses_raw_after_non_struct_error(self) -> None:
        from pcapkit.protocols.transport.transport import Transport

        class BrokenProtocol:
            def __init__(self, payload_io: io.BytesIO, length: int, **kwargs: object) -> None:
                raise ValueError('boom')

        class FakeRaw:
            def __init__(self, payload_io: io.BytesIO, length: int, **kwargs: object) -> None:
                self.payload = payload_io.read()
                self.length = length

        class FakeNoPayload:
            def __init__(self, payload_io: io.BytesIO, length: int, **kwargs: object) -> None:
                self.payload = payload_io.read()
                self.length = length

        class DummyTransport(Transport):
            __proto__ = collections.defaultdict(lambda: BrokenProtocol, {443: BrokenProtocol})

            @property
            def name(self) -> str:
                return 'Dummy Transport'

            @property
            def length(self) -> int:
                return 0

            def read(self, length: int | None = None, **kwargs: object) -> object:
                raise NotImplementedError

            def make(self, **kwargs: object) -> object:
                raise NotImplementedError

        install_fake_payload_protocols(FakeRaw, FakeNoPayload)

        with mock.patch('pcapkit.protocols.transport.transport.logger.error') as logger_error:
            report = DummyTransport.analyze((443, 65000), b'body')

        self.assertIsInstance(report, FakeRaw)
        self.assertEqual(report.payload, b'body')
        logger_error.assert_called_once()

    def test_analyze_resolves_module_descriptor_protocol(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.transport.transport import Transport

        class DummyTransport(Transport):
            __proto__ = collections.defaultdict(
                lambda: None,
                {80: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw')},
            )

            @property
            def name(self) -> str:
                return 'Dummy Transport'

            @property
            def length(self) -> int:
                return 0

            def read(self, length: int | None = None, **kwargs: object) -> object:
                raise NotImplementedError

            def make(self, **kwargs: object) -> object:
                raise NotImplementedError

        report = DummyTransport.analyze((12345, 80), b'body')

        self.assertEqual(report.data, b'body')

    def test_decode_next_layer_prefers_lower_registered_port(self) -> None:
        from pcapkit.protocols.protocol import ProtocolBase
        from pcapkit.protocols.transport.transport import Transport

        class DummyTransport(Transport):
            __proto__ = collections.defaultdict(lambda: None, {80: object, 5353: object})

            @property
            def name(self) -> str:
                return 'Dummy Transport'

            @property
            def length(self) -> int:
                return 0

            def read(self, length: int | None = None, **kwargs: object) -> object:
                raise NotImplementedError

            def make(self, **kwargs: object) -> object:
                raise NotImplementedError

            @classmethod
            def __index__(cls) -> int:
                return 0

        transport = object.__new__(DummyTransport)
        data = object()

        with mock.patch.object(ProtocolBase, '_decode_next_layer', return_value='decoded') as decode:
            result = DummyTransport._decode_next_layer(transport, data, (5353, 80), 12, packet={'id': 1})

        self.assertEqual(result, 'decoded')
        decode.assert_called_once_with(data, 80, 12, packet={'id': 1})

    def test_decode_next_layer_uses_higher_registered_port_when_lower_unknown(self) -> None:
        from pcapkit.protocols.protocol import ProtocolBase
        from pcapkit.protocols.transport.transport import Transport

        class DummyTransport(Transport):
            __proto__ = collections.defaultdict(lambda: None, {2000: object})

            @property
            def name(self) -> str:
                return 'Dummy Transport'

            @property
            def length(self) -> int:
                return 0

            def read(self, length: int | None = None, **kwargs: object) -> object:
                raise NotImplementedError

            def make(self, **kwargs: object) -> object:
                raise NotImplementedError

            @classmethod
            def __index__(cls) -> int:
                return 0

        transport = object.__new__(DummyTransport)
        data = object()

        with mock.patch.object(ProtocolBase, '_decode_next_layer', return_value='decoded') as decode:
            result = DummyTransport._decode_next_layer(transport, data, (1000, 2000), 12)

        self.assertEqual(result, 'decoded')
        decode.assert_called_once_with(data, 2000, 12, packet=None)


if __name__ == '__main__':
    unittest.main()
