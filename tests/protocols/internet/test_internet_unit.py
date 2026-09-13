from __future__ import annotations

import collections
import importlib.util
from types import SimpleNamespace
import unittest
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class MutableInfo(dict):
    __getattr__ = dict.__getitem__
    __update__ = dict.update


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class InternetBaseUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _make_internet_class(self, default_protocol: type | None = None):
        from pcapkit.protocols.internet.internet import Internet

        class DummyInternet(Internet):
            __proto__ = collections.defaultdict(lambda: default_protocol)

            @property
            def name(self) -> str:
                return 'Dummy Internet'

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

        return DummyInternet

    def test_layer_register_and_protocol_byte_reader(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.internet.ip import IP
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities.exceptions import RegistryError

        DummyInternet = self._make_internet_class()
        proto = object.__new__(DummyInternet)
        proto._read_unpack = lambda size: TransType.TCP.value

        self.assertEqual(IP.id(), ('IPv4', 'IPv6'))
        self.assertEqual(proto.layer, 'Internet')
        self.assertEqual(proto._read_protos(1), TransType.TCP)

        DummyInternet.register(TransType.get(250), Raw)
        self.assertIs(DummyInternet.__dict__['__proto__'][TransType.get(250)], Raw)
        DummyInternet.register(TransType.get(251), ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'))
        self.assertIs(DummyInternet.__dict__['__proto__'][TransType.get(251)], Raw)
        with self.assertRaises(RegistryError):
            DummyInternet.register(TransType.get(252), object)  # type: ignore[arg-type]
        with mock.patch('pcapkit.protocols.internet.internet.warn') as warn:
            DummyInternet.register(TransType.get(250), Raw)
        warn.assert_called_once()

    def test_decode_next_layer_updates_info_and_protochain(self) -> None:
        from pcapkit.corekit.protochain import ProtoChain

        DummyInternet = self._make_internet_class()
        proto = object.__new__(DummyInternet)

        next_layer = SimpleNamespace(
            info=MutableInfo(value=1),
            protochain=None,
            info_name='payload',
        )
        base_chain = ProtoChain(DummyInternet, 'DummyInternet')
        with mock.patch.object(DummyInternet, '_import_next_layer', return_value=next_layer) as importer:
            info = DummyInternet._decode_next_layer(
                proto,
                MutableInfo(),
                17,
                4,
                packet={'id': 1},
                version=6,
                ipv6_exthdr=base_chain,
                payload=b'data',
            )

        importer.assert_called_once_with(17, 4, packet={'id': 1}, version=6, payload=b'data')
        self.assertEqual(info['payload'].value, 1)
        self.assertIs(info['__next_type__'], type(next_layer))
        self.assertEqual(info['__next_name__'], 'payload')
        self.assertIs(proto._next, next_layer)
        self.assertIn('DummyInternet', str(proto._protos))

        next_chain = ProtoChain(DummyInternet, 'Next')
        next_layer.protochain = next_chain
        with mock.patch.object(DummyInternet, '_import_next_layer', return_value=next_layer):
            DummyInternet._decode_next_layer(proto, MutableInfo(), 17, 4,
                                             ipv6_exthdr=base_chain)
        self.assertIn('DummyInternet', str(proto._protos))

        with mock.patch.object(DummyInternet, '_import_next_layer', return_value=next_layer):
            DummyInternet._decode_next_layer(proto, MutableInfo(), 17, 4)
        self.assertNotIn('DummyInternet:DummyInternet', str(proto._protos))

    def test_import_next_layer_branches(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.module import ModuleDescriptor

        class FakePayload:
            def __init__(self, file_: bytes, length: int, **kwargs: object) -> None:
                self.file = file_
                self.length = length
                self.kwargs = kwargs

        DummyInternet = self._make_internet_class(FakePayload)
        DummyInternet.__dict__['__proto__'][TransType.get(250)] = FakePayload
        DummyInternet.__dict__['__proto__'][TransType.get(251)] = ModuleDescriptor(
            'pcapkit.protocols.misc.raw',
            'Raw',
        )

        proto = object.__new__(DummyInternet)
        proto._sigterm = False
        proto._exlayer = 'Internet'
        proto._exproto = 'dummy'
        proto.__header__ = SimpleNamespace(get_payload=lambda: b'header-payload')

        empty = DummyInternet._import_next_layer(proto, TransType.TCP, length=0, payload=b'')
        self.assertEqual(empty.alias, 'NoPayload')

        direct = DummyInternet._import_next_layer(proto, TransType.get(250), payload=b'direct')
        self.assertIsInstance(direct, FakePayload)
        self.assertEqual(direct.file, b'direct')
        self.assertEqual(direct.length, 6)
        self.assertEqual(direct.kwargs['layer'], 'Internet')

        proto._sigterm = True
        raw = DummyInternet._import_next_layer(proto, TransType.get(250), length=3, payload=b'raw')
        self.assertEqual(raw.data, b'raw')

        proto._sigterm = False
        module = DummyInternet._import_next_layer(proto, TransType.get(251), length=4, payload=b'mod!')
        self.assertEqual(module.data, b'mod!')
        self.assertNotIsInstance(DummyInternet.__dict__['__proto__'][TransType.get(251)], ModuleDescriptor)

        from_header = DummyInternet._import_next_layer(proto, TransType.get(250))
        self.assertEqual(from_header.file, b'header-payload')
        self.assertEqual(from_header.length, len(b'header-payload'))


if __name__ == '__main__':
    unittest.main()
