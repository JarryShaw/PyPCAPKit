"""Unit tests for payload dispatch on :class:`~pcapkit.protocols.application.application.Application`.

:class:`Application` encodes "no further *protocol* layer above this one". That
forbids dispatching on a protocol number, but not handing the undissected rest
of the packet to :class:`~pcapkit.protocols.misc.raw.Raw`, which is what the
``-1`` sentinel asks for. The tests pin both halves: the sentinel is accepted
and resolves to ``Raw``, and a real protocol number is still refused.

"""

from __future__ import annotations

import importlib.util
import unittest

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ApplicationDispatchUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    @staticmethod
    def _protocol_class(proto: int | None):
        """An :class:`Application` whose ``read`` dispatches the rest on ``proto``, or not at all."""
        from pcapkit.corekit.fields.misc import PayloadField
        from pcapkit.corekit.fields.strings import BytesField
        from pcapkit.corekit.infoclass import info_final
        from pcapkit.protocols.application.application import Application
        from pcapkit.protocols.data.data import Data
        from pcapkit.protocols.schema.schema import Schema, schema_final

        @info_final
        class DummyData(Data):
            value: int = 0

        @schema_final
        class DummySchema(Schema):
            head: bytes = BytesField(length=2, default=b'')
            payload: bytes = PayloadField(length=lambda packet: packet['__length__'] - 2, default=b'')

        class DummyApplication(Application[DummyData, DummySchema],
                               schema=DummySchema, data=DummyData):
            @property
            def name(self) -> str:
                return 'Dummy Application'

            @property
            def length(self) -> int:
                return 2

            def read(self, length: int | None = None, **kwargs: object) -> DummyData:
                data = DummyData(value=1)
                if proto is None:
                    return data
                return self._decode_next_layer(data, proto, len(self._data) - 2)

            def make(self, packet: bytes = b'ab', **kwargs: object) -> DummySchema:
                return DummySchema(head=packet[:2], payload=packet[2:])

        return DummyApplication

    def test_sentinel_dispatches_remainder_to_raw(self) -> None:
        from pcapkit.protocols.misc.raw import Raw

        proto = self._protocol_class(-1)(packet=b'abtrailer')

        self.assertEqual(proto.layer, 'Application')
        self.assertIsInstance(proto.payload, Raw)
        self.assertEqual(bytes(proto.payload), b'trailer')
        self.assertIs(proto.info.__next_type__, Raw)
        self.assertEqual(proto.info.__next_name__, 'raw')
        # the chain keeps the dispatched layer rather than being reset
        self.assertIn('Raw', str(proto.protochain))

    def test_sentinel_with_nothing_left_is_no_payload(self) -> None:
        from pcapkit.protocols.misc.null import NoPayload

        proto = self._protocol_class(-1)(packet=b'ab')

        self.assertIsInstance(proto.payload, NoPayload)

    def test_undispatched_application_still_has_no_payload(self) -> None:
        from pcapkit.protocols.misc.null import NoPayload

        proto = self._protocol_class(None)(packet=b'abtrailer')

        self.assertIsInstance(proto.payload, NoPayload)
        self.assertEqual(str(proto.protochain), 'DummyApplication')

    def test_real_protocol_number_is_still_refused(self) -> None:
        from pcapkit.utilities.exceptions import UnsupportedCall

        for number in (0, 6, 17, 0x0800):
            with self.subTest(proto=number):
                with self.assertRaises(UnsupportedCall):
                    self._protocol_class(number)(packet=b'abtrailer')

    def test_import_next_layer_accepts_only_the_sentinel(self) -> None:
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities.exceptions import UnsupportedCall

        proto = object.__new__(self._protocol_class(-1))
        proto._data = b'abtrailer'
        proto._sigterm = False
        proto._exlayer = proto._exproto = proto._exctx = None
        proto._get_payload = lambda: b'trailer'  # type: ignore[method-assign]

        self.assertIsInstance(proto._import_next_layer(-1, 7), Raw)
        for number in (0, 6, 17, 0x0800):
            with self.subTest(proto=number):
                with self.assertRaises(UnsupportedCall):
                    proto._import_next_layer(number, 7)
                with self.assertRaises(UnsupportedCall):
                    proto._decode_next_layer(None, number, 7)


if __name__ == '__main__':
    unittest.main()
