# -*- coding: utf-8 -*-
"""One :class:`~pcapkit.corekit.fields.numbers.PortEnumField` for TCP, UDP and SCTP.

GitHub issue #1516. The TCP, UDP and SCTP schemas each defined their own
``PortEnumField``, three copies that differed only in the
:class:`~pcapkit.const.reg.apptype.TransportProtocol` member hard-coded into
``post_process``. The owner ruled that they become one field in
:mod:`pcapkit.corekit.fields.numbers`, beside
:class:`~pcapkit.corekit.fields.numbers.EnumField`, with a ``proto`` parameter
each schema fills in with its own transport.

These tests pin the shared field: that each schema uses it with its own
transport, that ``proto`` alone decides which registry a port resolves in, that
an unassigned port resolves without growing the registry, and that packing and
unpacking close.

"""
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any


class PortEnumFieldTests(unittest.TestCase):
    """The shared port field, over each transport it serves."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _field(self, proto: 'Any') -> 'Any':
        from pcapkit.const.reg.apptype import AppType
        from pcapkit.corekit.fields.numbers import PortEnumField

        return PortEnumField(length=2, namespace=AppType, proto=proto)

    def _protos(self) -> 'tuple[Any, ...]':
        from pcapkit.const.reg.apptype import TransportProtocol

        return (TransportProtocol.tcp, TransportProtocol.udp, TransportProtocol.sctp)

    def test_it_is_public_beside_enum_field(self) -> None:
        from pcapkit.corekit.fields import numbers

        self.assertIn('PortEnumField', numbers.__all__)
        self.assertTrue(issubclass(numbers.PortEnumField, numbers.EnumField))

    def test_each_schema_uses_the_shared_field_with_its_own_transport(self) -> None:
        from pcapkit.const.reg.apptype import TransportProtocol
        from pcapkit.corekit.fields.numbers import PortEnumField
        from pcapkit.protocols.schema.transport.sctp import SCTP
        from pcapkit.protocols.schema.transport.tcp import TCP
        from pcapkit.protocols.schema.transport.udp import UDP

        for schema, proto in ((TCP, TransportProtocol.tcp), (UDP, TransportProtocol.udp),
                              (SCTP, TransportProtocol.sctp)):
            for name in ('srcport', 'dstport'):
                with self.subTest(schema=schema.__name__, field=name):
                    field = schema.__fields__[name]
                    self.assertIs(type(field), PortEnumField)
                    self.assertIs(field._proto, proto)  # pylint: disable=protected-access

    def test_proto_is_required(self) -> None:
        from pcapkit.const.reg.apptype import AppType
        from pcapkit.corekit.fields.numbers import PortEnumField

        with self.assertRaises(TypeError):
            PortEnumField(length=2, namespace=AppType)  # type: ignore[call-arg] # pylint: disable=missing-kwoa

    def test_proto_decides_the_registry_a_declared_port_resolves_in(self) -> None:
        """The same two octets, three transports, three answers.

        Port 512 is ``exec`` on TCP and ``biff`` on UDP, so a field that ignored
        ``proto`` could not get both right.

        """
        from pcapkit.const.reg.apptype import AppType, TransportProtocol

        for proto, port, octets, svc in ((TransportProtocol.tcp, 512, b'\x02\x00', 'exec'),
                                         (TransportProtocol.udp, 512, b'\x02\x00', 'biff'),
                                         (TransportProtocol.tcp, 80, b'\x00\x50', 'http'),
                                         (TransportProtocol.udp, 53, b'\x00\x35', 'domain'),
                                         (TransportProtocol.sctp, 9, b'\x00\x09', 'discard')):
            with self.subTest(proto=proto.name, port=port):
                resolved = self._field(proto).unpack(octets, {})
                self.assertIs(resolved, AppType.get(port, proto=proto))
                self.assertIsInstance(resolved, AppType.__registries__[proto])
                self.assertEqual((resolved.svc, resolved.port, resolved.proto), (svc, port, proto))

    def test_an_unknown_port_resolves_unregistered_in_its_own_transport(self) -> None:
        from pcapkit.const.reg.apptype import AppType

        for proto in self._protos():
            with self.subTest(proto=proto.name):
                owner = AppType.__registries__[proto]
                before = len(owner.__members__)

                resolved = self._field(proto).unpack(b'\xd4\x31', {})  # 54321

                self.assertIsInstance(resolved, owner)
                self.assertEqual(resolved.name, '<unassigned>')
                self.assertEqual(resolved.value, f'unknown [54321 - {proto.name}]')
                self.assertEqual((resolved.svc, resolved.port, resolved.proto),
                                 ('unknown', 54321, proto))
                self.assertEqual(len(owner.__members__), before)

    def test_pack_takes_a_member_or_a_bare_port(self) -> None:
        from pcapkit.const.reg.apptype import AppType

        for proto in self._protos():
            with self.subTest(proto=proto.name):
                field = self._field(proto)
                self.assertEqual(field.pack(AppType.get(80, proto=proto), {}), b'\x00\x50')
                self.assertEqual(field.pack(80, {}), b'\x00\x50')

    def test_unpack_then_pack_returns_the_octets(self) -> None:
        for proto in self._protos():
            for octets in (b'\x00\x50', b'\x02\x00', b'\xd4\x31', b'\xff\xff', b'\x00\x00'):
                with self.subTest(proto=proto.name, octets=octets):
                    field = self._field(proto)
                    self.assertEqual(field.pack(field.unpack(octets, {}), {}), octets)


if __name__ == '__main__':
    unittest.main()
