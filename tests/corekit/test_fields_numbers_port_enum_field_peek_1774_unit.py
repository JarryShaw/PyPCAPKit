# -*- coding: utf-8 -*-
"""Why :meth:`~pcapkit.corekit.fields.numbers.PortEnumField.post_process` peeks.

GitHub issue #1774. The field looks a port up in the registry rows and in
``AppType._missing_``'s spans before calling ``AppType.get``, so that a genuine
miss builds its member through ``EnumField._unregistered_member``. That peek was
written to stop ``get`` minting a member per ephemeral port. ``get`` does not
mint (#860), so the growth it guarded against cannot happen; but the member
``get`` builds on a miss is not the one a parse needs. These tests pin both
halves, so that the peek's documented reason fails here the day it stops being
true, and pin that a composite ``proto`` resolves a miss as ``get`` does.

"""
import pickle
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): exercises pickling and copying, whose protocols differ by
#: interpreter.
__tier__ = 'ALL'

#: An unassigned port on every transport, in none of ``_missing_``'s spans.
PORT = 50000


class PortEnumFieldPeekTests(unittest.TestCase):
    """The peek's reason, over every transport registry."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _protos(self) -> 'tuple[Any, ...]':
        from pcapkit.const.reg.apptype import TransportProtocol

        return (TransportProtocol.tcp, TransportProtocol.udp,
                TransportProtocol.sctp, TransportProtocol.dccp)

    def _field(self, proto: 'Any') -> 'Any':
        from pcapkit.const.reg.apptype import AppType
        from pcapkit.corekit.fields.numbers import PortEnumField

        return PortEnumField(length=2, namespace=AppType, proto=proto)

    @staticmethod
    def _tables(owner: 'Any') -> 'tuple[Any, ...]':
        by_value = dict(owner._value2member_map_)  # pylint: disable=protected-access
        rows = [(port, list(owner.__registry__.getlist(port))) for port in owner.__registry__]
        return (dict(owner.__members__), by_value, rows)

    def test_neither_the_field_nor_get_grows_the_registry(self) -> None:
        """The peek's original reason does not apply: ``get`` itself does not mint."""
        from pcapkit.const.reg.apptype import AppType

        for proto in self._protos():
            with self.subTest(proto=proto.name):
                owner = AppType.__registries__[proto]
                before = self._tables(owner)

                via_get = AppType.get(PORT, proto=proto)
                via_field = self._field(proto).unpack(PORT.to_bytes(2, 'big'), {})

                self.assertEqual(self._tables(owner), before)
                for member in (via_get, via_field):
                    self.assertIsInstance(member, owner)
                    self.assertEqual((member.svc, member.port, member.proto),
                                     ('unknown', PORT, proto))

    def test_a_miss_through_the_field_pickles_and_renders_as_unassigned(self) -> None:
        """What the peek buys: the member a parse returns survives pickling and
        dumps as ``<unassigned>``, like every other unassigned wire value."""
        from pcapkit.const.reg.apptype import AppType
        from pcapkit.dumpkit.common import render_enum

        for proto in self._protos():
            owner = AppType.__registries__[proto]
            member = self._field(proto).unpack(PORT.to_bytes(2, 'big'), {})
            with self.subTest(proto=proto.name):
                self.assertEqual(member.name, '<unassigned>')
                expected = f'{owner.__name__}::<unassigned> [unknown [{PORT} - {proto.name}]]'
                self.assertEqual(render_enum(member), expected)
            for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
                with self.subTest(proto=proto.name, protocol=protocol):
                    restored = pickle.loads(pickle.dumps(member, protocol))
                    self.assertIsInstance(restored, owner)
                    self.assertEqual((restored.svc, restored.port, restored.proto),
                                     ('unknown', PORT, proto))

    def test_gets_own_member_for_a_miss_is_not_that_member(self) -> None:
        """Why the field cannot just call ``get``: its miss member has no reducer
        and another name. If this starts failing, ``get``'s member has become
        what a parse needs, and the peek can go -- see #1774."""
        from pcapkit.const.reg.apptype import AppType

        for proto in self._protos():
            with self.subTest(proto=proto.name):
                member = AppType.get(PORT, proto=proto)

                self.assertEqual(member.name, 'unknown')
                with self.assertRaises(ValueError):
                    pickle.loads(pickle.dumps(member))

    def test_a_composite_proto_resolves_a_miss_as_get_does(self) -> None:
        """``tcp | udp`` is a bare :class:`int` (``3``, which is SCTP's value).

        ``get`` dispatches it to SCTP for a hit and a miss alike. The field's
        own miss branch takes the transport from the registry, as ``get`` does;
        reading ``.name`` off the bare :class:`int` instead raises
        :exc:`AttributeError` for a port ``get`` resolves.

        """
        from pcapkit.const.reg.apptype import AppType, TransportProtocol

        for label, proto in (('tcp|udp', TransportProtocol.tcp | TransportProtocol.udp),
                             ('int 1', 1)):
            with self.subTest(proto=label):
                self.assertIsInstance(proto, int)
                self.assertNotIsInstance(proto, TransportProtocol)
                field = self._field(proto)
                expected = AppType.get(PORT, proto=proto)
                owner = type(expected)
                before = self._tables(owner)

                miss = field.unpack(PORT.to_bytes(2, 'big'), {})
                hit = field.unpack(b'\x00\x50', {})  # 80

                self.assertIsInstance(miss, owner)
                self.assertEqual((miss.svc, miss.port, miss.proto),
                                 (expected.svc, expected.port, expected.proto))
                self.assertEqual(miss.name, '<unassigned>')
                self.assertIs(hit, AppType.get(80, proto=proto))
                self.assertEqual(self._tables(owner), before)

    def test_a_str_proto_resolves_a_miss_as_get_does(self) -> None:
        """``'tcp'`` names its registry, as ``get`` lets it, hit and miss alike."""
        from pcapkit.const.reg.apptype import AppType, TransportProtocol

        tcp = AppType.__registries__[TransportProtocol.tcp]
        field = self._field('tcp')
        before = self._tables(tcp)

        miss = field.unpack(PORT.to_bytes(2, 'big'), {})
        hit = field.unpack(b'\x00\x50', {})  # 80

        self.assertIsInstance(miss, tcp)
        self.assertEqual((miss.svc, miss.port, miss.proto),
                         ('unknown', PORT, TransportProtocol.tcp))
        self.assertEqual(miss.name, '<unassigned>')
        self.assertIs(hit, AppType.get(80, proto='tcp'))
        self.assertEqual(self._tables(tcp), before)

    def test_a_composite_naming_no_registry_is_refused_as_get_refuses_it(self) -> None:
        """``tcp | dccp`` is ``5``, which names no registry, hit or miss."""
        from pcapkit.const.reg.apptype import AppType, TransportProtocol

        proto = TransportProtocol.tcp | TransportProtocol.dccp
        field = self._field(proto)
        for port in (80, PORT):
            with self.subTest(port=port):
                with self.assertRaises(ValueError):
                    AppType.get(port, proto=proto)
                with self.assertRaises(ValueError):
                    field.unpack(port.to_bytes(2, 'big'), {})


if __name__ == '__main__':
    unittest.main()
