# -*- coding: utf-8 -*-
"""The LinuxSLL family base dispatches where the version is known. C.f. #2574.

A versioned family's base never yields an instance of itself. The ``version``
keyword names the member :class:`~pcapkit.protocols.link.linux_sll.protocol.LinuxSLL`
gives, from octets or from fields, and nothing else does: neither header has a
version field -- the link type names it, ``LINUX_SLL`` (113) or ``LINUX_SLL2``
(276), per tcpdump.org's pages for the two -- and no field picks a member, so
both are refused without it, ``interface_index`` included. ``from_data`` gives
the member whose data model it is handed, and refuses a ``dict``.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import struct
import unittest

from tests._support import reimport_once_per_class

#: An IPv4 header (DF clear, protocol UDP) and an 8-octet UDP header.
IPV4 = (bytes.fromhex('4500001c00010000401100000a0000010a000002')
        + bytes.fromhex('3039003500080000'))

#: A link-layer address, padded to the 8 octets both headers keep.
ADDR = bytes.fromhex('001122334455') + b'\x00\x00'

#: Each version's header carrying ``IPV4`` from an Ethernet interface: v1 is
#: packet type, ARPHRD type, address length, address and protocol type; v2 is
#: protocol type, reserved, interface index, ARPHRD type, packet type, address
#: length and address.
OCTETS = {
    1: struct.pack('>HHH', 0, 1, 6) + ADDR + struct.pack('>H', 0x0800) + IPV4,
    2: struct.pack('>HHIHBB', 0x0800, 0, 3, 1, 0, 6) + ADDR + IPV4,
}

#: Fields both members take, describing ``OCTETS``.
SHARED = {'packet_type': 0, 'arphrd_type': 1, 'link_addr': ADDR[:6],
          'protocol_type': 0x0800, 'payload': IPV4}

#: The refusals given no ``version``.
NO_VERSION_OCTETS = ('^LinuxSLL: no version field; pass version=1 or version=2, '
                     'or parse with LinuxSLL1 or LinuxSLL2$')
NO_VERSION_FIELDS = '^LinuxSLL: no version to build with; pass version=1 or version=2$'


class LinuxSLLBaseDispatchTests(unittest.TestCase):
    """``LinuxSLL(...)`` and ``LinuxSLL.from_data`` give the member, never the base."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def member(version: 'int') -> 'type':
        from pcapkit.protocols.link.linux_sll1.protocol import LinuxSLL1
        from pcapkit.protocols.link.linux_sll2.protocol import LinuxSLL2

        return {1: LinuxSLL1, 2: LinuxSLL2}[version]

    def test_octets_without_version_raise(self) -> None:
        from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL
        from pcapkit.utilities.exceptions import ProtocolError

        for version, octets in OCTETS.items():
            for source in ('bytes', 'stream'):
                with self.subTest(octets=version, source=source):
                    with self.assertRaisesRegex(ProtocolError, NO_VERSION_OCTETS):
                        if source == 'bytes':
                            LinuxSLL(octets)
                        else:
                            LinuxSLL(io.BytesIO(octets), len(octets))

    def test_version_picks_the_member_from_octets(self) -> None:
        """Even octets of the other version: the format carries none to object."""
        from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL

        for version in (1, 2):
            for octets_of, octets in OCTETS.items():
                for source in ('bytes', 'stream'):
                    with self.subTest(version=version, octets=octets_of, source=source):
                        layer = (LinuxSLL(octets, version=version) if source == 'bytes'
                                 else LinuxSLL(io.BytesIO(octets), len(octets), version=version))
                        self.assertIs(type(layer), self.member(version))
                        self.assertIsInstance(layer, LinuxSLL)
                        self.assertEqual(str(layer.protochain), str(self.member(version)(octets).protochain))
        self.assertEqual(str(LinuxSLL(OCTETS[2], version=2).protochain), 'LINUX_SLL2:IPv4:UDP')

    def test_version_picks_the_member_from_fields(self) -> None:
        """Each build is byte-exact against the member's own and parses back unchanged."""
        from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL

        cases = {
            'LinuxSLL1 defaults': ({}, 1),
            'LinuxSLL1 shared fields': (SHARED, 1),
            'LinuxSLL2 defaults': ({}, 2),
            'LinuxSLL2 own fields': ({**SHARED, 'interface_index': 3, 'reserved': 0}, 2),
        }
        for label, (fields, version) in cases.items():
            with self.subTest(fields=label):
                layer = LinuxSLL(version=version, **fields)
                self.assertIs(type(layer), self.member(version))
                self.assertEqual(layer.data, self.member(version)(**fields).data)
                parsed = LinuxSLL(layer.data, version=version)
                self.assertEqual(parsed.data, layer.data)
                self.assertEqual(LinuxSLL.from_data(parsed.info).data, layer.data)
        self.assertEqual(LinuxSLL(version=1, **SHARED).data, OCTETS[1])
        self.assertEqual(LinuxSLL(version=2, **SHARED, interface_index=3).data, OCTETS[2])

    def test_fields_without_version_raise(self) -> None:
        """Even ``reserved`` or ``interface_index``, which only LinuxSLL2 takes, pick nothing."""
        from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL
        from pcapkit.utilities.exceptions import ProtocolError

        for label, fields in (('no fields', {}), ('shared fields', SHARED),
                              ('interface index', {**SHARED, 'interface_index': 3}),
                              ('reserved', {'reserved': 0})):
            with self.subTest(fields=label):
                with self.assertRaisesRegex(ProtocolError, NO_VERSION_FIELDS):
                    LinuxSLL(**fields)

    def test_version_is_the_only_check(self) -> None:
        """A bad ``version`` raises; a field the member lacks fails the member's check."""
        from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL
        from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

        for version in (0, 3, True, '2', 1.0, 2.0):
            with self.subTest(version=version):
                with self.assertRaisesRegex(ProtocolError, f'^LinuxSLL: invalid version: {version!r}$'):
                    LinuxSLL(version=version)
        with self.assertRaisesRegex(UnsupportedCall, "^LinuxSLL1: unexpected keyword\\(s\\): 'interface_index'"):
            LinuxSLL(version=1, interface_index=3)

    def test_a_member_takes_version_only_as_its_own(self) -> None:
        """Building, ``version`` must name the member; parsing, it is handed on unread."""
        from pcapkit.protocols.link.linux_sll1.protocol import LinuxSLL1
        from pcapkit.protocols.link.linux_sll2.protocol import LinuxSLL2
        from pcapkit.utilities.exceptions import ProtocolError

        self.assertEqual(LinuxSLL1(version=1).data, LinuxSLL1().data)
        self.assertEqual(LinuxSLL2(version=2).data, LinuxSLL2().data)
        with self.assertRaisesRegex(ProtocolError, '^LinuxSLL1: version=2 names another member$'):
            LinuxSLL1(version=2)
        with self.assertRaisesRegex(ProtocolError, '^LinuxSLL2: version=1 names another member$'):
            LinuxSLL2(version=1)
        self.assertEqual(LinuxSLL2(OCTETS[2], version=1).data, OCTETS[2])

    def test_a_subclass_outside_the_members_has_no_version_of_its_own(self) -> None:
        """So it takes no ``version``, as a member takes no other's."""
        from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL
        from pcapkit.utilities.exceptions import ProtocolError

        class Outside(LinuxSLL):  # type: ignore[type-arg]
            """A concrete subclass of the base that is no member."""

            name = length = None  # type: ignore[assignment]

            def read(self, length: 'object' = None, **kwargs: 'object') -> 'object':
                raise NotImplementedError

            def make(self, **kwargs: 'object') -> 'object':
                raise NotImplementedError

        with self.assertRaisesRegex(ProtocolError, '^Outside: no version of its own to match version=2$'):
            Outside(version=2)

    def test_from_data_on_the_base_gives_the_member(self) -> None:
        """By the data model's class; a ``dict`` carries none, and is refused."""
        from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL
        from pcapkit.utilities.exceptions import ProtocolError

        for version, octets in OCTETS.items():
            with self.subTest(octets=version):
                parsed = self.member(version)(octets)
                rebuilt = LinuxSLL.from_data(parsed.info)
                self.assertIs(type(rebuilt), self.member(version))
                self.assertEqual(rebuilt.data, octets)
                self.assertEqual(self.member(version).from_data(parsed.info.to_dict()).data, octets)
                with self.assertRaisesRegex(
                        ProtocolError, '^LinuxSLL: invalid data: must be a LinuxSLL1 or LinuxSLL2 data model$'):
                    LinuxSLL.from_data(parsed.info.to_dict())

    def test_only_the_base_dispatches(self) -> None:
        """A subclass of the base is constructed as itself, abstract or not."""
        from pcapkit.protocols.link.linux_sll2.data import LinuxSLL2 as Data_LinuxSLL2
        from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL
        from pcapkit.protocols.link.linux_sll2.protocol import LinuxSLL2
        from pcapkit.protocols.link.linux_sll2.schema import LinuxSLL2 as Schema_LinuxSLL2

        class Abstract(LinuxSLL):  # type: ignore[type-arg] # pylint: disable=abstract-method
            """A direct subclass of the base, still abstract."""

        class Custom(LinuxSLL2, schema=Schema_LinuxSLL2, data=Data_LinuxSLL2):
            """A concrete subclass of the base, through a member."""

        octets = OCTETS[2]
        self.assertIs(type(LinuxSLL(interface_index=3, version=2)), LinuxSLL2)
        self.assertIs(type(Custom(octets)), Custom)
        self.assertIs(type(Custom(packet_type=0, version=2)), Custom)
        self.assertIs(type(Custom.from_data(Custom(octets).info)), Custom)
        with self.assertRaisesRegex(TypeError, 'abstract'):
            Abstract(octets)


if __name__ == '__main__':
    unittest.main()
