# -*- coding: utf-8 -*-
"""The IP family base dispatches on both paths. C.f. #2574.

A versioned family's base never yields an instance of itself: parsing octets
through :class:`~pcapkit.protocols.internet.ip.IP`, constructing it from fields,
and its ``from_data`` all give ``IPv4`` or ``IPv6``. The ``version`` keyword
names the member on either path, and it is the only thing that does: fields
without it are refused, whichever member takes them. Octets without it are read
by their Version field (RFC 791, section 3.1; RFC 8200, section 3), and data by
its ``version``.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import enum
import io
import struct
import unittest

from tests._support import reimport_once_per_class

#: A UDP datagram to the discard port, carrying ``ab``.
UDP = struct.pack('>HHHH', 40000, 9, 10, 0) + b'ab'


def ipv4(body: 'bytes', proto: 'int', version: 'int' = 4) -> 'bytes':
    """An IPv4 header of ``version``, checksum zero, carrying ``body`` as ``proto``."""
    return struct.pack('>BBHHHBBH4s4s', version << 4 | 5, 0, 20 + len(body), 1, 0x4000, 64, proto, 0,
                       b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02') + body


def ipv6(body: 'bytes', nxt: 'int') -> 'bytes':
    """An IPv6 header, ``::1`` to ``::2``, carrying ``body`` as ``nxt``."""
    return (struct.pack('>IHBB', 6 << 28, len(body), nxt, 64)
            + bytes(15) + b'\x01' + bytes(15) + b'\x02' + body)


#: Octets, with the member that parses them.
OCTETS = {
    'IPv4 UDP': (ipv4(UDP, 17), 'IPv4'),
    'IPv6 UDP': (ipv6(UDP, 17), 'IPv6'),
    'IPv6 no next header': (ipv6(b'abcd', 59), 'IPv6'),
}

#: Fields, with the ``version`` that builds them.
FIELDS = {
    'IPv4 defaults': ({}, 4),
    'IPv4 shared fields': ({'src': '10.0.0.1', 'dst': '10.0.0.2', 'payload': UDP}, 4),
    'IPv4 own fields': ({'ttl': 3, 'protocol': 17, 'payload': UDP}, 4),
    'IPv6 defaults': ({}, 6),
    'IPv6 shared fields': ({'src': '::1', 'dst': '::2', 'payload': UDP}, 6),
    'IPv6 own fields': ({'hop_limit': 3, 'next': 17, 'src': '::1', 'dst': '::2', 'payload': UDP}, 6),
}

#: The refusal of fields given no ``version``.
NO_VERSION = r'^IP: no version to build with; pass version=4 or version=6$'


class IPBaseDispatchTests(unittest.TestCase):
    """``IP(...)`` and ``IP.from_data`` give the member, never the base."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def member(name: 'str | int') -> 'type':
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.internet.ipv6 import IPv6

        return {'IPv4': IPv4, 'IPv6': IPv6, 4: IPv4, 6: IPv6}[name]

    def test_octets_without_version_give_the_member_their_version_names(self) -> None:
        from pcapkit.protocols.internet.ip import IP

        for label, (octets, name) in OCTETS.items():
            for source in ('bytes', 'stream'):
                with self.subTest(octets=label, source=source):
                    layer = IP(octets) if source == 'bytes' else IP(io.BytesIO(octets), len(octets))
                    direct = self.member(name)(octets)
                    self.assertIs(type(layer), self.member(name))
                    self.assertIsInstance(layer, IP)
                    self.assertEqual(layer.info.version, octets[0] >> 4)
                    self.assertEqual(layer.data, octets)
                    self.assertEqual(str(layer.protochain), str(direct.protochain))

    def test_octets_naming_no_version_raise(self) -> None:
        from pcapkit.protocols.internet.ip import IP
        from pcapkit.utilities.exceptions import ProtocolError

        for version in (0, 5, 15):
            with self.subTest(version=version):
                with self.assertRaisesRegex(ProtocolError, f'^IP: invalid version: {version}$'):
                    IP(ipv4(UDP, 17, version))
        with self.assertRaisesRegex(ProtocolError, '^IP: no version in an empty packet$'):
            IP(b'')

    def test_version_picks_the_member_from_fields(self) -> None:
        """Each build is byte-exact against the member's own and parses back unchanged."""
        from pcapkit.protocols.internet.ip import IP

        for label, (fields, version) in FIELDS.items():
            with self.subTest(fields=label):
                layer = IP(version=version, **fields)
                self.assertIs(type(layer), self.member(version))
                self.assertEqual(layer.data, self.member(version)(**fields).data)
                parsed = IP(layer.data)
                self.assertIs(type(parsed), type(layer))
                self.assertEqual(parsed.data, layer.data)

    def test_version_picks_the_member_from_octets(self) -> None:
        """A ``version`` that matches the octets parses them as the member would."""
        from pcapkit.protocols.internet.ip import IP

        for label, (octets, name) in OCTETS.items():
            for source in ('bytes', 'stream'):
                with self.subTest(octets=label, source=source):
                    version = octets[0] >> 4
                    layer = (IP(octets, version=version) if source == 'bytes'
                             else IP(io.BytesIO(octets), len(octets), version=version))
                    self.assertIs(type(layer), self.member(name))
                    self.assertEqual(layer.data, octets)

    def test_version_over_octets_of_the_other_member_is_its_parser_s_error(self) -> None:
        """No cross-check: the member ``version`` names parses, and refuses the Version field."""
        from pcapkit.protocols.internet.ip import IP
        from pcapkit.utilities.exceptions import ProtocolError

        cases = {
            'IPv4 octets, version=6': (OCTETS['IPv4 UDP'][0], 6, r'^\[IPv6\] invalid version: 4$'),
            'IPv6 octets, version=4': (OCTETS['IPv6 UDP'][0], 4, r'^\[IPv4\] invalid version: 6$'),
        }
        for label, (octets, version, message) in cases.items():
            with self.subTest(case=label):
                with self.assertRaisesRegex(ProtocolError, message):
                    IP(octets, version=version)

    def test_a_member_checks_the_version_field_before_its_header(self) -> None:
        """IPv6's first octet reads to IPv4 as an IHL of 0 to 4; the Version field is checked first."""
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.utilities.exceptions import ProtocolError

        six = OCTETS['IPv6 UDP'][0]
        for first in range(0x60, 0x65):
            with self.subTest(first=hex(first)):
                with self.assertRaisesRegex(ProtocolError, r'^\[IPv4\] invalid version: 6$'):
                    IPv4(bytes([first]) + six[1:])
        with self.assertRaisesRegex(ProtocolError, r'^\[IPv6\] invalid version: 4$'):
            IPv6(OCTETS['IPv4 UDP'][0])

    def test_fields_without_version_raise(self) -> None:
        """Even a field only one member takes picks nothing."""
        from pcapkit.protocols.internet.ip import IP
        from pcapkit.utilities.exceptions import ProtocolError

        cases = {
            'no fields': {},
            'shared fields': {'src': '10.0.0.1', 'dst': '10.0.0.2'},
            'IPv4 only': {'ttl': 3},
            'IPv6 only': {'hop_limit': 3},
            'flow label': {'flow_label': 1, 'src': '::1', 'dst': '::2'},
            'both': {'ttl': 3, 'hop_limit': 3},
        }
        for label, fields in cases.items():
            with self.subTest(fields=label):
                with self.assertRaisesRegex(ProtocolError, NO_VERSION):
                    IP(**fields)

    def test_version_is_the_only_check(self) -> None:
        """A bad ``version`` raises; a field the member lacks fails the member's check."""
        from pcapkit.protocols.internet.ip import IP
        from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

        for version in (5, True, '4', 4.0, 6.0):
            with self.subTest(version=version):
                with self.assertRaisesRegex(ProtocolError, f'^IP: invalid version: {version!r}$'):
                    IP(version=version)

        class Version(enum.IntEnum):
            """An :class:`~enum.IntEnum` member is an :obj:`int`, and accepted."""

            IPV6 = 6

        self.assertIs(type(IP(version=Version.IPV6)), self.member(6))
        with self.assertRaisesRegex(UnsupportedCall, "^IPv4: unexpected keyword\\(s\\): 'hop_limit'"):
            IP(version=4, hop_limit=3)
        with self.assertRaisesRegex(UnsupportedCall, "^IPv6: unexpected keyword\\(s\\): 'ttl'"):
            IP(version=6, ttl=3)

    def test_a_member_takes_version_only_as_its_own(self) -> None:
        """Building, ``version`` must name the member; parsing, it is handed on unread."""
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.utilities.exceptions import ProtocolError

        self.assertEqual(IPv4(version=4).data, IPv4().data)
        self.assertEqual(IPv6(version=6).data, IPv6().data)
        with self.assertRaisesRegex(ProtocolError, '^IPv4: version=6 names another member$'):
            IPv4(version=6)
        with self.assertRaisesRegex(ProtocolError, '^IPv6: version=4 names another member$'):
            IPv6(version=4)
        # NOTE: The enclosing IP layer hands its own version to the one it
        # carries under this name, so IPv6 in IPv4 is parsed with ``version=4``.
        six_in_four = ipv4(OCTETS['IPv6 UDP'][0], 41)
        self.assertEqual(str(IPv4(six_in_four).protochain), 'IPv4:IPv6:UDP:Raw')
        self.assertIs(type(IPv6(OCTETS['IPv6 UDP'][0], version=4)), IPv6)

    def test_a_subclass_outside_the_members_has_no_version_of_its_own(self) -> None:
        """So it takes no ``version``, as a member takes no other's."""
        from pcapkit.protocols.internet.ip import IP
        from pcapkit.utilities.exceptions import ProtocolError

        class Outside(IP):  # type: ignore[type-arg]
            """A concrete subclass of the base that is no member."""

            name = length = None  # type: ignore[assignment]
            @classmethod
            def __index__(cls) -> 'int':  # type: ignore[override]
                raise NotImplementedError

            def read(self, length: 'object' = None, **kwargs: 'object') -> 'object':
                raise NotImplementedError

            def make(self, **kwargs: 'object') -> 'object':
                raise NotImplementedError

        with self.assertRaisesRegex(ProtocolError, '^Outside: no version of its own to match version=4$'):
            Outside(version=4)

    def test_from_data_on_the_base_gives_the_member(self) -> None:
        from pcapkit.protocols.internet.ip import IP
        from pcapkit.utilities.exceptions import ProtocolError

        for label, (octets, name) in OCTETS.items():
            parsed = self.member(name)(octets)
            for form in ('info', 'dict'):
                with self.subTest(octets=label, form=form):
                    data = parsed.info if form == 'info' else parsed.info.to_dict()
                    rebuilt = IP.from_data(data)
                    self.assertIs(type(rebuilt), self.member(name))
                    self.assertEqual(rebuilt.data, octets)
        with self.assertRaisesRegex(ProtocolError, '^IP: invalid version: None$'):
            IP.from_data({})
        with self.assertRaisesRegex(ProtocolError, '^IPv4: version=6 names another member$'):
            IP.from_data(self.member('IPv4')(OCTETS['IPv4 UDP'][0]).info, version=6)

    def test_only_the_base_dispatches(self) -> None:
        """A subclass of the base is constructed as itself, abstract or not."""
        from pcapkit.protocols.data.internet.ipv4 import IPv4 as Data_IPv4
        from pcapkit.protocols.internet.ip import IP
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.schema.internet.ipv4 import IPv4 as Schema_IPv4

        class Abstract(IP):  # type: ignore[type-arg] # pylint: disable=abstract-method
            """A direct subclass of the base, still abstract."""

        class Custom(IPv4, schema=Schema_IPv4, data=Data_IPv4):
            """A concrete subclass of the base, through a member."""

        octets = OCTETS['IPv4 UDP'][0]
        self.assertIs(type(IP(octets)), IPv4)
        self.assertIs(type(Custom(octets)), Custom)
        self.assertIs(type(Custom(ttl=3, version=4)), Custom)
        self.assertIs(type(Custom.from_data(Custom(octets).info)), Custom)
        with self.assertRaisesRegex(TypeError, 'abstract'):
            Abstract(octets)


if __name__ == '__main__':
    unittest.main()
