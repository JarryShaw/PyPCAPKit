# -*- coding: utf-8 -*-
"""The IP family base dispatches on both paths. C.f. #2574.

A versioned family's base never yields an instance of itself: parsing octets
through :class:`~pcapkit.protocols.internet.ip.protocol.IP`, constructing it from fields,
and its ``from_data`` all give ``IPv4`` or ``IPv6``. The ``version`` keyword
names the member on either path, and it is the only thing that does: fields
without it are refused, whichever member takes them. Octets without it are read
by their Version field (RFC 791, section 3.1; RFC 8200, section 3), and data by
its ``version``.

The checks are :mod:`tests.protocols._versioned_base`'s; this module holds the
family's tables, and the checks only IP's members need. Every case builds its own
octets in memory and reads no capture.

"""

import struct
import unittest

from tests.protocols._versioned_base import FromDataByVersion, OctetsCarryTheVersion

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


class IPBaseDispatchTests(OctetsCarryTheVersion, FromDataByVersion, unittest.TestCase):
    """``IP(...)`` and ``IP.from_data`` give the member, never the base."""

    BASE = 'pcapkit.protocols.internet.ip.protocol:IP'
    MEMBERS = {4: 'pcapkit.protocols.internet.ipv4.protocol:IPv4',
               6: 'pcapkit.protocols.internet.ipv6.protocol:IPv6'}
    OCTETS = {
        'IPv4 UDP': (ipv4(UDP, 17), 4),
        'IPv6 UDP': (ipv6(UDP, 17), 6),
        'IPv6 no next header': (ipv6(b'abcd', 59), 6),
    }
    BAD_VERSIONS = (5, True, '4', 4.0, 6.0)
    CUSTOM = (4, 'pcapkit.protocols.internet.ipv4.schema:IPv4', 'pcapkit.protocols.internet.ipv4.data:IPv4',
              {'ttl': 3})
    NO_MEMBER = {version: ipv4(UDP, 17, version) for version in (0, 5, 15)}
    SHORT = (b'', 'no version in an empty packet')
    CROSSED = {
        'IPv4 octets, version=6': (OCTETS['IPv4 UDP'][0], 6, r'^\[IPv6\] invalid version: 4$'),
        'IPv6 octets, version=4': (OCTETS['IPv6 UDP'][0], 4, r'^\[IPv4\] invalid version: 6$'),
    }

    def cases_from_fields(self) -> 'dict[str, tuple[dict[str, object], int, object]]':
        return {
            'IPv4 defaults': ({}, 4, None),
            'IPv4 shared fields': ({'src': '10.0.0.1', 'dst': '10.0.0.2', 'payload': UDP}, 4, None),
            'IPv4 own fields': ({'ttl': 3, 'protocol': 17, 'payload': UDP}, 4, None),
            'IPv6 defaults': ({}, 6, None),
            'IPv6 shared fields': ({'src': '::1', 'dst': '::2', 'payload': UDP}, 6, None),
            'IPv6 own fields': ({'hop_limit': 3, 'next': 17, 'src': '::1', 'dst': '::2', 'payload': UDP}, 6, None),
        }

    def versionless_fields(self) -> 'dict[str, dict[str, object]]':
        """Even a field only one member takes."""
        return {
            'no fields': {},
            'shared fields': {'src': '10.0.0.1', 'dst': '10.0.0.2'},
            'IPv4 only': {'ttl': 3},
            'IPv6 only': {'hop_limit': 3},
            'flow label': {'flow_label': 1, 'src': '::1', 'dst': '::2'},
            'both': {'ttl': 3, 'hop_limit': 3},
        }

    def foreign_fields(self) -> 'dict[int, dict[str, object]]':
        return {4: {'hop_limit': 3}, 6: {'ttl': 3}}

    def test_a_member_checks_the_version_field_before_its_header(self) -> None:
        """IPv6's first octet reads to IPv4 as an IHL of 0 to 4; the Version field is checked first."""
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.utilities.exceptions import ProtocolError

        six = self.OCTETS['IPv6 UDP'][0]
        for first in range(0x60, 0x65):
            with self.subTest(first=hex(first)):
                with self.assertRaisesRegex(ProtocolError, r'^\[IPv4\] invalid version: 6$'):
                    IPv4(bytes([first]) + six[1:])
        with self.assertRaisesRegex(ProtocolError, r'^\[IPv6\] invalid version: 4$'):
            IPv6(self.OCTETS['IPv4 UDP'][0])

    def test_the_outer_layer_s_version_takes_the_private_channel(self) -> None:
        """IPv4 hands its own version to the IPv6 it carries, so IPv6 in IPv4 is no member check."""
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.internet.ipv6.protocol import IPv6

        six = self.OCTETS['IPv6 UDP'][0]
        self.assertEqual(str(IPv4(ipv4(six, 41)).protochain), 'IPv4:IPv6:UDP:Raw')
        self.assertIs(type(IPv6._from_parent(six, len(six), version=4)), IPv6)  # pylint: disable=protected-access


if __name__ == '__main__':
    unittest.main()
