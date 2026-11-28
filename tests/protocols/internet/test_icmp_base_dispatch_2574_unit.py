# -*- coding: utf-8 -*-
"""The ICMP family base dispatches where the version is known. C.f. #2574.

A versioned family's base never yields an instance of itself. The ``version``
keyword names the member :class:`~pcapkit.protocols.internet.icmp.protocol.ICMP` gives,
from octets or from fields, and nothing else does: an ICMP message has no
version field -- the IP layer names it, by protocol number 1 (RFC 792) or 58
(RFC 4443, section 1) -- and no field picks a member, so both are refused
without it, ``pseudo`` included. ``from_data`` gives the member whose data model
it is handed, and refuses a ``dict``, whose keys need not tell the two apart: an
Echo message's do not.

The checks are :mod:`tests.protocols._versioned_base`'s; this module holds the
family's tables. Every case builds its own octets in memory and reads no capture.

"""

import struct
import unittest

from tests.protocols._versioned_base import FromDataByModel, OctetsCarryNoVersion

#: An Echo Request of each version, identifier 7, sequence 2, checksum zero:
#: type 8 in ICMPv4 (RFC 792) and 128 in ICMPv6 (RFC 4443, section 4.1).
ECHO = {
    4: struct.pack('>BBHHH', 8, 0, 0, 7, 2) + b'odd',
    6: struct.pack('>BBHHH', 128, 0, 0, 7, 2) + b'odd',
}


def pseudo() -> 'object':
    """An IPv6 pseudo-header, which only ICMPv6 takes."""
    from pcapkit.const.reg.transtype import TransType
    from pcapkit.protocols.misc.checksum.ip_pseudo.protocol import IP_Pseudo

    return IP_Pseudo.from_fields(src='2001:db8::1', dst='2001:db8::2', protocol=TransType.IPv6_ICMP, upper_length=0)


class ICMPBaseDispatchTests(OctetsCarryNoVersion, FromDataByModel, unittest.TestCase):
    """``ICMP(...)`` and ``ICMP.from_data`` give the member, never the base."""

    BASE = 'pcapkit.protocols.internet.icmp.protocol:ICMP'
    MEMBERS = {4: 'pcapkit.protocols.internet.icmpv4.protocol:ICMPv4',
               6: 'pcapkit.protocols.internet.icmpv6.protocol:ICMPv6'}
    OCTETS = {'ICMPv4 echo': (ECHO[4], 4), 'ICMPv6 echo': (ECHO[6], 6)}
    BAD_VERSIONS = (1, True, '6', 4.0, 6.0)
    CUSTOM = (4, 'pcapkit.protocols.internet.icmpv4.schema:ICMPv4', 'pcapkit.protocols.internet.icmpv4.data:ICMPv4',
              {'type': 8})
    NOT_A_DATA_MODEL = '^ICMP: invalid data: must be an ICMPv4 or ICMPv6 data model$'

    def cases_from_fields(self) -> 'dict[str, tuple[dict[str, object], int, object]]':
        return {
            'ICMPv4 defaults': ({}, 4, None),
            'ICMPv4 echo': ({'type': 8, 'body': ECHO[4][4:]}, 4, None),
            'ICMPv4 echo, checksum given': ({'type': 8, 'body': ECHO[4][4:], 'checksum': b'\x00\x00'}, 4, ECHO[4]),
            'ICMPv6 defaults': ({}, 6, None),
            'ICMPv6 echo': ({'type': 128, 'body': ECHO[6][4:], 'pseudo': pseudo()}, 6, None),
        }

    def versionless_fields(self) -> 'dict[str, dict[str, object]]':
        """Even ``pseudo``, the field only ICMPv6 takes."""
        return {'no fields': {}, 'shared fields': {'type': 8, 'body': ECHO[4][4:]},
                'pseudo': {'type': 128, 'pseudo': pseudo()}}

    def foreign_fields(self) -> 'dict[int, dict[str, object]]':
        return {4: {'pseudo': pseudo()}}

    def test_the_ip_layer_s_version_takes_the_private_channel(self) -> None:
        """The enclosing IP layer hands its own version on, which is no member check."""
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6

        self.assertEqual(ICMPv6._from_parent(ECHO[6], len(ECHO[6]), version=4).data, ECHO[6])  # pylint: disable=protected-access


if __name__ == '__main__':
    unittest.main()
