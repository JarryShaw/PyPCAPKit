# -*- coding: utf-8 -*-
"""The L2TP family base dispatches on both paths. C.f. #2574.

A versioned family's base never yields an instance of itself: parsing octets
through :class:`~pcapkit.protocols.link.l2tp.protocol.L2TP`, constructing it from fields,
and its ``from_data`` all give the member the version names. The ``version``
field names it on either path, and it is the only thing that does from fields:
fields without it are refused. Octets without it are read by the version
nibble, bits 12 to 15 of the first word (RFC 2661, section 3.1), and data by its
``version``. ``2`` is ``L2TPv2``; no other member exists, so ``1`` (L2F) and
``3`` (L2TPv3) raise. ``version`` is a field ``L2TPv2`` writes, so a subclass
outside the members is refused it when parsing only.

The checks are :mod:`tests.protocols._versioned_base`'s; this module holds the
family's tables. Every case builds its own octets in memory and reads no capture.

"""

import struct
import unittest

from tests.protocols._versioned_base import FromDataByVersion, OctetsCarryTheVersion


def l2tp_data(version: 'int' = 2) -> 'bytes':
    """A data message, tunnel ``0x1234``, session ``0x5678``, with the nibble ``version``."""
    return struct.pack('!HHH', version, 0x1234, 0x5678) + b'\xff\x03\x00\x21PPP'


#: A control message (RFC 2661, section 3.1): T, L and S set, Length 12, Ns and Nr zero.
CONTROL = struct.pack('!HHHHHH', 0xC802, 12, 1, 0, 0, 0)

#: Fields only L2TPv2 takes.
IDS = {'tunnel_id': 0x1234, 'session_id': 0x5678}


class L2TPBaseDispatchTests(OctetsCarryTheVersion, FromDataByVersion, unittest.TestCase):
    """``L2TP(...)`` and ``L2TP.from_data`` give the member, never the base."""

    BASE = 'pcapkit.protocols.link.l2tp.protocol:L2TP'
    MEMBERS = {2: 'pcapkit.protocols.link.l2tpv2.protocol:L2TPv2'}
    OCTETS = {'data message': (l2tp_data(), 2), 'control message': (CONTROL, 2)}
    BAD_VERSIONS = (1, 3, True, '2', 2.0)
    CUSTOM = (2, 'pcapkit.protocols.link.l2tp.schema:L2TP', 'pcapkit.protocols.link.l2tp.data:L2TP',
              {'tunnel_id': 1})
    VERSION_IS_A_FIELD = True
    NO_MEMBER = {version: l2tp_data(version) for version in (1, 3, 15)}
    SHORT = (b'\x00', 'no version in a packet shorter than 2 octets')
    CROSSED = {f'nibble {nibble}': (l2tp_data(nibble), 2, f'^L2TPv2: invalid version: {nibble}$')
               for nibble in (1, 3)}

    def cases_from_fields(self) -> 'dict[str, tuple[dict[str, object], int, object]]':
        return {'defaults': ({}, 2, None), 'ids': (IDS, 2, None)}

    def versionless_fields(self) -> 'dict[str, dict[str, object]]':
        """Even fields only L2TPv2 takes."""
        return {'no fields': {}, 'ids': IDS}

    def foreign_fields(self) -> 'dict[int, dict[str, object]]':
        return {2: {'ttl': 3}}


if __name__ == '__main__':
    unittest.main()
