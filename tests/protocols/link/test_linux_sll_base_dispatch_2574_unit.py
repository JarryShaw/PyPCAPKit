# -*- coding: utf-8 -*-
"""The LinuxSLL family base dispatches where the version is known. C.f. #2574.

A versioned family's base never yields an instance of itself. The ``version``
keyword names the member :class:`~pcapkit.protocols.link.linux_sll.protocol.LinuxSLL`
gives, from octets or from fields, and nothing else does: neither header has a
version field -- the link type names it, ``LINUX_SLL`` (113) or ``LINUX_SLL2``
(276), per tcpdump.org's pages for the two -- and no field picks a member, so
both are refused without it, ``interface_index`` included. ``from_data`` gives
the member whose data model it is handed, and refuses a ``dict``.

The checks are :mod:`tests.protocols._versioned_base`'s; this module holds the
family's tables. Every case builds its own octets in memory and reads no capture.

"""

import struct
import unittest

from tests.protocols._versioned_base import FromDataByModel, OctetsCarryNoVersion

#: An IPv4 header (DF clear, protocol UDP) and an 8-octet UDP header.
IPV4 = (bytes.fromhex('4500001c00010000401100000a0000010a000002')
        + bytes.fromhex('3039003500080000'))

#: A link-layer address, padded to the 8 octets both headers keep.
ADDR = bytes.fromhex('001122334455') + b'\x00\x00'

#: Each version's header carrying ``IPV4`` from an Ethernet interface: v1 is
#: packet type, ARPHRD type, address length, address and protocol type; v2 is
#: protocol type, reserved, interface index, ARPHRD type, packet type, address
#: length and address.
HEADERS = {
    1: struct.pack('>HHH', 0, 1, 6) + ADDR + struct.pack('>H', 0x0800) + IPV4,
    2: struct.pack('>HHIHBB', 0x0800, 0, 3, 1, 0, 6) + ADDR + IPV4,
}

#: Fields both members take, describing ``HEADERS``.
SHARED = {'packet_type': 0, 'arphrd_type': 1, 'link_addr': ADDR[:6],
          'protocol_type': 0x0800, 'payload': IPV4}


class LinuxSLLBaseDispatchTests(OctetsCarryNoVersion, FromDataByModel, unittest.TestCase):
    """``LinuxSLL(...)`` and ``LinuxSLL.from_data`` give the member, never the base."""

    BASE = 'pcapkit.protocols.link.linux_sll.protocol:LinuxSLL'
    MEMBERS = {1: 'pcapkit.protocols.link.linux_sll1.protocol:LinuxSLL1',
               2: 'pcapkit.protocols.link.linux_sll2.protocol:LinuxSLL2'}
    OCTETS = {'LinuxSLL1': (HEADERS[1], 1), 'LinuxSLL2': (HEADERS[2], 2)}
    BAD_VERSIONS = (0, 3, True, '2', 1.0, 2.0)
    CUSTOM = (2, 'pcapkit.protocols.link.linux_sll2.schema:LinuxSLL2',
              'pcapkit.protocols.link.linux_sll2.data:LinuxSLL2', {'packet_type': 0})
    NOT_A_DATA_MODEL = '^LinuxSLL: invalid data: must be a LinuxSLL1 or LinuxSLL2 data model$'

    def cases_from_fields(self) -> 'dict[str, tuple[dict[str, object], int, object]]':
        return {
            'LinuxSLL1 defaults': ({}, 1, None),
            'LinuxSLL1 shared fields': (SHARED, 1, HEADERS[1]),
            'LinuxSLL2 defaults': ({}, 2, None),
            'LinuxSLL2 interface index': ({**SHARED, 'interface_index': 3}, 2, HEADERS[2]),
            'LinuxSLL2 own fields': ({**SHARED, 'interface_index': 3, 'reserved': 0}, 2, HEADERS[2]),
        }

    def versionless_fields(self) -> 'dict[str, dict[str, object]]':
        """Even ``reserved`` or ``interface_index``, which only LinuxSLL2 takes."""
        return {'no fields': {}, 'shared fields': SHARED, 'interface index': {**SHARED, 'interface_index': 3},
                'reserved': {'reserved': 0}}

    def foreign_fields(self) -> 'dict[int, dict[str, object]]':
        return {1: {'interface_index': 3}}

    def test_the_payload_dispatches_as_ethernet_s_does(self) -> None:
        from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL

        self.assertEqual(str(LinuxSLL(HEADERS[2], version=2).protochain), 'LINUX_SLL2:IPv4:UDP')


if __name__ == '__main__':
    unittest.main()
