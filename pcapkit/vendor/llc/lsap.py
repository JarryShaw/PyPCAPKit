# -*- coding: utf-8 -*-
"""LLC Address (LSAP) Values
===============================

.. module:: pcapkit.vendor.llc.lsap

This module contains the vendor crawler for **LLC Address (LSAP) Values**,
which is automatically generating :class:`pcapkit.const.llc.lsap.LSAP`.

The crawler reads :data:`DATA` rather than a URL, for the reason
:mod:`pcapkit.vendor.llc` gives. A value is the whole address octet, its
least significant bit included: the I/G bit of a DSAP, where ``1`` makes it
a group address, and the C/R bit of an SSAP, which
:class:`~pcapkit.protocols.link.llc.protocol.LLC` clears before the lookup,
since an SSAP is always an individual address. The values Wireshark's
``packet-llc.h`` and the Linux kernel's ``include/uapi/linux/llc.h`` name
beyond the listing, such as ``0xE0`` (NetWare) and ``0xF0`` (NetBIOS), are
in its unreserved ranges and resolve under that label.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['LSAP']

#: Individual and group LSAP address values assigned in the IEEE Registration
#: Authority's *Logical Link Control (LLC) Public Listing*.
#:
#: Maps an address value to the enumeration name it takes and the comment
#: rendered above it: the use the listing's footnote gives, then the document
#: it cites.
DATA = {
    0x00: ('Null', 'Null address [ISO/IEC 8802-2]'),
    0x02: ('LLC_Sublayer_Management', 'LLC Sublayer Management [IEEE 802.1B]'),
    0x06: ('Internet_Protocol', 'Internet Protocol [:rfc:`791`]'),
    0x0A: ('Secure_Data_Exchange', 'Secure Data Exchange Protocol of Interoperable LAN Security [IEEE 802.10B]'),
    0x0E: ('PROWAY_Network_Management', 'Network Management, Maintenance and Initialization of PROWAY C [IEC 955]'),
    0x42: ('Bridge_Spanning_Tree_Protocol', 'Bridge Spanning Tree Protocol [ISO/IEC 10038]'),
    0x4E: ('Manufacturing_Message_Service', 'Manufacturing Message Service [ISO 9506]'),
    0x7E: ('X_25_Packet_Layer_Protocol', 'X.25 packet layer protocol as the network layer protocol [ISO/IEC 8208]'),
    0x82: ('BACnet', 'BACnet [ANSI/ASHRAE 135-1995]'),
    0x8E: ('PROWAY_Active_Station_List_Maintenance', 'Active station list maintenance of PROWAY C [IEC 955]'),
    0xA6: ('Route_Determination_Entity', 'Source Routing Route Determination Entity [ISO/IEC 8802-2]'),
    0xAA: ('SNAP', 'Subnetwork Access Protocol [IEEE 802]'),
    0xE6: ('Service_User_Layer_Entity', 'Service user layer entity of meter data exchange over HDLC [IEC 62056-46]'),
    0xFE: ('Network_Layer_Protocol_Identification', 'Protocol identification in the network layer [ISO/IEC TR 9577]'),
    0xFF: ('Global', 'Global DSAP address [ISO/IEC 8802-2]'),
}  # type: dict[int, tuple[str, str]]


class LSAP(Vendor):
    """LLC Address (LSAP) Values [IEEE Registration Authority, LLC Public Listing]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x00 <= value <= 0xFF'

    #: Destination of a bare ``LSAP`` member; see
    #: :attr:`~pcapkit.vendor.default.Vendor.PROTO_DEST`.
    PROTO_DEST = (ModuleDescriptor('pcapkit.protocols.link.llc.protocol', 'LLC'),)

    def request(self) -> 'dict[int, tuple[str, str]]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.llc.lsap.DATA`).

        """
        return DATA

    def count(self, data: 'dict[int, tuple[str, str]]') -> 'Counter[str]':  # type: ignore[override]
        """Count field records.

        Args:
            data: Registry data.

        Returns:
            Field recordings.

        """
        return collections.Counter(self.safe_name(name) for name, _ in data.values())

    def process(self, data: 'dict[int, tuple[str, str]]') -> 'tuple[list[str], list[str]]':  # type: ignore[override]
        """Process registry data.

        The listing leaves every value whose second least significant bit is
        ``0`` to unreserved use, individual and group alike, and reserves every
        other value it assigns to no one.

        Args:
            data: Registry data.

        Returns:
            Enumeration fields and missing fields.

        """
        enum = []  # type: list[str]
        miss = [
            'if value & 0b10:',
            '    #: Reserved',
            "    return cls._unregistered_member(value, 'Reserved')",
            '#: Unreserved use',
            "return cls._unregistered_member(value, 'Unreserved use')",
        ]

        for code, (name, desc) in data.items():
            pval = f'0x{code:02X}'
            renm = self.rename(name, pval)

            enum.append(f'#: {self.wrap_comment(desc)}\n    {renm} = {pval}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(LSAP())  # type: ignore[arg-type]
