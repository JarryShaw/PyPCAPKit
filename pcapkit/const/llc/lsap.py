# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""LLC Address (LSAP) Values
===============================

.. module:: pcapkit.const.llc.lsap

This module contains the constant enumeration for **LLC Address (LSAP) Values**,
which is automatically generated from :class:`pcapkit.vendor.llc.lsap.LSAP`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['LSAP']


class LSAP(EnumRegistry, IntEnum):
    """[LSAP] LLC Address (LSAP) Values [IEEE Registration Authority, LLC Public Listing]"""

    #: Protocol class(es) owning the ``__proto__`` dispatch registry keyed by
    #: this enumeration, read by
    #: :func:`~pcapkit.foundation.registry.protocols.protocol.register_protocol_code`
    #: to resolve a bare member of it into its destination(s). The classes are
    #: named as lazy :class:`~pcapkit.corekit.module.ModuleDescriptor`
    #: references rather than imported, because :mod:`pcapkit.const` sits below
    #: :mod:`pcapkit.protocols` and importing one from here would be circular.
    __proto_dest__ = (
        ModuleDescriptor('pcapkit.protocols.link.llc.protocol', 'LLC'),
    )

    #: Null address [ISO/IEC 8802-2]
    Null = 0x00

    #: LLC Sublayer Management [IEEE 802.1B]
    LLC_Sublayer_Management = 0x02

    #: Internet Protocol [:rfc:`791`]
    Internet_Protocol = 0x06

    #: Secure Data Exchange Protocol of Interoperable LAN Security [IEEE 802.10B]
    Secure_Data_Exchange = 0x0A

    #: Network Management, Maintenance and Initialization of PROWAY C [IEC 955]
    PROWAY_Network_Management = 0x0E

    #: Bridge Spanning Tree Protocol [ISO/IEC 10038]
    Bridge_Spanning_Tree_Protocol = 0x42

    #: Manufacturing Message Service [ISO 9506]
    Manufacturing_Message_Service = 0x4E

    #: X.25 packet layer protocol as the network layer protocol [ISO/IEC 8208]
    X_25_Packet_Layer_Protocol = 0x7E

    #: BACnet [ANSI/ASHRAE 135-1995]
    BACnet = 0x82

    #: Active station list maintenance of PROWAY C [IEC 955]
    PROWAY_Active_Station_List_Maintenance = 0x8E

    #: Source Routing Route Determination Entity [ISO/IEC 8802-2]
    Route_Determination_Entity = 0xA6

    #: Subnetwork Access Protocol [IEEE 802]
    SNAP = 0xAA

    #: Service user layer entity of meter data exchange over HDLC [IEC 62056-46]
    Service_User_Layer_Entity = 0xE6

    #: Protocol identification in the network layer [ISO/IEC TR 9577]
    Network_Layer_Protocol_Identification = 0xFE

    #: Global DSAP address [ISO/IEC 8802-2]
    Global = 0xFF

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it passes the range check :meth:`_missing_` makes.

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value`
        with that check and the message it raises, so
        :meth:`~pcapkit.corekit.enum.EnumRegistry.register` refuses exactly the
        values :meth:`~pcapkit.corekit.enum.EnumLookup.get` refuses, in the
        same words (:issue:`1816`).

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` fails that check. A
                :exc:`ValueError`, so an ``except ValueError`` caller is
                unaffected.

        """
        if not (isinstance(value, int) and 0x00 <= value <= 0xFF):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'LSAP':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x00 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if value & 0b10:
            #: Reserved
            return cls._unregistered_member(value, 'Reserved')
        #: Unreserved use
        return cls._unregistered_member(value, 'Unreserved use')
