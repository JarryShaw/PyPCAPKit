# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Socket Types
==================

.. module:: pcapkit.const.ipx.socket

This module contains the constant enumeration for **Socket Types**,
which is automatically generated from :class:`pcapkit.vendor.ipx.socket.Socket`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Socket']


class Socket(IntEnum):
    """[Socket] Socket Types"""

    #: Routing Information Packet
    Routing_Information_Packet = 0x0001

    #: Echo Protocol Packet
    Echo_Protocol_Packet = 0x0002

    #: Error Handling Packet
    Error_Handling_Packet = 0x0003

    #: NetWare Core Protocol, NCP – used by Novell NetWare servers
    NetWare_Core_Protocol = 0x0451

    #: Service Advertising Protocol, SAP
    Service_Advertising_Protocol = 0x0452

    #: Routing Information Protocol, RIP
    Routing_Information_Protocol = 0x0453

    #: NetBIOS
    NetBIOS = 0x0455

    #: Diagnostic Packet
    Diagnostic_Packet = 0x0456

    #: Serialization Packet, used for NCP as well
    Serialization_Packet = 0x0457

    #: Used by Novell NetWare Client
    Used_by_Novell_NetWare_Client = 0x4003

    #: LLC [ 4 ]
    LLC_4 = 0x8060

    #: TCP over IPXF
    TCP_over_IPXF = 0x9091

    #: UDP over IPXF
    UDP_over_IPXF = 0x9092

    #: IPXF, IPX Fragmentation Protocol
    IPXF = 0x9093

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Socket':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return Socket(key)
        if key not in Socket._member_map_:  # pylint: disable=no-member
            return extend_enum(Socket, key, default)
        return Socket[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'Socket':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x0000 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0001 <= value <= 0x0BB8:
            #: Registered by Xerox
            return extend_enum(cls, 'Registered by Xerox_0x%s' % hex(value)[2:].upper().zfill(4), value)
        if 0x0020 <= value <= 0x003F:
            #: Experimental
            return extend_enum(cls, 'Experimental_0x%s' % hex(value)[2:].upper().zfill(4), value)
        if 0x0BB9 <= value <= 0xFFFF:
            #: Dynamically Assigned
            return extend_enum(cls, 'Dynamically Assigned_0x%s' % hex(value)[2:].upper().zfill(4), value)
        if 0x4000 <= value <= 0x4FFF:
            #: Dynamically Assigned Socket Numbers
            return extend_enum(cls, 'Dynamically Assigned Socket Numbers_0x%s' % hex(value)[2:].upper().zfill(4), value)
        if 0x8000 <= value <= 0xFFFF:
            #: Statically Assigned Socket Numbers
            return extend_enum(cls, 'Statically Assigned Socket Numbers_0x%s' % hex(value)[2:].upper().zfill(4), value)
        return super()._missing_(value)
