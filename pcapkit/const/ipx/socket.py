# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Socket Types"""

from aenum import IntEnum, extend_enum

__all__ = ['Socket']


class Socket(IntEnum):
    """[Socket] Socket Types"""

    _ignore_ = 'Socket _'
    Socket = vars()

    Socket['Routing_Information_Packet'] = 0x0001

    Socket['Echo_Protocol_Packet'] = 0x0002

    Socket['Error_Handling_Packet'] = 0x0003

    #: NCP – used by Novell NetWare servers
    Socket['NetWare_Core_Protocol'] = 0x0451

    #: SAP
    Socket['Service_Advertising_Protocol'] = 0x0452

    #: RIP
    Socket['Routing_Information_Protocol'] = 0x0453

    Socket['NetBIOS'] = 0x0455

    Socket['Diagnostic_Packet'] = 0x0456

    #: used for NCP as well
    Socket['Serialization_Packet'] = 0x0457

    Socket['Used_By_Novell_NetWare_Client'] = 0x4003

    Socket['IPX'] = 0x8060

    Socket['TCP_Over_IPXF'] = 0x9091

    Socket['UDP_Over_IPXF'] = 0x9092

    #: IPX Fragmentation Protocol
    Socket['IPXF'] = 0x9093

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Socket(key)
        if key not in Socket._member_map_:  # pylint: disable=no-member
            extend_enum(Socket, key, default)
        return Socket[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0x0000 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0001 <= value <= 0x0BB8:
            extend_enum(cls, 'Registered by Xerox [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x0020 <= value <= 0x003F:
            extend_enum(cls, 'Experimental [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x0BB9 <= value <= 0xFFFF:
            extend_enum(cls, 'Dynamically Assigned [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x4000 <= value <= 0x4FFF:
            extend_enum(cls, 'Dynamically Assigned Socket Numbers [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8000 <= value <= 0xFFFF:
            extend_enum(cls, 'Statically Assigned Socket Numbers [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        return super()._missing_(value)
