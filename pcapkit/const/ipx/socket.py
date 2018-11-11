# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class Socket(IntEnum):
    """Enumeration class for Socket."""
    _ignore_ = 'Socket _'
    Socket = vars()

    # Socket Types
    Socket['Routing Information Packet'] = 0x0001
    Socket['Echo Protocol Packet'] = 0x0002
    Socket['Error Handling Packet'] = 0x0003
    Socket['NetWare Core Protocol'] = 0x0451                                    # NCP - used by Novell NetWare servers
    Socket['Service Advertising Protocol'] = 0x0452                             # SAP
    Socket['Routing Information Protocol'] = 0x0453                             # RIP
    Socket['NetBIOS'] = 0x0455
    Socket['Diagnostic Packet'] = 0x0456
    Socket['Serialization Packet'] = 0x0457                                     # used for NCP as well
    Socket['Used by Novell NetWare Client'] = 0x4003
    Socket['IPX'] = 0x8060
    Socket['TCP over IPXF'] = 0x9091
    Socket['UDP over IPXF'] = 0x9092
    Socket['IPXF'] = 0x9093                                                     # IPX Fragmentation Protocol

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Socket(key)
        if key not in Socket._member_map_:
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
        super()._missing_(value)
