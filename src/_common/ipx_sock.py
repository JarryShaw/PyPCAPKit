# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class Sockets(IntEnum):
    """Enumeration class for Sockets."""
    _ignore_ = 'Sockets _'
    Sockets = vars()

    # Socket Types
    Sockets['Routing Information Packet'] = 0x0001
    Sockets['Echo Protocol Packet'] = 0x0002
    Sockets['Error Handling Packet'] = 0x0003
    Sockets['NetWare Core Protocol'] = 0x0451                                   # NCP - used by Novell NetWare servers
    Sockets['Service Advertising Protocol'] = 0x0452                            # SAP
    Sockets['Routing Information Protocol'] = 0x0453                            # RIP
    Sockets['NetBIOS'] = 0x0455
    Sockets['Diagnostic Packet'] = 0x0456
    Sockets['Serialization Packet'] = 0x0457                                    # used for NCP as well
    Sockets['Used by Novell NetWare Client'] = 0x4003
    Sockets['IPX'] = 0x8060
    Sockets['TCP over IPXF'] = 0x9091
    Sockets['UDP over IPXF'] = 0x9092
    Sockets['IPXF'] = 0x9093                                                    # IPX Fragmentation Protocol

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Sockets(key)
        if key not in Sockets._member_map_:
            extend_enum(Sockets, key, default)
        return Sockets[key]

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
