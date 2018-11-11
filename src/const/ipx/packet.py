# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class Packet(IntEnum):
    """Enumeration class for Packet."""
    _ignore_ = 'Packet _'
    Packet = vars()

    # IPX Packet Types
    Packet['Unknown'] = 0
    Packet['RIP'] = 1                                                           # Routing Information Protocol ([RFC 1582], [RFC 2091])
    Packet['Echo Packet'] = 2
    Packet['Error Packet'] = 3
    Packet['PEP'] = 4                                                           # Packet Exchange Protocol, used for SAP (Service Advertising Protocol)
    Packet['SPX'] = 5                                                           # Sequenced Packet Exchange
    Packet['NCP'] = 17                                                          # NetWare Core Protocol

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Packet(key)
        if key not in Packet._member_map_:
            extend_enum(Packet, key, default)
        return Packet[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
        super()._missing_(value)
