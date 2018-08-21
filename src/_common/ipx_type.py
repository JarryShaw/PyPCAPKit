# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class PktType(IntEnum):
    """Enumeration class for PktType."""
    _ignore_ = 'PktType _'
    PktType = vars()

    # IPX Packet Types
    PktType['Unknown'] = 0
    PktType['RIP'] = 1                                                          # Routing Information Protocol ([RFC 1582], [RFC 2091])
    PktType['Echo Packet'] = 2
    PktType['Error Packet'] = 3
    PktType['PEP'] = 4                                                          # Packet Exchange Protocol, used for SAP (Service Advertising Protocol)
    PktType['SPX'] = 5                                                          # Sequenced Packet Exchange
    PktType['NCP'] = 17                                                         # NetWare Core Protocol

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return PktType(key)
        if key not in PktType._member_map_:
            extend_enum(PktType, key, default)
        return PktType[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
