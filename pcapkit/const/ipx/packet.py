# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""IPX Packet Types"""

from aenum import IntEnum, extend_enum

__all__ = ['Packet']


class Packet(IntEnum):
    """[Packet] IPX Packet Types"""

    _ignore_ = 'Packet _'
    Packet = vars()

    Packet['Unknown'] = 0

    #: Routing Information Protocol ([:rfc:`1582`], [:rfc:`2091`])
    Packet['RIP'] = 1

    Packet['Echo_Packet'] = 2

    Packet['Error_Packet'] = 3

    #: Packet Exchange Protocol, used for SAP (Service Advertising Protocol)
    Packet['PEP'] = 4

    #: Sequenced Packet Exchange
    Packet['SPX'] = 5

    #: NetWare Core Protocol
    Packet['NCP'] = 17

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Packet(key)
        if key not in Packet._member_map_:  # pylint: disable=no-member
            extend_enum(Packet, key, default)
        return Packet[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
