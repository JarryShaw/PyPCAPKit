# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""IPX Packet Types"""

from aenum import IntEnum, extend_enum

__all__ = ['Packet']


class Packet(IntEnum):
    """[Packet] IPX Packet Types"""

    #: Unknown
    Unknown = 0

    #: RIP - Routing Information Protocol ([:rfc:`1582`], [:rfc:`2091`])
    RIP = 1

    #: Echo Packet
    Echo_Packet = 2

    #: Error Packet
    Error_Packet = 3

    #: PEP - Packet Exchange Protocol, used for SAP (Service Advertising Protocol)
    PEP = 4

    #: SPX - Sequenced Packet Exchange
    SPX = 5

    #: NCP - NetWare Core Protocol
    NCP = 17

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
        extend_enum(cls, 'Unassigned_%d' % value, value)
        return cls(value)
