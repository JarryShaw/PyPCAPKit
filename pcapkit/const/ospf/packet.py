# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""OSPF Packet Types"""

from aenum import IntEnum, extend_enum

__all__ = ['Packet']


class Packet(IntEnum):
    """[Packet] OSPF Packet Types"""

    _ignore_ = 'Packet _'
    Packet = vars()

    Packet['Reserved'] = 0

    #: [:rfc:`2328`]
    Packet['Hello'] = 1

    #: [:rfc:`2328`]
    Packet['Database_Description'] = 2

    #: [:rfc:`2328`]
    Packet['Link_State_Request'] = 3

    #: [:rfc:`2328`]
    Packet['Link_State_Update'] = 4

    #: [:rfc:`2328`]
    Packet['Link_State_Ack'] = 5

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
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 6 <= value <= 127:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 128 <= value <= 255:
            extend_enum(cls, 'Reserved [%d]' % value, value)
            return cls(value)
        return super()._missing_(value)
