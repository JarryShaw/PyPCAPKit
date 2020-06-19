# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""OSPF Packet Types"""

from aenum import IntEnum, extend_enum

__all__ = ['Packet']


class Packet(IntEnum):
    """[Packet] OSPF Packet Types"""

    #: Reserved
    Reserved = 0

    #: Hello [:rfc:`2328`]
    Hello = 1

    #: Database Description [:rfc:`2328`]
    Database_Description = 2

    #: Link State Request [:rfc:`2328`]
    Link_State_Request = 3

    #: Link State Update [:rfc:`2328`]
    Link_State_Update = 4

    #: Link State Ack [:rfc:`2328`]
    Link_State_Ack = 5

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
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 128 <= value <= 255:
            #: Reserved
            extend_enum(cls, 'Reserved_%d' % value, value)
            return cls(value)
        return super()._missing_(value)
