# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""OSPF Packet Types
=======================

.. module:: pcapkit.const.ospf.packet

This module contains the constant enumeration for **OSPF Packet Types**,
which is automatically generated from :class:`pcapkit.vendor.ospf.packet.Packet`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Packet']


class Packet(IntEnum):
    """[Packet] OSPF Packet Types"""

    #: Reserved
    Reserved_0 = 0

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
    def get(key: 'int | str', default: 'int' = -1) -> 'Packet':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return Packet(key)
        if key not in Packet._member_map_:  # pylint: disable=no-member
            return extend_enum(Packet, key, default)
        return Packet[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'Packet':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 6 <= value <= 127:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 128 <= value <= 255:
            #: Reserved
            return extend_enum(cls, 'Reserved_%d' % value, value)
        return super()._missing_(value)
