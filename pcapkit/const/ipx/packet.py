# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""IPX Packet Types
======================

.. module:: pcapkit.const.ipx.packet

This module contains the constant enumeration for **IPX Packet Types**,
which is automatically generated from :class:`pcapkit.vendor.ipx.packet.Packet`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Packet']


class Packet(IntEnum):
    """[Packet] IPX Packet Types"""

    #: Unknown
    Unknown = 0

    #: ``RIP``, Routing Information Protocol ([:rfc:`1582`], [:rfc:`2091`])
    RIP = 1

    #: Echo Packet
    Echo_Packet = 2

    #: Error Packet
    Error_Packet = 3

    #: ``PEP``, Packet Exchange Protocol, used for SAP (Service Advertising
    #: Protocol)
    PEP = 4

    #: ``SPX``, Sequenced Packet Exchange
    SPX = 5

    #: ``NCP``, NetWare Core Protocol
    NCP = 17

    #: Broadcast[4]
    Broadcast_4 = 20

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
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)
