# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HIP Packet Types
======================

.. module:: pcapkit.const.hip.packet

This module contains the constant enumeration for **HIP Packet Types**,
which is automatically generated from :class:`pcapkit.vendor.hip.packet.Packet`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Packet']


class Packet(IntEnum):
    """[Packet] HIP Packet Types"""

    #: Reserved [:rfc:`7401`]
    Reserved_0 = 0

    #: I1 the HIP Initiator Packet [:rfc:`7401`]
    I1 = 1

    #: R1 the HIP Responder Packet [:rfc:`7401`]
    R1 = 2

    #: I2 the Second HIP Initiator Packet [:rfc:`7401`]
    I2 = 3

    #: R2 the Second HIP Responder Packet [:rfc:`7401`]
    R2 = 4

    #: UPDATE the HIP Update Packet [:rfc:`7401`]
    UPDATE = 16

    #: NOTIFY the HIP Notify Packet [:rfc:`7401`]
    NOTIFY = 17

    #: CLOSE the HIP Association Closing Packet [:rfc:`7401`]
    CLOSE = 18

    #: CLOSE_ACK the HIP Closing Acknowledgment Packet [:rfc:`7401`]
    CLOSE_ACK = 19

    #: HDRR (HIP Distributed Hash Table Resource Record) [:rfc:`6537`]
    HDRR = 20

    #: HIP_DATA [:rfc:`6078`]
    HIP_DATA = 32

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
        if not (isinstance(value, int) and 0 <= value <= 127):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 5 <= value <= 15:
            # Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 21 <= value <= 31:
            # Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 33 <= value <= 127:
            # Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
