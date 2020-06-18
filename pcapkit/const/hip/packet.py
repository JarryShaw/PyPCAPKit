# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""HIP Packet Types"""

from aenum import IntEnum, extend_enum

__all__ = ['Packet']


class Packet(IntEnum):
    """[Packet] HIP Packet Types"""

    #: Reserved [:rfc:`7401`]
    Reserved = 0

    #: I1 [:rfc:`7401`] the HIP Initiator Packet
    I1 = 1

    #: R1 [:rfc:`7401`] the HIP Responder Packet
    R1 = 2

    #: I2 [:rfc:`7401`] the Second HIP Initiator Packet
    I2 = 3

    #: R2 [:rfc:`7401`] the Second HIP Responder Packet
    R2 = 4

    #: UPDATE [:rfc:`7401`] the HIP Update Packet
    UPDATE = 16

    #: NOTIFY [:rfc:`7401`] the HIP Notify Packet
    NOTIFY = 17

    #: CLOSE [:rfc:`7401`] the HIP Association Closing Packet
    CLOSE = 18

    #: CLOSE_ACK [:rfc:`7401`] the HIP Closing Acknowledgment Packet
    CLOSE_ACK = 19

    #: HDRR [:rfc:`6537`] HIP Distributed Hash Table Resource Record
    HDRR = 20

    #: HIP_DATA [:rfc:`6078`]
    HIP_DATA = 32

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
        if not (isinstance(value, int) and 0 <= value <= 127):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 5 <= value <= 15:
            # Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 21 <= value <= 31:
            # Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 33 <= value <= 127:
            # Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        return super()._missing_(value)
