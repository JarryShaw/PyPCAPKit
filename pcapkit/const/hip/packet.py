# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""HIP Packet Types"""

from aenum import IntEnum, extend_enum

__all__ = ['Packet']


class Packet(IntEnum):
    """[Packet] HIP Packet Types"""

    _ignore_ = 'Packet _'
    Packet = vars()

    #: [:rfc:`7401`]
    Packet['Reserved'] = 0

    #: [:rfc:`7401`] the HIP Initiator Packet
    Packet['I1'] = 1

    #: [:rfc:`7401`] the HIP Responder Packet
    Packet['R1'] = 2

    #: [:rfc:`7401`] the Second HIP Initiator Packet
    Packet['I2'] = 3

    #: [:rfc:`7401`] the Second HIP Responder Packet
    Packet['R2'] = 4

    #: [:rfc:`7401`] the HIP Update Packet
    Packet['UPDATE'] = 16

    #: [:rfc:`7401`] the HIP Notify Packet
    Packet['NOTIFY'] = 17

    #: [:rfc:`7401`] the HIP Association Closing Packet
    Packet['CLOSE'] = 18

    #: [:rfc:`7401`] the HIP Closing Acknowledgment Packet
    Packet['CLOSE_ACK'] = 19

    #: [:rfc:`6537`] HIP Distributed Hash Table Resource Record
    Packet['HDRR'] = 20

    #: [:rfc:`6078`]
    Packet['HIP_DATA'] = 32

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
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 21 <= value <= 31:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 33 <= value <= 127:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        return super()._missing_(value)
