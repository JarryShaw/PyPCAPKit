# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class Packet(IntEnum):
    """Enumeration class for Packet."""
    _ignore_ = 'Packet _'
    Packet = vars()

    # HIP Packet Types
    Packet['Reserved'] = 0                                                      # [RFC 7401]
    Packet['I1'] = 1                                                            # [RFC 7401] the HIP Initiator Packet
    Packet['R1'] = 2                                                            # [RFC 7401] the HIP Responder Packet
    Packet['I2'] = 3                                                            # [RFC 7401] the Second HIP Initiator Packet
    Packet['R2'] = 4                                                            # [RFC 7401] the Second HIP Responder Packet
    Packet['UPDATE'] = 16                                                       # [RFC 7401] the HIP Update Packet
    Packet['NOTIFY'] = 17                                                       # [RFC 7401] the HIP Notify Packet
    Packet['CLOSE'] = 18                                                        # [RFC 7401] the HIP Association Closing Packet
    Packet['CLOSE_ACK'] = 19                                                    # [RFC 7401] the HIP Closing Acknowledgment Packet
    Packet['HDRR'] = 20                                                         # [RFC 6537] HIP Distributed Hash Table Resource Record
    Packet['HIP_DATA'] = 32                                                     # [RFC 6078]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Packet(key)
        if key not in Packet._member_map_:
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
        super()._missing_(value)
