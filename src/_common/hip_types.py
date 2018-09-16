# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class PktType(IntEnum):
    """Enumeration class for PktType."""
    _ignore_ = 'PktType _'
    PktType = vars()

    # HIP Packet Types
    PktType['Reserved'] = 0                                                     # [RFC 7401]
    PktType['I1'] = 1                                                           # [RFC 7401] the HIP Initiator Packet
    PktType['R1'] = 2                                                           # [RFC 7401] the HIP Responder Packet
    PktType['I2'] = 3                                                           # [RFC 7401] the Second HIP Initiator Packet
    PktType['R2'] = 4                                                           # [RFC 7401] the Second HIP Responder Packet
    PktType['UPDATE'] = 16                                                      # [RFC 7401] the HIP Update Packet
    PktType['NOTIFY'] = 17                                                      # [RFC 7401] the HIP Notify Packet
    PktType['CLOSE'] = 18                                                       # [RFC 7401] the HIP Association Closing Packet
    PktType['CLOSE_ACK'] = 19                                                   # [RFC 7401] the HIP Closing Acknowledgment Packet
    PktType['HDRR'] = 20                                                        # [RFC 6537] HIP Distributed Hash Table Resource Record
    PktType['HIP_DATA'] = 32                                                    # [RFC 6078]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return PktType(key)
        if key not in PktType._member_map_:
            extend_enum(PktType, key, default)
        return PktType[key]

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
