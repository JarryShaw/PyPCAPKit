# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class PktType(IntEnum):
    """Enumeration class for PktType."""
    _ignore_ = 'PktType _'
    PktType = vars()

    # OSPF Packet Types
    PktType['Reserved'] = 0
    PktType['Hello'] = 1                                                        # [RFC 2328]
    PktType['Database Description'] = 2                                         # [RFC 2328]
    PktType['Link State Request'] = 3                                           # [RFC 2328]
    PktType['Link State Update'] = 4                                            # [RFC 2328]
    PktType['Link State Ack'] = 5                                               # [RFC 2328]

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
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 6 <= value <= 127:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 128 <= value <= 255:
            extend_enum(cls, 'Reserved [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
