# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class Transport(IntEnum):
    """Enumeration class for Transport."""
    _ignore_ = 'Transport _'
    Transport = vars()

    # HIP Transport Modes
    Transport['RESERVED'] = 0                                                   # [RFC 6261]
    Transport['DEFAULT'] = 1                                                    # [RFC 6261]
    Transport['ESP'] = 2                                                        # [RFC 6261]
    Transport['ESP-TCP'] = 3                                                    # [RFC 6261]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Transport(key)
        if key not in Transport._member_map_:
            extend_enum(Transport, key, default)
        return Transport[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 3):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        
        super()._missing_(value)
