# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class RegFailType(IntEnum):
    """Enumeration class for RegFailType."""
    _ignore_ = 'RegFailType _'
    RegFailType = vars()

    # Registration Failure Types
    RegFailType['Registration requires additional credentials'] = 0             # [RFC 8003]
    RegFailType['Registration type unavailable'] = 1                            # [RFC 8003]
    RegFailType['Insufficient resources'] = 2                                   # [RFC 8003]
    RegFailType['Invalid certificate'] = 3                                      # [RFC 8003]
    RegFailType['Bad certificate'] = 4                                          # [RFC 8003]
    RegFailType['Unsupported certificate'] = 5                                  # [RFC 8003]
    RegFailType['Certificate expired'] = 6                                      # [RFC 8003]
    RegFailType['Certificate other'] = 7                                        # [RFC 8003]
    RegFailType['Unknown CA'] = 8                                               # [RFC 8003]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return RegFailType(key)
        if key not in RegFailType._member_map_:
            extend_enum(RegFailType, key, default)
        return RegFailType[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 9 <= value <= 200:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 201 <= value <= 255:
            # [RFC 8003]
            extend_enum(cls, 'Reserved for Private Use [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
