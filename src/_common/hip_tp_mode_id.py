# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class TAT_ModeID(IntEnum):
    """Enumeration class for TAT_ModeID."""
    _ignore_ = 'TAT_ModeID _'
    TAT_ModeID = vars()

    # HIP Transport Modes
    TAT_ModeID['RESERVED'] = 0                                                  # [RFC 6261]
    TAT_ModeID['DEFAULT'] = 1                                                   # [RFC 6261]
    TAT_ModeID['ESP'] = 2                                                       # [RFC 6261]
    TAT_ModeID['ESP-TCP'] = 3                                                   # [RFC 6261]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return TAT_ModeID(key)
        if key not in TAT_ModeID._member_map_:
            extend_enum(TAT_ModeID, key, default)
        return TAT_ModeID[key]
