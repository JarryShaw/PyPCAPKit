# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class PriorityLevel(IntEnum):
    """Enumeration class for PriorityLevel."""
    _ignore_ = 'PriorityLevel _'
    PriorityLevel = vars()

    # priority levels defined in IEEE 802.1p
    PriorityLevel['BK'] = 0b001                                                 # 0 - Background (lowest)
    PriorityLevel['BE'] = 0b000                                                 # 1 - Best effort (default)
    PriorityLevel['EE'] = 0b010                                                 # 2 - Excellent effort
    PriorityLevel['CA'] = 0b011                                                 # 3 - Critical applications
    PriorityLevel['VI'] = 0b100                                                 # 4 - Video, < 100 ms latency and jitter
    PriorityLevel['VO'] = 0b101                                                 # 5 - Voice, < 10 ms latency and jitter
    PriorityLevel['IC'] = 0b110                                                 # 6 - Internetwork control
    PriorityLevel['NC'] = 0b111                                                 # 7 - Network control (highest)

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return PriorityLevel(key)
        if key not in PriorityLevel._member_map_:
            extend_enum(PriorityLevel, key, default)
        return PriorityLevel[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0b000 <= value <= 0b111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [0b%s]' % bin(value)[2:].zfill(3), value)
        return cls(value)
        super()._missing_(value)
