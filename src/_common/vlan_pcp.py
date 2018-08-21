# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class PrioLvl(IntEnum):
    """Enumeration class for PrioLvl."""
    _ignore_ = 'PrioLvl _'
    PrioLvl = vars()

    # priority levels defined in IEEE 802.1p
    PrioLvl['BK'] = 0b001                                                       # 0 - Background (lowest)
    PrioLvl['BE'] = 0b000                                                       # 1 - Best effort (default)
    PrioLvl['EE'] = 0b010                                                       # 2 - Excellent effort
    PrioLvl['CA'] = 0b011                                                       # 3 - Critical applications
    PrioLvl['VI'] = 0b100                                                       # 4 - Video, < 100 ms latency and jitter
    PrioLvl['VO'] = 0b101                                                       # 5 - Voice, < 10 ms latency and jitter
    PrioLvl['IC'] = 0b110                                                       # 6 - Internetwork control
    PrioLvl['NC'] = 0b111                                                       # 7 - Network control (highest)

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return PrioLvl(key)
        if key not in PrioLvl._member_map_:
            extend_enum(PrioLvl, key, default)
        return PrioLvl[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0b000 <= value <= 0b111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [0b%s]' % bin(value)[2:].zfill(3), value)
        return cls(value)
