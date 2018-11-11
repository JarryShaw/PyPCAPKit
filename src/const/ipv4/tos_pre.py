# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class TOS_PRE(IntEnum):
    """Enumeration class for TOS_PRE."""
    _ignore_ = 'TOS_PRE _'
    TOS_PRE = vars()

    # TOS (DS Field) Precedence
    TOS_PRE['Network Control'] = 7
    TOS_PRE['Internetwork Control'] = 6
    TOS_PRE['CRITIC/ECP'] = 5
    TOS_PRE['Flash Override'] = 4
    TOS_PRE['Flash'] = 3
    TOS_PRE['Immediate'] = 2
    TOS_PRE['Priority'] = 1
    TOS_PRE['Routine'] = 0

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return TOS_PRE(key)
        if key not in TOS_PRE._member_map_:
            extend_enum(TOS_PRE, key, default)
        return TOS_PRE[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0b000 <= value <= 0b111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
        super()._missing_(value)
