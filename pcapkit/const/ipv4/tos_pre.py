# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""ToS (DS Field) Precedence"""

from aenum import IntEnum, extend_enum

__all__ = ['ToS_PRE']


class ToS_PRE(IntEnum):
    """[ToS_PRE] ToS (DS Field) Precedence"""

    _ignore_ = 'ToS_PRE _'
    ToS_PRE = vars()

    ToS_PRE['Network Control'] = 7

    ToS_PRE['Internetwork Control'] = 6

    ToS_PRE['CRITIC/ECP'] = 5

    ToS_PRE['Flash Override'] = 4

    ToS_PRE['Flash'] = 3

    ToS_PRE['Immediate'] = 2

    ToS_PRE['Priority'] = 1

    ToS_PRE['Routine'] = 0

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ToS_PRE(key)
        if key not in ToS_PRE._member_map_:  # pylint: disable=no-member
            extend_enum(ToS_PRE, key, default)
        return ToS_PRE[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0b000 <= value <= 0b111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
