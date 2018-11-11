# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class TOS_THR(IntEnum):
    """Enumeration class for TOS_THR."""
    _ignore_ = 'TOS_THR _'
    TOS_THR = vars()

    # TOS (DS Field) Throughput
    TOS_THR['NORMAL'] = 0
    TOS_THR['HIGH'] = 1

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return TOS_THR(key)
        if key not in TOS_THR._member_map_:
            extend_enum(TOS_THR, key, default)
        return TOS_THR[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
        super()._missing_(value)
