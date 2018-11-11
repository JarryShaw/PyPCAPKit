# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class TOS_ECN(IntEnum):
    """Enumeration class for TOS_ECN."""
    _ignore_ = 'TOS_ECN _'
    TOS_ECN = vars()

    # TOS ECN FIELD
    TOS_ECN['Not-ECT'] = 0b00
    TOS_ECN['ECT(1)'] = 0b01
    TOS_ECN['ECT(0)'] = 0b10
    TOS_ECN['CE'] = 0b11

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return TOS_ECN(key)
        if key not in TOS_ECN._member_map_:
            extend_enum(TOS_ECN, key, default)
        return TOS_ECN[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0b00 <= value <= 0b11):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [0b%s]' % bin(value)[2:].zfill(2), value)
        return cls(value)
        super()._missing_(value)
