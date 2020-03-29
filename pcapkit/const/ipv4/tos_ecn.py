# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""ToS ECN FIELD"""

from aenum import IntEnum, extend_enum

__all__ = ['ToS_ECN']


class ToS_ECN(IntEnum):
    """[ToS_ECN] ToS ECN FIELD"""

    _ignore_ = 'ToS_ECN _'
    ToS_ECN = vars()

    ToS_ECN['Not-ECT'] = 0b00

    ToS_ECN['ECT(1)'] = 0b01

    ToS_ECN['ECT(0)'] = 0b10

    ToS_ECN['CE'] = 0b11

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ToS_ECN(key)
        if key not in ToS_ECN._member_map_:  # pylint: disable=no-member
            extend_enum(ToS_ECN, key, default)
        return ToS_ECN[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0b00 <= value <= 0b11):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [0b%s]' % bin(value)[2:].zfill(2), value)
        return cls(value)
