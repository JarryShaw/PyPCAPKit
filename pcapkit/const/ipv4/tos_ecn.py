# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""ToS ECN Field"""

from aenum import IntEnum, extend_enum

__all__ = ['ToSECN']


class ToSECN(IntEnum):
    """[ToSECN] ToS ECN Field"""

    Not_ECT = 0b00

    ECT_0b01 = 0b01

    ECT_0b10 = 0b10

    CE = 0b11

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ToSECN(key)
        if key not in ToSECN._member_map_:  # pylint: disable=no-member
            extend_enum(ToSECN, key, default)
        return ToSECN[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0b00 <= value <= 0b11):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned_0b%s' % bin(value)[2:].zfill(2), value)
        return cls(value)
