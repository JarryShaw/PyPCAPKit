# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Classification Level Encodings"""

from aenum import IntEnum, extend_enum

__all__ = ['ClassificationLevel']


class ClassificationLevel(IntEnum):
    """[ClassificationLevel] Classification Level Encodings"""

    Reserved_4 = 0b00000001

    Top_Secret = 0b00111101

    Secret = 0b01011010

    Confidential = 0b10010110

    Reserved_3 = 0b01100110

    Reserved_2 = 0b11001100

    Unclassified = 0b10101011

    Reserved_1 = 0b11110001

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ClassificationLevel(key)
        if key not in ClassificationLevel._member_map_:  # pylint: disable=no-member
            extend_enum(ClassificationLevel, key, default)
        return ClassificationLevel[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0b00000000 <= value <= 0b11111111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        temp = bin(value)[2:].upper().zfill(8)
        extend_enum(cls, 'Unassigned_0b%s' % (temp[:4]+'_'+temp[4:]), value)
        return cls(value)
