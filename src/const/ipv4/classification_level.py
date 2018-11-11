# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class ClassificationLevel(IntEnum):
    """Enumeration class for ClassificationLevel."""
    _ignore_ = 'ClassificationLevel _'
    ClassificationLevel = vars()

    # Classification Level Encodings
    ClassificationLevel['Reserved [4]'] = 0b0000_0001
    ClassificationLevel['Top Secret'] = 0b0011_1101
    ClassificationLevel['Secret'] = 0b0101_1010
    ClassificationLevel['Confidential'] = 0b1001_0110
    ClassificationLevel['Reserved [3]'] = 0b0110_0110
    ClassificationLevel['Reserved [2]'] = 0b1100_1100
    ClassificationLevel['Unclassified'] = 0b1010_1011
    ClassificationLevel['Reserved [1]'] = 0b1111_0001

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ClassificationLevel(key)
        if key not in ClassificationLevel._member_map_:
            extend_enum(ClassificationLevel, key, default)
        return ClassificationLevel[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0b0000_0000 <= value <= 0b1111_1111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        temp = bin(value)[2:].upper().zfill(8)
        extend_enum(cls, 'Unassigned [0b%s]' % (temp[:4]+'_'+temp[4:]), value)
        return cls(value)
        super()._missing_(value)
