# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Classification Level Encodings
====================================

.. module:: pcapkit.const.ipv4.classification_level

This module contains the constant enumeration for **Classification Level Encodings**,
which is automatically generated from :class:`pcapkit.vendor.ipv4.classification_level.ClassificationLevel`.

"""

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
    def get(key: 'int | str', default: 'int' = -1) -> 'ClassificationLevel':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return ClassificationLevel(key)
        if key not in ClassificationLevel._member_map_:  # pylint: disable=no-member
            return extend_enum(ClassificationLevel, key, default)
        return ClassificationLevel[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'ClassificationLevel':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0b00000000 <= value <= 0b11111111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        temp = bin(value)[2:].upper().zfill(8)
        return extend_enum(cls, 'Unassigned_0b%s' % (temp[:4]+'_'+temp[4:]), value)
