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
            default: Default value if not found. The placeholder ``-1`` stands
                for *no default*, in which case an unresolvable key propagates
                the lookup error instead of falling back.

        :meta private:
        """
        if isinstance(key, int):
            try:
                return ClassificationLevel(key)
            except ValueError:
                if default == -1:
                    raise
                return ClassificationLevel(default)
        try:
            return ClassificationLevel[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return ClassificationLevel(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'ClassificationLevel':
        """Explicitly register a new member.

        Unlike :meth:`get` and :meth:`_missing_`, which resolve a key or a
        value without minting anything new, this is the caller-named entry
        point that still grows the registry, via :func:`aenum.extend_enum`.

        Args:
            value: Value of the new member.
            name: Name of the new member.

        Returns:
            The newly registered member.

        """
        return extend_enum(cls, name, value)

    @classmethod
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'ClassificationLevel':
        """Build a member absent from this registry's own lookup tables.

        Used by :meth:`_missing_` for a bounded-but-unassigned value it
        resolves without anyone asking for a name, so that such a lookup no
        longer grows the registry -- contrast :meth:`register`, the explicit
        path that still does.

        Args:
            value: The member's value.
            name: The member's name.

        Returns:
            The unregistered member.

        """
        obj = int.__new__(cls, value)
        obj._name_ = name  # pylint: disable=protected-access
        obj._value_ = value  # pylint: disable=protected-access
        return obj

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
