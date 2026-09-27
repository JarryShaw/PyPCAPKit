# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Access Network Information (ANI) Sub-Option Type Values
=============================================================

.. module:: pcapkit.const.mh.ani_suboption

This module contains the constant enumeration for **Access Network Information (ANI) Sub-Option Type Values**,
which is automatically generated from :class:`pcapkit.vendor.mh.ani_suboption.ANISuboption`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['ANISuboption']


class ANISuboption(IntEnum):
    """[ANISuboption] Access Network Information (ANI) Sub-Option Type Values"""

    #: Reserved [:rfc:`6757`]
    Reserved_0 = 0

    #: Network-Identifier sub-option [:rfc:`6757`]
    Network_Identifier = 1

    #: Geo-Location sub-option [:rfc:`6757`]
    Geo_Location = 2

    #: Operator-Identifier sub-option [:rfc:`6757`]
    Operator_Identifier = 3

    #: Civic-Location sub-option [:rfc:`7563`]
    Civic_Location = 4

    #: MAG-Group-Identifier sub-option [:rfc:`7563`]
    MAG_Group_Identifier = 5

    #: ANI Update-Timer sub-option [:rfc:`7563`]
    ANI_Update_Timer = 6

    #: Reserved [:rfc:`6757`]
    Reserved_255 = 255

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'ANISuboption':
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
                return ANISuboption(key)
            except ValueError:
                if default == -1:
                    raise
                return ANISuboption(default)
        try:
            return ANISuboption[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return ANISuboption(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'ANISuboption':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'ANISuboption':
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
    def _missing_(cls, value: 'int') -> 'ANISuboption':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 7 <= value <= 254:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
