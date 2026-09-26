# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Mobile Node Identifier Option Subtypes
============================================

.. module:: pcapkit.const.mh.mn_id_subtype

This module contains the constant enumeration for **Mobile Node Identifier Option Subtypes**,
which is automatically generated from :class:`pcapkit.vendor.mh.mn_id_subtype.MNIDSubtype`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['MNIDSubtype']


class MNIDSubtype(IntEnum):
    """[MNIDSubtype] Mobile Node Identifier Option Subtypes"""

    #: NAI [:rfc:`4283`]
    NAI = 1

    #: IPv6 Address [:rfc:`8371`]
    IPv6_Address = 2

    #: IMSI [:rfc:`8371`]
    IMSI = 3

    #: P-TMSI [:rfc:`8371`]
    P_TMSI = 4

    #: EUI-48 address [:rfc:`8371`]
    EUI_48_address = 5

    #: EUI-64 address [:rfc:`8371`]
    EUI_64_address = 6

    #: GUTI [:rfc:`8371`]
    GUTI = 7

    #: DUID [:rfc:`8371`]
    DUID = 8

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'MNIDSubtype':
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
                return MNIDSubtype(key)
            except ValueError:
                if default == -1:
                    raise
                return MNIDSubtype(default)
        try:
            return MNIDSubtype[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return MNIDSubtype(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'MNIDSubtype':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'MNIDSubtype':
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
    def _missing_(cls, value: 'int') -> 'MNIDSubtype':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 9 <= value <= 15:
            #: Reserved [:rfc:`8371`]
            return extend_enum(cls, 'Reserved_%d' % value, value)
        if 16 <= value <= 255:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
