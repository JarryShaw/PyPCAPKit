# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""ToS (DS Field) Precedence
===============================

.. module:: pcapkit.const.ipv4.tos_pre

This module contains the constant enumeration for **ToS (DS Field) Precedence**,
which is automatically generated from :class:`pcapkit.vendor.ipv4.tos_pre.ToSPrecedence`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['ToSPrecedence']


class ToSPrecedence(IntEnum):
    """[ToSPrecedence] ToS (DS Field) Precedence"""

    Network_Control = 7

    Internetwork_Control = 6

    CRITIC_ECP = 5

    Flash_Override = 4

    Flash = 3

    Immediate = 2

    Priority = 1

    Routine = 0

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'ToSPrecedence':
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
                return ToSPrecedence(key)
            except ValueError:
                if default == -1:
                    raise
                return ToSPrecedence(default)
        try:
            return ToSPrecedence[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return ToSPrecedence(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'ToSPrecedence':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'ToSPrecedence':
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
    def _missing_(cls, value: 'int') -> 'ToSPrecedence':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0b000 <= value <= 0b111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)
