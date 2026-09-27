# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Operator-Identifier Type Registry
=======================================

.. module:: pcapkit.const.mh.operator_id

This module contains the constant enumeration for **Operator-Identifier Type Registry**,
which is automatically generated from :class:`pcapkit.vendor.mh.operator_id.OperatorID`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['OperatorID']


class OperatorID(IntEnum):
    """[OperatorID] Operator-Identifier Type Registry"""

    #: Reserved [:rfc:`6757`]
    Reserved_0 = 0

    #: Operator-Identifier as a variable-length Private Enterprise Number (PEN)
    #: [:rfc:`6757`]
    Operator_Identifier_as_a_variable_length_Private_Enterprise_Number = 1

    #: Realm of the Operator [:rfc:`6757`]
    Realm_of_the_Operator = 2

    #: Reserved [:rfc:`6757`]
    Reserved_255 = 255

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'OperatorID':
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
                return OperatorID(key)
            except ValueError:
                if default == -1:
                    raise
                return OperatorID(default)
        try:
            return OperatorID[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return OperatorID(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'OperatorID':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'OperatorID':
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
    def _missing_(cls, value: 'int') -> 'OperatorID':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 3 <= value <= 254:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
