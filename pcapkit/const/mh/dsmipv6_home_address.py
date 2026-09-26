# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Dual Stack MIPv6 (DSMIPv6) IPv4 Home Address Option Status Codes
======================================================================

.. module:: pcapkit.const.mh.dsmipv6_home_address

This module contains the constant enumeration for **Dual Stack MIPv6 (DSMIPv6) IPv4 Home Address Option Status Codes**,
which is automatically generated from :class:`pcapkit.vendor.mh.dsmipv6_home_address.DSMIPv6HomeAddress`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['DSMIPv6HomeAddress']


class DSMIPv6HomeAddress(IntEnum):
    """[DSMIPv6HomeAddress] Dual Stack MIPv6 (DSMIPv6) IPv4 Home Address Option Status Codes"""

    #: Success [:rfc:`5555`]
    Success = 0

    #: Failure, reason unspecified [:rfc:`5555`]
    Failure_reason_unspecified = 128

    #: Administratively prohibited [:rfc:`5555`]
    Administratively_prohibited = 129

    #: Incorrect IPv4 home address [:rfc:`5555`]
    Incorrect_IPv4_home_address = 130

    #: Invalid IPv4 address [:rfc:`5555`]
    Invalid_IPv4_address = 131

    #: Dynamic IPv4 home address assignment not available [:rfc:`5555`]
    Dynamic_IPv4_home_address_assignment_not_available = 132

    #: Prefix allocation unauthorized [:rfc:`5555`]
    Prefix_allocation_unauthorized = 133

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'DSMIPv6HomeAddress':
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
                return DSMIPv6HomeAddress(key)
            except ValueError:
                if default == -1:
                    raise
                return DSMIPv6HomeAddress(default)
        try:
            return DSMIPv6HomeAddress[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return DSMIPv6HomeAddress(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'DSMIPv6HomeAddress':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'DSMIPv6HomeAddress':
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
    def _missing_(cls, value: 'int') -> 'DSMIPv6HomeAddress':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 1 <= value <= 127:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 134 <= value <= 255:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
