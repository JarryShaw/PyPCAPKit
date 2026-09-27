# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Pseudo Home Address Acknowledgement Status Codes
======================================================

.. module:: pcapkit.const.mh.ack_status_code

This module contains the constant enumeration for **Pseudo Home Address Acknowledgement Status Codes**,
which is automatically generated from :class:`pcapkit.vendor.mh.ack_status_code.ACKStatusCode`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['ACKStatusCode']


class ACKStatusCode(IntEnum):
    """[ACKStatusCode] Pseudo Home Address Acknowledgement Status Codes"""

    #: Success [:rfc:`5726`]
    Success = 0

    #: Failure, reason unspecified [:rfc:`5726`]
    Failure_reason_unspecified = 128

    #: Administratively prohibited [:rfc:`5726`]
    Administratively_prohibited = 129

    #: Incorrect pseudo home address [:rfc:`5726`]
    Incorrect_pseudo_home_address = 130

    #: Invalid pseudo home address [:rfc:`5726`]
    Invalid_pseudo_home_address = 131

    #: Dynamic pseudo home address assignment not available [:rfc:`5726`]
    Dynamic_pseudo_home_address_assignment_not_available = 132

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'ACKStatusCode':
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
                return ACKStatusCode(key)
            except ValueError:
                if default == -1:
                    raise
                return ACKStatusCode(default)
        try:
            return ACKStatusCode[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return ACKStatusCode(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'ACKStatusCode':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'ACKStatusCode':
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
    def _missing_(cls, value: 'int') -> 'ACKStatusCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 1 <= value <= 127:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 133 <= value <= 255:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
