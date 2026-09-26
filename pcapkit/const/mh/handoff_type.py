# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Handoff Indicator Option Type Values
==========================================

.. module:: pcapkit.const.mh.handoff_type

This module contains the constant enumeration for **Handoff Indicator Option Type Values**,
which is automatically generated from :class:`pcapkit.vendor.mh.handoff_type.HandoffType`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['HandoffType']


class HandoffType(IntEnum):
    """[HandoffType] Handoff Indicator Option Type Values"""

    #: Reserved [:rfc:`5213`]
    Reserved_0 = 0

    #: Attachment over a new interface [:rfc:`5213`]
    Attachment_over_a_new_interface = 1

    #: Handoff between two different interfaces of the mobile node [:rfc:`5213`]
    Handoff_between_two_different_interfaces_of_the_mobile_node = 2

    #: Handoff between mobile access gateways for the same interface [:rfc:`5213`]
    Handoff_between_mobile_access_gateways_for_the_same_interface = 3

    #: Handoff state unknown [:rfc:`5213`]
    Handoff_state_unknown = 4

    #: Handoff state not changed (Re-registration) [:rfc:`5213`]
    Handoff_state_not_changed = 5

    #: Attachment over a new interface sharing prefixes [:rfc:`7864`]
    Attachment_over_a_new_interface_sharing_prefixes = 6

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'HandoffType':
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
                return HandoffType(key)
            except ValueError:
                if default == -1:
                    raise
                return HandoffType(default)
        try:
            return HandoffType[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return HandoffType(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'HandoffType':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'HandoffType':
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
    def _missing_(cls, value: 'int') -> 'HandoffType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 7 <= value <= 255:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
