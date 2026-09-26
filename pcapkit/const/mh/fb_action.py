# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Flow Binding Action Values
================================

.. module:: pcapkit.const.mh.fb_action

This module contains the constant enumeration for **Flow Binding Action Values**,
which is automatically generated from :class:`pcapkit.vendor.mh.fb_action.FlowBindingAction`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['FlowBindingAction']


class FlowBindingAction(IntEnum):
    """[FlowBindingAction] Flow Binding Action Values"""

    #: Add a flow binding [:rfc:`7109`]
    Add = 11

    #: Delete a flow binding [:rfc:`7109`]
    Delete = 12

    #: Modify a flow binding [:rfc:`7109`]
    Modify = 13

    #: Refresh a flow binding [:rfc:`7109`]
    Refresh = 14

    #: Move a flow binding [:rfc:`7109`]
    Move = 15

    #: Revoke a flow binding [:rfc:`7109`]
    Revoke = 16

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'FlowBindingAction':
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
                return FlowBindingAction(key)
            except ValueError:
                if default == -1:
                    raise
                return FlowBindingAction(default)
        try:
            return FlowBindingAction[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return FlowBindingAction(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'FlowBindingAction':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'FlowBindingAction':
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
    def _missing_(cls, value: 'int') -> 'FlowBindingAction':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0 <= value <= 10:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 17 <= value <= 255:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
