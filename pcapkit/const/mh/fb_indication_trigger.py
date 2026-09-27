# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Flow Binding Indication Triggers
======================================

.. module:: pcapkit.const.mh.fb_indication_trigger

This module contains the constant enumeration for **Flow Binding Indication Triggers**,
which is automatically generated from :class:`pcapkit.vendor.mh.fb_indication_trigger.FlowBindingIndicationTrigger`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['FlowBindingIndicationTrigger']


class FlowBindingIndicationTrigger(IntEnum):
    """[FlowBindingIndicationTrigger] Flow Binding Indication Triggers"""

    #: Reserved [:rfc:`7109`]
    Reserved_0 = 0

    #: Unspecified [:rfc:`7109`]
    Unspecified = 1

    #: Administrative Reason [:rfc:`7109`]
    Administrative_Reason = 2

    #: Possible Out-of-Sync BCE State [:rfc:`7109`]
    Possible_Out_of_Sync_BCE_State = 3

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'FlowBindingIndicationTrigger':
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
                return FlowBindingIndicationTrigger(key)
            except ValueError:
                if default == -1:
                    raise
                return FlowBindingIndicationTrigger(default)
        try:
            return FlowBindingIndicationTrigger[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return FlowBindingIndicationTrigger(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'FlowBindingIndicationTrigger':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'FlowBindingIndicationTrigger':
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
    def _missing_(cls, value: 'int') -> 'FlowBindingIndicationTrigger':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 4 <= value <= 249:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 250 <= value <= 255:
            #: Reserved for Testing Purposes Only [:rfc:`7109`]
            return extend_enum(cls, 'Reserved_for_Testing_Purposes_Only_%d' % value, value)
        return super()._missing_(value)
