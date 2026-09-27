# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Flow Identification Sub-Options
=====================================

.. module:: pcapkit.const.mh.flow_id_suboption

This module contains the constant enumeration for **Flow Identification Sub-Options**,
which is automatically generated from :class:`pcapkit.vendor.mh.flow_id_suboption.FlowIDSuboption`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['FlowIDSuboption']


class FlowIDSuboption(IntEnum):
    """[FlowIDSuboption] Flow Identification Sub-Options"""

    #: Pad [:rfc:`6089`]
    Pad = 0

    #: PadN [:rfc:`6089`]
    PadN = 1

    #: BID Reference [:rfc:`6089`]
    BID_Reference = 2

    #: Traffic Selector [:rfc:`6089`]
    Traffic_Selector = 3

    #: Flow Binding Action [:rfc:`7109`]
    Flow_Binding_Action = 4

    #: Target Care-of Address [:rfc:`7109`]
    Target_Care_of_Address = 5

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'FlowIDSuboption':
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
                return FlowIDSuboption(key)
            except ValueError:
                if default == -1:
                    raise
                return FlowIDSuboption(default)
        try:
            return FlowIDSuboption[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return FlowIDSuboption(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'FlowIDSuboption':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'FlowIDSuboption':
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
    def _missing_(cls, value: 'int') -> 'FlowIDSuboption':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 6 <= value <= 250:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 251 <= value <= 255:
            #: Reserved for Experimental Use [:rfc:`6089`]
            return extend_enum(cls, 'Reserved_for_Experimental_Use_%d' % value, value)
        return super()._missing_(value)
