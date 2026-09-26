# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Priority levels defined in IEEE 802.1p
============================================

.. module:: pcapkit.const.vlan.priority_level

This module contains the constant enumeration for **Priority levels defined in IEEE 802.1p**,
which is automatically generated from :class:`pcapkit.vendor.vlan.priority_level.PriorityLevel`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['PriorityLevel']


class PriorityLevel(IntEnum):
    """[PriorityLevel] Priority levels defined in IEEE 802.1p"""

    #: Background (lowest)
    BK = 0b001

    #: Best effort (default)
    BE = 0b000

    #: Excellent effort
    EE = 0b010

    #: Critical applications
    CA = 0b011

    #: Video, < 100 ms latency and jitter
    VI = 0b100

    #: Voice, < 10 ms latency and jitter
    VO = 0b101

    #: Internetwork control
    IC = 0b110

    #: Network control (highest)
    NC = 0b111

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'PriorityLevel':
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
                return PriorityLevel(key)
            except ValueError:
                if default == -1:
                    raise
                return PriorityLevel(default)
        try:
            return PriorityLevel[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return PriorityLevel(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'PriorityLevel':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'PriorityLevel':
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
    def _missing_(cls, value: 'int') -> 'PriorityLevel':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0b000 <= value <= 0b111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned [0b%s]' % bin(value)[2:].zfill(3), value)
