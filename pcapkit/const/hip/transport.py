# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HIP Transport Modes
=========================

.. module:: pcapkit.const.hip.transport

This module contains the constant enumeration for **HIP Transport Modes**,
which is automatically generated from :class:`pcapkit.vendor.hip.transport.Transport`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Transport']


class Transport(IntEnum):
    """[Transport] HIP Transport Modes"""

    #: RESERVED [:rfc:`6261`]
    RESERVED_0 = 0

    #: DEFAULT [:rfc:`6261`]
    DEFAULT = 1

    #: ESP [:rfc:`6261`]
    ESP = 2

    #: ESP-TCP [:rfc:`6261`]
    ESP_TCP = 3

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Transport':
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
                return Transport(key)
            except ValueError:
                if default == -1:
                    raise
                return Transport(default)
        try:
            return Transport[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return Transport(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'Transport':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'Transport':
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
    def _missing_(cls, value: 'int') -> 'Transport':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 3):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)
