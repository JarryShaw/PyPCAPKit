# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""TaggerID Types
====================

.. module:: pcapkit.const.ipv6.tagger_id

This module contains the constant enumeration for **TaggerID Types**,
which is automatically generated from :class:`pcapkit.vendor.ipv6.tagger_id.TaggerID`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['TaggerID']


class TaggerID(IntEnum):
    """[TaggerID] TaggerID Types"""

    #: NULL [:rfc:`6621`]
    NULL = 0

    #: DEFAULT [:rfc:`6621`]
    DEFAULT = 1

    #: IPv4 [:rfc:`6621`]
    IPv4 = 2

    #: IPv6 [:rfc:`6621`]
    IPv6 = 3

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'TaggerID':
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
                return TaggerID(key)
            except ValueError:
                if default == -1:
                    raise
                return TaggerID(default)
        try:
            return TaggerID[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return TaggerID(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'TaggerID':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'TaggerID':
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
    def _missing_(cls, value: 'int') -> 'TaggerID':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 7):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 4 <= value <= 7:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
