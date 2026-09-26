# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Registration Types
========================

.. module:: pcapkit.const.hip.registration

This module contains the constant enumeration for **Registration Types**,
which is automatically generated from :class:`pcapkit.vendor.hip.registration.Registration`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Registration']


class Registration(IntEnum):
    """[Registration] Registration Types"""

    #: Unassigned
    Unassigned_0 = 0

    #: RENDEZVOUS [:rfc:`8004`]
    RENDEZVOUS = 1

    #: RELAY_UDP_HIP [:rfc:`5770`]
    RELAY_UDP_HIP = 2

    #: RELAY_UDP_ESP [:rfc:`9028`]
    RELAY_UDP_ESP = 3

    #: CANDIDATE_DISCOVERY [:rfc:`9028`]
    CANDIDATE_DISCOVERY = 4

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Registration':
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
                return Registration(key)
            except ValueError:
                if default == -1:
                    raise
                return Registration(default)
        try:
            return Registration[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return Registration(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'Registration':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'Registration':
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
    def _missing_(cls, value: 'int') -> 'Registration':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 5 <= value <= 200:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 201 <= value <= 255:
            #: Reserved for Private Use [:rfc:`8003`]
            return cls._unregistered_member(value, 'Reserved_for_Private_Use')
        return super()._missing_(value)
