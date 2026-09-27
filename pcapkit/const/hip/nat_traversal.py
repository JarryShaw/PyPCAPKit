# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HIP NAT Traversal Modes
=============================

.. module:: pcapkit.const.hip.nat_traversal

This module contains the constant enumeration for **HIP NAT Traversal Modes**,
which is automatically generated from :class:`pcapkit.vendor.hip.nat_traversal.NATTraversal`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['NATTraversal']


class NATTraversal(IntEnum):
    """[NATTraversal] HIP NAT Traversal Modes"""

    #: Reserved [:rfc:`5770`]
    Reserved_0 = 0

    #: UDP-ENCAPSULATION [:rfc:`5770`]
    UDP_ENCAPSULATION = 1

    #: ICE-STUN-UDP [:rfc:`5770`]
    ICE_STUN_UDP = 2

    #: ICE-HIP-UDP [:rfc:`9028`]
    ICE_HIP_UDP = 3

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'NATTraversal':
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
                return NATTraversal(key)
            except ValueError:
                if default == -1:
                    raise
                return NATTraversal(default)
        try:
            return NATTraversal[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return NATTraversal(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'NATTraversal':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'NATTraversal':
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
    def _missing_(cls, value: 'int') -> 'NATTraversal':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 4 <= value <= 65535:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
