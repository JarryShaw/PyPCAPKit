# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""OSPF Packet Types
=======================

.. module:: pcapkit.const.ospf.packet

This module contains the constant enumeration for **OSPF Packet Types**,
which is automatically generated from :class:`pcapkit.vendor.ospf.packet.Packet`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Packet']


class Packet(IntEnum):
    """[Packet] OSPF Packet Types"""

    #: Reserved
    Reserved_0 = 0

    #: Hello [:rfc:`2328`]
    Hello = 1

    #: Database Description [:rfc:`2328`]
    Database_Description = 2

    #: Link State Request [:rfc:`2328`]
    Link_State_Request = 3

    #: Link State Update [:rfc:`2328`]
    Link_State_Update = 4

    #: Link State Ack [:rfc:`2328`]
    Link_State_Ack = 5

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Packet':
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
                return Packet(key)
            except ValueError:
                if default == -1:
                    raise
                return Packet(default)
        try:
            return Packet[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return Packet(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'Packet':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'Packet':
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
    def _missing_(cls, value: 'int') -> 'Packet':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 6 <= value <= 127:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 128 <= value <= 255:
            #: Reserved
            return cls._unregistered_member(value, 'Reserved')
        return super()._missing_(value)
