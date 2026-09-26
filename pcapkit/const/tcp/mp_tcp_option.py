# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Multipath TCP options
===========================

.. module:: pcapkit.const.tcp.mp_tcp_option

This module contains the constant enumeration for **Multipath TCP options**,
which is automatically generated from :class:`pcapkit.vendor.tcp.mp_tcp_option.MPTCPOption`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['MPTCPOption']


class MPTCPOption(IntEnum):
    """[MPTCPOption] Multipath TCP options [:rfc:`6824`]"""

    #: Multipath Capable [:rfc:`8684#3.1`]
    MP_CAPABLE = 0x0

    #: Join Connection [:rfc:`8684#3.2`]
    MP_JOIN = 0x1

    #: Data Sequence Signal (Data ACK and Data Sequence Mapping) [:rfc:`8684#3.3`]
    DSS = 0x2

    #: Add Address [:rfc:`8684#3.4.1`]
    ADD_ADDR = 0x3

    #: Remove Address [:rfc:`8684#3.4.2`]
    REMOVE_ADDR = 0x4

    #: Change Subflow Priority [:rfc:`8684#3.3.8`]
    MP_PRIO = 0x5

    #: Fallback [:rfc:`8684#3.7`]
    MP_FAIL = 0x6

    #: Fast Close [:rfc:`8684#3.5`]
    MP_FASTCLOSE = 0x7

    #: Subflow Reset [:rfc:`8684#3.6`]
    MP_TCPRST = 0x8

    #: [:rfc:`8684`]
    Reserved_for_Private_Use = 0xf

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'MPTCPOption':
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
                return MPTCPOption(key)
            except ValueError:
                if default == -1:
                    raise
                return MPTCPOption(default)
        try:
            return MPTCPOption[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return MPTCPOption(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'MPTCPOption':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'MPTCPOption':
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
    def _missing_(cls, value: 'int') -> 'MPTCPOption':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x9 <= value <= 0xe:
            #:
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
