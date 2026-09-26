# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""CGA Extension Type Values
===============================

.. module:: pcapkit.const.mh.cga_extension

This module contains the constant enumeration for **CGA Extension Type Values**,
which is automatically generated from :class:`pcapkit.vendor.mh.cga_extension.CGAExtension`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['CGAExtension']


class CGAExtension(IntEnum):
    """[CGAExtension] CGA Extension Type Values"""

    #: Multi-Prefix [:rfc:`5535`]
    Multi_Prefix = 0x0012

    #: Exp_FFFD (experimental) [:rfc:`4581`]
    Exp_FFFD = 0xFFFD

    #: Exp_FFFE (experimental) [:rfc:`4581`]
    Exp_FFFE = 0xFFFE

    #: Exp_FFFF (experimental) [:rfc:`4581`]
    Exp_FFFF = 0xFFFF

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'CGAExtension':
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
                return CGAExtension(key)
            except ValueError:
                if default == -1:
                    raise
                return CGAExtension(default)
        try:
            return CGAExtension[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return CGAExtension(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'CGAExtension':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'CGAExtension':
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
    def _missing_(cls, value: 'int') -> 'CGAExtension':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0000 <= value <= 0x0011:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%04x' % value, value)
        if 0x0013 <= value <= 0xFFFC:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%04x' % value, value)
        #: Unspecified in the IANA registry
        return extend_enum(cls, 'Unassigned_%04x' % value, value)
