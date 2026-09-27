# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""CGA SEC
=============

.. module:: pcapkit.const.mh.cga_sec

This module contains the constant enumeration for **CGA SEC**,
which is automatically generated from :class:`pcapkit.vendor.mh.cga_sec.CGASec`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['CGASec']


class CGASec(IntEnum):
    """[CGASec] CGA SEC"""

    #: SHA-1_0hash2bits [:rfc:`4982`]
    SHA_1_0hash2bits = 0b000

    #: SHA-1_16hash2bits [:rfc:`4982`]
    SHA_1_16hash2bits = 0b001

    #: SHA-1_32hash2bits [:rfc:`4982`]
    SHA_1_32hash2bits = 0b010

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'CGASec':
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
                return CGASec(key)
            except ValueError:
                if default == -1:
                    raise
                return CGASec(default)
        try:
            return CGASec[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return CGASec(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'CGASec':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'CGASec':
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
    def _missing_(cls, value: 'int') -> 'CGASec':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0b111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        #: Unspecified in the IANA registry
        return extend_enum(cls, 'Unassigned_%s' % bin(value)[2:], value)
