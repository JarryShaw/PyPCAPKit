# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HI Algorithm
==================

.. module:: pcapkit.const.hip.hi_algorithm

This module contains the constant enumeration for **HI Algorithm**,
which is automatically generated from :class:`pcapkit.vendor.hip.hi_algorithm.HIAlgorithm`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['HIAlgorithm']


class HIAlgorithm(IntEnum):
    """[HIAlgorithm] HI Algorithm"""

    #: RESERVED [:rfc:`7401`]
    RESERVED_0 = 0

    #: NULL-ENCRYPT [:rfc:`2410`]
    NULL_ENCRYPT = 1

    #: Unassigned
    Unassigned_2 = 2

    #: DSA [:rfc:`7401`]
    DSA = 3

    #: Unassigned
    Unassigned_4 = 4

    #: RSA [:rfc:`7401`]
    RSA = 5

    #: Unassigned
    Unassigned_6 = 6

    #: ECDSA [:rfc:`7401`]
    ECDSA = 7

    #: Unassigned
    Unassigned_8 = 8

    #: ECDSA_LOW [:rfc:`7401`]
    ECDSA_LOW = 9

    #: EdDSA [:rfc:`8032`]
    EdDSA = 13

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'HIAlgorithm':
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
                return HIAlgorithm(key)
            except ValueError:
                if default == -1:
                    raise
                return HIAlgorithm(default)
        try:
            return HIAlgorithm[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return HIAlgorithm(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'HIAlgorithm':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'HIAlgorithm':
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
    def _missing_(cls, value: 'int') -> 'HIAlgorithm':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 10 <= value <= 12:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 14 <= value <= 65535:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
