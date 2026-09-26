# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HIP Certificate Types
===========================

.. module:: pcapkit.const.hip.certificate

This module contains the constant enumeration for **HIP Certificate Types**,
which is automatically generated from :class:`pcapkit.vendor.hip.certificate.Certificate`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Certificate']


class Certificate(IntEnum):
    """[Certificate] HIP Certificate Types"""

    #: Reserved [:rfc:`8002`]
    Reserved_0 = 0

    #: X.509 v3 [:rfc:`8002`]
    X_509_v3 = 1

    #: Obsoleted [:rfc:`8002`]
    Obsoleted_2 = 2

    #: Hash and URL of X.509 v3 [:rfc:`8002`]
    Hash_and_URL_of_X_509_v3 = 3

    #: Obsoleted [:rfc:`8002`]
    Obsoleted_4 = 4

    #: LDAP URL of X.509 v3 [:rfc:`8002`]
    LDAP_URL_of_X_509_v3 = 5

    #: Obsoleted [:rfc:`8002`]
    Obsoleted_6 = 6

    #: Distinguished Name of X.509 v3 [:rfc:`8002`]
    Distinguished_Name_of_X_509_v3 = 7

    #: Obsoleted [:rfc:`8002`]
    Obsoleted_8 = 8

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Certificate':
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
                return Certificate(key)
            except ValueError:
                if default == -1:
                    raise
                return Certificate(default)
        try:
            return Certificate[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return Certificate(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'Certificate':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'Certificate':
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
    def _missing_(cls, value: 'int') -> 'Certificate':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 9 <= value <= 255:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
