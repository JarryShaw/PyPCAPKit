# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Binding Revocation Acknowledgement Status Codes
=====================================================

.. module:: pcapkit.const.mh.revocation_status_code

This module contains the constant enumeration for **Binding Revocation Acknowledgement Status Codes**,
which is automatically generated from :class:`pcapkit.vendor.mh.revocation_status_code.RevocationStatusCode`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['RevocationStatusCode']


class RevocationStatusCode(IntEnum):
    """[RevocationStatusCode] Binding Revocation Acknowledgement Status Codes"""

    #: success [:rfc:`5846`]
    success = 0

    #: partial success [:rfc:`5846`]
    partial_success = 1

    #: Binding Does NOT Exist [:rfc:`5846`]
    Binding_Does_NOT_Exist = 128

    #: IPv4 Home Address Option Required [:rfc:`5846`]
    IPv4_Home_Address_Option_Required = 129

    #: Global Revocation NOT Authorized [:rfc:`5846`]
    Global_Revocation_NOT_Authorized = 130

    #: Revoked Mobile Nodes Identity Required [:rfc:`5846`]
    Revoked_Mobile_Nodes_Identity_Required = 131

    #: Revocation Failed - MN is Attached [:rfc:`5846`]
    Revocation_Failed_MN_is_Attached = 132

    #: Revocation Trigger NOT Supported [:rfc:`5846`]
    Revocation_Trigger_NOT_Supported = 133

    #: Revocation Function NOT Supported [:rfc:`5846`]
    Revocation_Function_NOT_Supported = 134

    #: Proxy Binding Revocation NOT Supported [:rfc:`5846`]
    Proxy_Binding_Revocation_NOT_Supported = 135

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'RevocationStatusCode':
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
                return RevocationStatusCode(key)
            except ValueError:
                if default == -1:
                    raise
                return RevocationStatusCode(default)
        try:
            return RevocationStatusCode[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return RevocationStatusCode(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'RevocationStatusCode':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'RevocationStatusCode':
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
    def _missing_(cls, value: 'int') -> 'RevocationStatusCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 2 <= value <= 127:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 136 <= value <= 255:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
