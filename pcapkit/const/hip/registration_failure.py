# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Registration Failure Types
================================

.. module:: pcapkit.const.hip.registration_failure

This module contains the constant enumeration for **Registration Failure Types**,
which is automatically generated from :class:`pcapkit.vendor.hip.registration_failure.RegistrationFailure`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['RegistrationFailure']


class RegistrationFailure(IntEnum):
    """[RegistrationFailure] Registration Failure Types"""

    #: Registration requires additional credentials [:rfc:`8003`]
    Registration_requires_additional_credentials = 0

    #: Registration type unavailable [:rfc:`8003`]
    Registration_type_unavailable = 1

    #: Insufficient resources [:rfc:`8003`]
    Insufficient_resources = 2

    #: Invalid certificate [:rfc:`8003`]
    Invalid_certificate = 3

    #: Bad certificate [:rfc:`8003`]
    Bad_certificate = 4

    #: Unsupported certificate [:rfc:`8003`]
    Unsupported_certificate = 5

    #: Certificate expired [:rfc:`8003`]
    Certificate_expired = 6

    #: Certificate other [:rfc:`8003`]
    Certificate_other = 7

    #: Unknown CA [:rfc:`8003`]
    Unknown_CA = 8

    #: Simultaneous Rendezvous and Control Relay Service usage prohibited
    #: [:rfc:`9028`]
    Simultaneous_Rendezvous_and_Control_Relay_Service_usage_prohibited = 9

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'RegistrationFailure':
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
                return RegistrationFailure(key)
            except ValueError:
                if default == -1:
                    raise
                return RegistrationFailure(default)
        try:
            return RegistrationFailure[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return RegistrationFailure(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'RegistrationFailure':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'RegistrationFailure':
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
    def _missing_(cls, value: 'int') -> 'RegistrationFailure':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 10 <= value <= 200:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 201 <= value <= 255:
            #: Reserved for Private Use [:rfc:`8003`]
            return cls._unregistered_member(value, 'Reserved_for_Private_Use')
        return super()._missing_(value)
