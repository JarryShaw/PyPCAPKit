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
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return RegistrationFailure(key)
        if key not in RegistrationFailure._member_map_:  # pylint: disable=no-member
            return extend_enum(RegistrationFailure, key, default)
        return RegistrationFailure[key]  # type: ignore[misc]

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
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 201 <= value <= 255:
            #: Reserved for Private Use [:rfc:`8003`]
            return extend_enum(cls, 'Reserved_for_Private_Use_%d' % value, value)
        return super()._missing_(value)
