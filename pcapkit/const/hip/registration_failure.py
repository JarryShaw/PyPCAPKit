# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Registration Failure Types"""

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

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return RegistrationFailure(key)
        if key not in RegistrationFailure._member_map_:  # pylint: disable=no-member
            extend_enum(RegistrationFailure, key, default)
        return RegistrationFailure[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 9 <= value <= 200:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 201 <= value <= 255:
            #: Reserved for Private Use [:rfc:`8003`]
            extend_enum(cls, 'Reserved_for_Private_Use_%d' % value, value)
            return cls(value)
        return super()._missing_(value)
