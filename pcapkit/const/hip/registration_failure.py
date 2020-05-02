# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Registration Failure Types"""

from aenum import IntEnum, extend_enum

__all__ = ['RegistrationFailure']


class RegistrationFailure(IntEnum):
    """[RegistrationFailure] Registration Failure Types"""

    _ignore_ = 'RegistrationFailure _'
    RegistrationFailure = vars()

    #: [:rfc:`8003`]
    RegistrationFailure['Registration_Requires_Additional_Credentials'] = 0

    #: [:rfc:`8003`]
    RegistrationFailure['Registration_Type_Unavailable'] = 1

    #: [:rfc:`8003`]
    RegistrationFailure['Insufficient_Resources'] = 2

    #: [:rfc:`8003`]
    RegistrationFailure['Invalid_Certificate'] = 3

    #: [:rfc:`8003`]
    RegistrationFailure['Bad_Certificate'] = 4

    #: [:rfc:`8003`]
    RegistrationFailure['Unsupported_Certificate'] = 5

    #: [:rfc:`8003`]
    RegistrationFailure['Certificate_Expired'] = 6

    #: [:rfc:`8003`]
    RegistrationFailure['Certificate_Other'] = 7

    #: [:rfc:`8003`]
    RegistrationFailure['Unknown_CA'] = 8

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
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 201 <= value <= 255:
            #: [:rfc:`8003`]
            extend_enum(cls, 'Reserved for Private Use [%d]' % value, value)
            return cls(value)
        return super()._missing_(value)
