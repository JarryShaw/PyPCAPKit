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
    RegistrationFailure['Registration requires additional credentials'] = 0

    #: [:rfc:`8003`]
    RegistrationFailure['Registration type unavailable'] = 1

    #: [:rfc:`8003`]
    RegistrationFailure['Insufficient resources'] = 2

    #: [:rfc:`8003`]
    RegistrationFailure['Invalid certificate'] = 3

    #: [:rfc:`8003`]
    RegistrationFailure['Bad certificate'] = 4

    #: [:rfc:`8003`]
    RegistrationFailure['Unsupported certificate'] = 5

    #: [:rfc:`8003`]
    RegistrationFailure['Certificate expired'] = 6

    #: [:rfc:`8003`]
    RegistrationFailure['Certificate other'] = 7

    #: [:rfc:`8003`]
    RegistrationFailure['Unknown CA'] = 8

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
