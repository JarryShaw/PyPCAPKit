# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class RegistrationFailure(IntEnum):
    """Enumeration class for RegistrationFailure."""
    _ignore_ = 'RegistrationFailure _'
    RegistrationFailure = vars()

    # Registration Failure Types
    RegistrationFailure['Registration requires additional credentials'] = 0     # [RFC 8003]
    RegistrationFailure['Registration type unavailable'] = 1                    # [RFC 8003]
    RegistrationFailure['Insufficient resources'] = 2                           # [RFC 8003]
    RegistrationFailure['Invalid certificate'] = 3                              # [RFC 8003]
    RegistrationFailure['Bad certificate'] = 4                                  # [RFC 8003]
    RegistrationFailure['Unsupported certificate'] = 5                          # [RFC 8003]
    RegistrationFailure['Certificate expired'] = 6                              # [RFC 8003]
    RegistrationFailure['Certificate other'] = 7                                # [RFC 8003]
    RegistrationFailure['Unknown CA'] = 8                                       # [RFC 8003]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return RegistrationFailure(key)
        if key not in RegistrationFailure._member_map_:
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
            # [RFC 8003]
            extend_enum(cls, 'Reserved for Private Use [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
