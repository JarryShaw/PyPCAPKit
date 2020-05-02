# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Authentication Types"""

from aenum import IntEnum, extend_enum

__all__ = ['Authentication']


class Authentication(IntEnum):
    """[Authentication] Authentication Types"""

    _ignore_ = 'Authentication _'
    Authentication = vars()

    #: [:rfc:`1583`]
    Authentication['No_Authentication'] = 0

    #: [:rfc:`1583`]
    Authentication['Simple_Password_Authentication'] = 1

    #: [:rfc:`2328`][:rfc:`5709`]
    Authentication['Cryptographic_Authentication'] = 2

    #: [:rfc:`7474`]
    Authentication['Cryptographic_Authentication_With_Extended_Sequence_Numbers'] = 3

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Authentication(key)
        if key not in Authentication._member_map_:  # pylint: disable=no-member
            extend_enum(Authentication, key, default)
        return Authentication[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 4 <= value <= 255:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 256 <= value <= 65535:
            #: [:rfc:`6549`]
            extend_enum(cls, 'Deprecated [%d]' % value, value)
            return cls(value)
        return super()._missing_(value)
