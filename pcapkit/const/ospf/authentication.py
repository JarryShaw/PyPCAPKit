# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Authentication Types"""

from aenum import IntEnum, extend_enum

__all__ = ['Authentication']


class Authentication(IntEnum):
    """[Authentication] Authentication Types"""

    #: No Authentication [:rfc:`1583`]
    No_Authentication = 0

    #: Simple Password Authentication [:rfc:`1583`]
    Simple_Password_Authentication = 1

    #: Cryptographic authentication [:rfc:`2328`][:rfc:`5709`]
    Cryptographic_authentication = 2

    #: Cryptographic Authentication with Extended Sequence Numbers [:rfc:`7474`]
    Cryptographic_Authentication_with_Extended_Sequence_Numbers = 3

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
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 256 <= value <= 65535:
            #: Deprecated [:rfc:`6549`]
            extend_enum(cls, 'Deprecated_%d' % value, value)
            return cls(value)
        return super()._missing_(value)
