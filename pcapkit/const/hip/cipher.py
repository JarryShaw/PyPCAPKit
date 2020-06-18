# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Cipher IDs"""

from aenum import IntEnum, extend_enum

__all__ = ['Cipher']


class Cipher(IntEnum):
    """[Cipher] Cipher IDs"""

    #: RESERVED [:rfc:`7401`]
    RESERVED_0 = 0

    #: NULL-ENCRYPT [:rfc:`7401`]
    NULL_ENCRYPT = 1

    #: AES-128-CBC [:rfc:`7401`]
    AES_128_CBC = 2

    #: RESERVED [:rfc:`7401`]
    RESERVED_3 = 3

    #: AES-256-CBC [:rfc:`7401`]
    AES_256_CBC = 4

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Cipher(key)
        if key not in Cipher._member_map_:  # pylint: disable=no-member
            extend_enum(Cipher, key, default)
        return Cipher[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 5 <= value <= 65535:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        return super()._missing_(value)
