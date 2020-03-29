# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Cipher IDs"""

from aenum import IntEnum, extend_enum

__all__ = ['Cipher']


class Cipher(IntEnum):
    """[Cipher] Cipher IDs"""

    _ignore_ = 'Cipher _'
    Cipher = vars()

    #: [:rfc:`7401`]
    Cipher['RESERVED [0]'] = 0

    #: [:rfc:`7401`]
    Cipher['NULL-ENCRYPT'] = 1

    #: [:rfc:`7401`]
    Cipher['AES-128-CBC'] = 2

    #: [:rfc:`7401`]
    Cipher['RESERVED [3]'] = 3

    #: [:rfc:`7401`]
    Cipher['AES-256-CBC'] = 4

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
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        return super()._missing_(value)
