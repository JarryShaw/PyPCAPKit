# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Suite IDs"""

from aenum import IntEnum, extend_enum

__all__ = ['Suite']


class Suite(IntEnum):
    """[Suite] Suite IDs"""

    _ignore_ = 'Suite _'
    Suite = vars()

    #: [:rfc:`5201`]
    Suite['Reserved'] = 0

    #: [:rfc:`5201`]
    Suite['AES_CBC_With_HMAC_SHA1'] = 1

    #: [:rfc:`5201`]
    Suite['3DES_CBC_With_HMAC_SHA1'] = 2

    #: [:rfc:`5201`]
    Suite['3DES_CBC_With_HMAC_MD5'] = 3

    #: [:rfc:`5201`]
    Suite['BLOWFISH_CBC_With_HMAC_SHA1'] = 4

    #: [:rfc:`5201`]
    Suite['NULL_ENCRYPT_With_HMAC_SHA1'] = 5

    #: [:rfc:`5201`]
    Suite['NULL_ENCRYPT_With_HMAC_MD5'] = 6

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Suite(key)
        if key not in Suite._member_map_:  # pylint: disable=no-member
            extend_enum(Suite, key, default)
        return Suite[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 7 <= value <= 65535:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        return super()._missing_(value)
