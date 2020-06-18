# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Suite IDs"""

from aenum import IntEnum, extend_enum

__all__ = ['Suite']


class Suite(IntEnum):
    """[Suite] Suite IDs"""

    #: Reserved [:rfc:`5201`]
    Reserved = 0

    #: AES-CBC with HMAC-SHA1 [:rfc:`5201`]
    AES_CBC_with_HMAC_SHA1 = 1

    #: 3DES-CBC with HMAC-SHA1 [:rfc:`5201`]
    Suite_3DES_CBC_with_HMAC_SHA1 = 2

    #: 3DES-CBC with HMAC-MD5 [:rfc:`5201`]
    Suite_3DES_CBC_with_HMAC_MD5 = 3

    #: BLOWFISH-CBC with HMAC-SHA1 [:rfc:`5201`]
    BLOWFISH_CBC_with_HMAC_SHA1 = 4

    #: NULL-ENCRYPT with HMAC-SHA1 [:rfc:`5201`]
    NULL_ENCRYPT_with_HMAC_SHA1 = 5

    #: NULL-ENCRYPT with HMAC-MD5 [:rfc:`5201`]
    NULL_ENCRYPT_with_HMAC_MD5 = 6

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
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        return super()._missing_(value)
