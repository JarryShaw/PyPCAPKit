# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Suite IDs
===============

.. module:: pcapkit.const.hip.suite

This module contains the constant enumeration for **Suite IDs**,
which is automatically generated from :class:`pcapkit.vendor.hip.suite.Suite`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Suite']


class Suite(IntEnum):
    """[Suite] Suite IDs"""

    #: Reserved [:rfc:`5201`]
    Reserved_0 = 0

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
    def get(key: 'int | str', default: 'int' = -1) -> 'Suite':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return Suite(key)
        if key not in Suite._member_map_:  # pylint: disable=no-member
            return extend_enum(Suite, key, default)
        return Suite[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'Suite':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 7 <= value <= 65535:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
