# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Transform Type 3 - Integrity Algorithm Transform IDs
==========================================================

.. module:: pcapkit.const.esp.integrity

This module contains the constant enumeration for **Transform Type 3 - Integrity Algorithm Transform IDs**,
which is automatically generated from :class:`pcapkit.vendor.esp.integrity.Integrity`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Integrity']


class Integrity(IntEnum):
    """[Integrity] Transform Type 3 - Integrity Algorithm Transform IDs"""

    #: NONE [:rfc:`7296`]
    NONE = 0

    #: AUTH_HMAC_MD5_96 [:rfc:`2403`][:rfc:`7296`] (DEPRECATED [:rfc:`8247`])
    AUTH_HMAC_MD5_96 = 1

    #: Alias of :attr:`Integrity.AUTH_HMAC_MD5_96`.
    HMAC_MD5_96 = 1

    #: AUTH_HMAC_SHA1_96 [:rfc:`2404`][:rfc:`7296`]
    AUTH_HMAC_SHA1_96 = 2

    #: Alias of :attr:`Integrity.AUTH_HMAC_SHA1_96`.
    HMAC_SHA1_96 = 2

    #: AUTH_DES_MAC [UNSPECIFIED] (DEPRECATED [:rfc:`8247`])
    AUTH_DES_MAC = 3

    #: Alias of :attr:`Integrity.AUTH_DES_MAC`.
    DES_MAC = 3

    #: AUTH_KPDK_MD5 [UNSPECIFIED] (DEPRECATED [:rfc:`8247`])
    AUTH_KPDK_MD5 = 4

    #: Alias of :attr:`Integrity.AUTH_KPDK_MD5`.
    KPDK_MD5 = 4

    #: AUTH_AES_XCBC_96 [:rfc:`3566`][:rfc:`7296`]
    AUTH_AES_XCBC_96 = 5

    #: Alias of :attr:`Integrity.AUTH_AES_XCBC_96`.
    AES_XCBC_96 = 5

    #: AUTH_HMAC_MD5_128 [:rfc:`4595`] (DEPRECATED [:rfc:`9395`])
    AUTH_HMAC_MD5_128 = 6

    #: Alias of :attr:`Integrity.AUTH_HMAC_MD5_128`.
    HMAC_MD5_128 = 6

    #: AUTH_HMAC_SHA1_160 [:rfc:`4595`] (DEPRECATED [:rfc:`9395`])
    AUTH_HMAC_SHA1_160 = 7

    #: Alias of :attr:`Integrity.AUTH_HMAC_SHA1_160`.
    HMAC_SHA1_160 = 7

    #: AUTH_AES_CMAC_96 [:rfc:`4494`]
    AUTH_AES_CMAC_96 = 8

    #: Alias of :attr:`Integrity.AUTH_AES_CMAC_96`.
    AES_CMAC_96 = 8

    #: AUTH_AES_128_GMAC [:rfc:`4543`]
    AUTH_AES_128_GMAC = 9

    #: Alias of :attr:`Integrity.AUTH_AES_128_GMAC`.
    AES_128_GMAC = 9

    #: AUTH_AES_192_GMAC [:rfc:`4543`]
    AUTH_AES_192_GMAC = 10

    #: Alias of :attr:`Integrity.AUTH_AES_192_GMAC`.
    AES_192_GMAC = 10

    #: AUTH_AES_256_GMAC [:rfc:`4543`]
    AUTH_AES_256_GMAC = 11

    #: Alias of :attr:`Integrity.AUTH_AES_256_GMAC`.
    AES_256_GMAC = 11

    #: AUTH_HMAC_SHA2_256_128 [:rfc:`4868`]
    AUTH_HMAC_SHA2_256_128 = 12

    #: Alias of :attr:`Integrity.AUTH_HMAC_SHA2_256_128`.
    HMAC_SHA2_256_128 = 12

    #: AUTH_HMAC_SHA2_384_192 [:rfc:`4868`]
    AUTH_HMAC_SHA2_384_192 = 13

    #: Alias of :attr:`Integrity.AUTH_HMAC_SHA2_384_192`.
    HMAC_SHA2_384_192 = 13

    #: AUTH_HMAC_SHA2_512_256 [:rfc:`4868`]
    AUTH_HMAC_SHA2_512_256 = 14

    #: Alias of :attr:`Integrity.AUTH_HMAC_SHA2_512_256`.
    HMAC_SHA2_512_256 = 14

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Integrity':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return Integrity(key)
        if key not in Integrity._member_map_:  # pylint: disable=no-member
            return extend_enum(Integrity, key, default)
        return Integrity[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'Integrity':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 15 <= value <= 1023:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 1024 <= value <= 65535:
            #: Reserved for Private Use [:rfc:`7296`]
            return extend_enum(cls, 'Reserved_for_Private_Use_%d' % value, value)
        return super()._missing_(value)
