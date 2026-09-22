# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Transform Type 1 - Encryption Algorithm Transform IDs
===========================================================

.. module:: pcapkit.const.esp.cipher

This module contains the constant enumeration for **Transform Type 1 - Encryption Algorithm Transform IDs**,
which is automatically generated from :class:`pcapkit.vendor.esp.cipher.Cipher`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Cipher']


class Cipher(IntEnum):
    """[Cipher] Transform Type 1 - Encryption Algorithm Transform IDs"""

    #: Reserved [:rfc:`7296`]
    Reserved_0 = 0

    #: ENCR_DES_IV64 (DEPRECATED [:rfc:`9395`])
    ENCR_DES_IV64 = 1

    #: Alias of :attr:`Cipher.ENCR_DES_IV64`.
    DES_IV64 = 1

    #: ENCR_DES [:rfc:`2405`] (DEPRECATED [:rfc:`8247`])
    ENCR_DES = 2

    #: Alias of :attr:`Cipher.ENCR_DES`.
    DES = 2

    #: ENCR_3DES [:rfc:`2451`]
    ENCR_3DES = 3

    #: ENCR_RC5 [:rfc:`2451`] (DEPRECATED [:rfc:`9395`])
    ENCR_RC5 = 4

    #: Alias of :attr:`Cipher.ENCR_RC5`.
    RC5 = 4

    #: ENCR_IDEA [:rfc:`2451`] (DEPRECATED [:rfc:`9395`])
    ENCR_IDEA = 5

    #: Alias of :attr:`Cipher.ENCR_IDEA`.
    IDEA = 5

    #: ENCR_CAST [:rfc:`2451`] (DEPRECATED [:rfc:`9395`])
    ENCR_CAST = 6

    #: Alias of :attr:`Cipher.ENCR_CAST`.
    CAST = 6

    #: ENCR_BLOWFISH [:rfc:`2451`] (DEPRECATED [:rfc:`9395`])
    ENCR_BLOWFISH = 7

    #: Alias of :attr:`Cipher.ENCR_BLOWFISH`.
    BLOWFISH = 7

    #: ENCR_3IDEA (DEPRECATED [:rfc:`9395`])
    ENCR_3IDEA = 8

    #: ENCR_DES_IV32 (DEPRECATED [:rfc:`9395`])
    ENCR_DES_IV32 = 9

    #: Alias of :attr:`Cipher.ENCR_DES_IV32`.
    DES_IV32 = 9

    #: Reserved [:rfc:`7296`]
    Reserved_10 = 10

    #: ENCR_NULL [:rfc:`2410`]
    ENCR_NULL = 11

    #: Alias of :attr:`Cipher.ENCR_NULL`.
    NULL = 11

    #: ENCR_AES_CBC [:rfc:`3602`]
    ENCR_AES_CBC = 12

    #: Alias of :attr:`Cipher.ENCR_AES_CBC`.
    AES_CBC = 12

    #: ENCR_AES_CTR [:rfc:`3686`]
    ENCR_AES_CTR = 13

    #: Alias of :attr:`Cipher.ENCR_AES_CTR`.
    AES_CTR = 13

    #: ENCR_AES_CCM_8 [:rfc:`4309`]
    ENCR_AES_CCM_8 = 14

    #: Alias of :attr:`Cipher.ENCR_AES_CCM_8`.
    AES_CCM_8 = 14

    #: ENCR_AES_CCM_12 [:rfc:`4309`]
    ENCR_AES_CCM_12 = 15

    #: Alias of :attr:`Cipher.ENCR_AES_CCM_12`.
    AES_CCM_12 = 15

    #: ENCR_AES_CCM_16 [:rfc:`4309`]
    ENCR_AES_CCM_16 = 16

    #: Alias of :attr:`Cipher.ENCR_AES_CCM_16`.
    AES_CCM_16 = 16

    #: Unassigned
    Unassigned_17 = 17

    #: ENCR_AES_GCM_8 [:rfc:`4106`][:rfc:`8247`]
    ENCR_AES_GCM_8 = 18

    #: Alias of :attr:`Cipher.ENCR_AES_GCM_8`.
    AES_GCM_8 = 18

    #: ENCR_AES_GCM_12 [:rfc:`4106`][:rfc:`8247`]
    ENCR_AES_GCM_12 = 19

    #: Alias of :attr:`Cipher.ENCR_AES_GCM_12`.
    AES_GCM_12 = 19

    #: ENCR_AES_GCM_16 [:rfc:`4106`][:rfc:`8247`]
    ENCR_AES_GCM_16 = 20

    #: Alias of :attr:`Cipher.ENCR_AES_GCM_16`.
    AES_GCM_16 = 20

    #: ENCR_NULL_AUTH_AES_GMAC [:rfc:`4543`]
    ENCR_NULL_AUTH_AES_GMAC = 21

    #: Alias of :attr:`Cipher.ENCR_NULL_AUTH_AES_GMAC`.
    NULL_AUTH_AES_GMAC = 21

    #: Reserved for IEEE P1619 XTS-AES [Matt Ball]
    Reserved_for_IEEE_P1619_XTS_AES = 22

    #: ENCR_CAMELLIA_CBC [:rfc:`5529`]
    ENCR_CAMELLIA_CBC = 23

    #: Alias of :attr:`Cipher.ENCR_CAMELLIA_CBC`.
    CAMELLIA_CBC = 23

    #: ENCR_CAMELLIA_CTR [:rfc:`5529`]
    ENCR_CAMELLIA_CTR = 24

    #: Alias of :attr:`Cipher.ENCR_CAMELLIA_CTR`.
    CAMELLIA_CTR = 24

    #: ENCR_CAMELLIA_CCM_8 [:rfc:`5529`][:rfc:`8247`]
    ENCR_CAMELLIA_CCM_8 = 25

    #: Alias of :attr:`Cipher.ENCR_CAMELLIA_CCM_8`.
    CAMELLIA_CCM_8 = 25

    #: ENCR_CAMELLIA_CCM_12 [:rfc:`5529`][:rfc:`8247`]
    ENCR_CAMELLIA_CCM_12 = 26

    #: Alias of :attr:`Cipher.ENCR_CAMELLIA_CCM_12`.
    CAMELLIA_CCM_12 = 26

    #: ENCR_CAMELLIA_CCM_16 [:rfc:`5529`][:rfc:`8247`]
    ENCR_CAMELLIA_CCM_16 = 27

    #: Alias of :attr:`Cipher.ENCR_CAMELLIA_CCM_16`.
    CAMELLIA_CCM_16 = 27

    #: ENCR_CHACHA20_POLY1305 [:rfc:`7634`]
    ENCR_CHACHA20_POLY1305 = 28

    #: Alias of :attr:`Cipher.ENCR_CHACHA20_POLY1305`.
    CHACHA20_POLY1305 = 28

    #: ENCR_AES_CCM_8_IIV [:rfc:`8750`]
    ENCR_AES_CCM_8_IIV = 29

    #: Alias of :attr:`Cipher.ENCR_AES_CCM_8_IIV`.
    AES_CCM_8_IIV = 29

    #: ENCR_AES_GCM_16_IIV [:rfc:`8750`]
    ENCR_AES_GCM_16_IIV = 30

    #: Alias of :attr:`Cipher.ENCR_AES_GCM_16_IIV`.
    AES_GCM_16_IIV = 30

    #: ENCR_CHACHA20_POLY1305_IIV [:rfc:`8750`]
    ENCR_CHACHA20_POLY1305_IIV = 31

    #: Alias of :attr:`Cipher.ENCR_CHACHA20_POLY1305_IIV`.
    CHACHA20_POLY1305_IIV = 31

    #: ENCR_KUZNYECHIK_MGM_KTREE [:rfc:`9227`]
    ENCR_KUZNYECHIK_MGM_KTREE = 32

    #: Alias of :attr:`Cipher.ENCR_KUZNYECHIK_MGM_KTREE`.
    KUZNYECHIK_MGM_KTREE = 32

    #: ENCR_MAGMA_MGM_KTREE [:rfc:`9227`]
    ENCR_MAGMA_MGM_KTREE = 33

    #: Alias of :attr:`Cipher.ENCR_MAGMA_MGM_KTREE`.
    MAGMA_MGM_KTREE = 33

    #: ENCR_KUZNYECHIK_MGM_MAC_KTREE [:rfc:`9227`]
    ENCR_KUZNYECHIK_MGM_MAC_KTREE = 34

    #: Alias of :attr:`Cipher.ENCR_KUZNYECHIK_MGM_MAC_KTREE`.
    KUZNYECHIK_MGM_MAC_KTREE = 34

    #: ENCR_MAGMA_MGM_MAC_KTREE [:rfc:`9227`]
    ENCR_MAGMA_MGM_MAC_KTREE = 35

    #: Alias of :attr:`Cipher.ENCR_MAGMA_MGM_MAC_KTREE`.
    MAGMA_MGM_MAC_KTREE = 35

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Cipher':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found. The placeholder ``-1`` stands
                for *no default*, in which case an unresolvable key propagates
                the lookup error instead of falling back.

        :meta private:
        """
        if isinstance(key, int):
            try:
                return Cipher(key)
            except ValueError:
                if default == -1:
                    raise
                return Cipher(default)
        if key not in Cipher._member_map_:  # pylint: disable=no-member
            return extend_enum(Cipher, key, default)
        return Cipher[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'Cipher':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 36 <= value <= 1023:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 1024 <= value <= 65535:
            #: Reserved for Private Use [:rfc:`7296`]
            return extend_enum(cls, 'Reserved_for_Private_Use_%d' % value, value)
        return super()._missing_(value)
