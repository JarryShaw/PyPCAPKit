# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""ESP Transform Suite IDs"""

from aenum import IntEnum, extend_enum

__all__ = ['ESPTransformSuite']


class ESPTransformSuite(IntEnum):
    """[ESPTransformSuite] ESP Transform Suite IDs"""

    #: RESERVED [:rfc:`7402`]
    RESERVED = 0

    #: AES-128-CBC with HMAC-SHA1 [:rfc:`3602`][:rfc:`2404`]
    AES_128_CBC_with_HMAC_SHA1 = 1

    #: DEPRECATED [:rfc:`7402`]
    DEPRECATED_2 = 2

    #: DEPRECATED [:rfc:`7402`]
    DEPRECATED_3 = 3

    #: DEPRECATED [:rfc:`7402`]
    DEPRECATED_4 = 4

    #: DEPRECATED [:rfc:`7402`]
    DEPRECATED_5 = 5

    #: DEPRECATED [:rfc:`7402`]
    DEPRECATED_6 = 6

    #: NULL with HMAC-SHA-256 [:rfc:`2410`][:rfc:`4868`]
    NULL_with_HMAC_SHA_256 = 7

    #: AES-128-CBC with HMAC-SHA-256 [:rfc:`3602`][:rfc:`4868`]
    AES_128_CBC_with_HMAC_SHA_256 = 8

    #: AES-256-CBC with HMAC-SHA-256 [:rfc:`3602`][:rfc:`4868`]
    AES_256_CBC_with_HMAC_SHA_256 = 9

    #: AES-CCM-8 [:rfc:`4309`]
    AES_CCM_8 = 10

    #: AES-CCM-16 [:rfc:`4309`]
    AES_CCM_16 = 11

    #: AES-GCM with an 8 octet ICV [:rfc:`4106`]
    AES_GCM_with_an_8_octet_ICV = 12

    #: AES-GCM with a 16 octet ICV [:rfc:`4106`]
    AES_GCM_with_a_16_octet_ICV = 13

    #: AES-CMAC-96 [:rfc:`4493`][:rfc:`4494`]
    AES_CMAC_96 = 14

    #: AES-GMAC [:rfc:`4543`]
    AES_GMAC = 15

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ESPTransformSuite(key)
        if key not in ESPTransformSuite._member_map_:  # pylint: disable=no-member
            extend_enum(ESPTransformSuite, key, default)
        return ESPTransformSuite[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 16 <= value <= 65535:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        return super()._missing_(value)
