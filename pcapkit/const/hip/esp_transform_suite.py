# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""ESP Transform Suite IDs"""

from aenum import IntEnum, extend_enum

__all__ = ['ESPTransformSuite']


class ESPTransformSuite(IntEnum):
    """[ESPTransformSuite] ESP Transform Suite IDs"""

    _ignore_ = 'ESPTransformSuite _'
    ESPTransformSuite = vars()

    #: [:rfc:`7402`]
    ESPTransformSuite['RESERVED'] = 0

    #: [:rfc:`3602`][:rfc:`2404`]
    ESPTransformSuite['AES_128_CBC_With_HMAC_SHA1'] = 1

    #: [:rfc:`7402`]
    ESPTransformSuite['DEPRECATED_2'] = 2

    #: [:rfc:`7402`]
    ESPTransformSuite['DEPRECATED_3'] = 3

    #: [:rfc:`7402`]
    ESPTransformSuite['DEPRECATED_4'] = 4

    #: [:rfc:`7402`]
    ESPTransformSuite['DEPRECATED_5'] = 5

    #: [:rfc:`7402`]
    ESPTransformSuite['DEPRECATED_6'] = 6

    #: [:rfc:`2410`][:rfc:`4868`]
    ESPTransformSuite['NULL_With_HMAC_SHA_256'] = 7

    #: [:rfc:`3602`][:rfc:`4868`]
    ESPTransformSuite['AES_128_CBC_With_HMAC_SHA_256'] = 8

    #: [:rfc:`3602`][:rfc:`4868`]
    ESPTransformSuite['AES_256_CBC_With_HMAC_SHA_256'] = 9

    #: [:rfc:`4309`]
    ESPTransformSuite['AES_CCM_8'] = 10

    #: [:rfc:`4309`]
    ESPTransformSuite['AES_CCM_16'] = 11

    #: [:rfc:`4106`]
    ESPTransformSuite['AES_GCM_With_An_8_Octet_ICV'] = 12

    #: [:rfc:`4106`]
    ESPTransformSuite['AES_GCM_With_A_16_Octet_ICV'] = 13

    #: [:rfc:`4493`][:rfc:`4494`]
    ESPTransformSuite['AES_CMAC_96'] = 14

    #: [:rfc:`4543`]
    ESPTransformSuite['AES_GMAC'] = 15

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
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        return super()._missing_(value)
