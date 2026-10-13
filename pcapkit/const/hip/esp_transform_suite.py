# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""ESP Transform Suite IDs
=============================

.. module:: pcapkit.const.hip.esp_transform_suite

This module contains the constant enumeration for **ESP Transform Suite IDs**,
which is automatically generated from :class:`pcapkit.vendor.hip.esp_transform_suite.ESPTransformSuite`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['ESPTransformSuite']


class ESPTransformSuite(EnumRegistry, IntEnum):
    """[ESPTransformSuite] ESP Transform Suite IDs"""

    #: RESERVED [RFC 7402]
    RESERVED_0 = 0

    #: AES-128-CBC with HMAC-SHA1 [RFC 3602][; ][RFC 2404]
    AES_128_CBC_with_HMAC_SHA1 = 1

    #: DEPRECATED [RFC 7402]
    DEPRECATED_2 = 2

    #: DEPRECATED [RFC 7402]
    DEPRECATED_3 = 3

    #: DEPRECATED [RFC 7402]
    DEPRECATED_4 = 4

    #: DEPRECATED [RFC 7402]
    DEPRECATED_5 = 5

    #: DEPRECATED [RFC 7402]
    DEPRECATED_6 = 6

    #: NULL with HMAC-SHA-256 [RFC 2410][; ][RFC 4868]
    NULL_with_HMAC_SHA_256 = 7

    #: AES-128-CBC with HMAC-SHA-256 [RFC 3602][; ][RFC 4868]
    AES_128_CBC_with_HMAC_SHA_256 = 8

    #: AES-256-CBC with HMAC-SHA-256 [RFC 3602][; ][RFC 4868]
    AES_256_CBC_with_HMAC_SHA_256 = 9

    #: AES-CCM-8 [RFC 4309]
    AES_CCM_8 = 10

    #: AES-CCM-16 [RFC 4309]
    AES_CCM_16 = 11

    #: AES-GCM with an 8 octet ICV [RFC 4106]
    AES_GCM_with_an_8_octet_ICV = 12

    #: AES-GCM with a 16 octet ICV [RFC 4106]
    AES_GCM_with_a_16_octet_ICV = 13

    #: AES-CMAC-96 [RFC 4493][; ][RFC 4494]
    AES_CMAC_96 = 14

    #: AES-GMAC [RFC 4543]
    AES_GMAC = 15

    @classmethod
    def _missing_(cls, value: 'int') -> 'ESPTransformSuite':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 16 <= value <= 65535:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
