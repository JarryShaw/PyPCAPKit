# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HI Algorithm
==================

.. module:: pcapkit.const.hip.hi_algorithm

This module contains the constant enumeration for **HI Algorithm**,
which is automatically generated from :class:`pcapkit.vendor.hip.hi_algorithm.HIAlgorithm`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['HIAlgorithm']


class HIAlgorithm(EnumRegistry, IntEnum):
    """[HIAlgorithm] HI Algorithm"""

    #: RESERVED [RFC 7401]
    RESERVED_0 = 0

    #: NULL-ENCRYPT [RFC 2410]
    NULL_ENCRYPT = 1

    #: Unassigned
    Unassigned_2 = 2

    #: DSA [RFC 7401]
    DSA = 3

    #: Unassigned
    Unassigned_4 = 4

    #: RSA [RFC 7401]
    RSA = 5

    #: Unassigned
    Unassigned_6 = 6

    #: ECDSA [RFC 7401]
    ECDSA = 7

    #: Unassigned
    Unassigned_8 = 8

    #: ECDSA_LOW [RFC 7401]
    ECDSA_LOW = 9

    #: EdDSA [RFC 8032]
    EdDSA = 13

    @classmethod
    def _missing_(cls, value: 'int') -> 'HIAlgorithm':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 10 <= value <= 12:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 14 <= value <= 65535:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
