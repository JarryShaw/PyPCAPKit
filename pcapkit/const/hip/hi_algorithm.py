# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HI Algorithm
==================

.. module:: pcapkit.const.hip.hi_algorithm

This module contains the constant enumeration for **HI Algorithm**,
which is automatically generated from :class:`pcapkit.vendor.hip.hi_algorithm.HIAlgorithm`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['HIAlgorithm']


class HIAlgorithm(IntEnum):
    """[HIAlgorithm] HI Algorithm"""

    #: RESERVED [:rfc:`7401`]
    RESERVED_0 = 0

    #: NULL-ENCRYPT [:rfc:`2410`]
    NULL_ENCRYPT = 1

    #: Unassigned
    Unassigned_2 = 2

    #: DSA [:rfc:`7401`]
    DSA = 3

    #: Unassigned
    Unassigned_4 = 4

    #: RSA [:rfc:`7401`]
    RSA = 5

    #: Unassigned
    Unassigned_6 = 6

    #: ECDSA [:rfc:`7401`]
    ECDSA = 7

    #: Unassigned
    Unassigned_8 = 8

    #: ECDSA_LOW [:rfc:`7401`]
    ECDSA_LOW = 9

    #: EdDSA [:rfc:`8032`]
    EdDSA = 13

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'HIAlgorithm':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return HIAlgorithm(key)
        if key not in HIAlgorithm._member_map_:  # pylint: disable=no-member
            return extend_enum(HIAlgorithm, key, default)
        return HIAlgorithm[key]  # type: ignore[misc]

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
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 14 <= value <= 65535:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
