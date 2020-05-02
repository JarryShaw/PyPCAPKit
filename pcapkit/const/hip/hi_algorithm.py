# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""HI Algorithm"""

from aenum import IntEnum, extend_enum

__all__ = ['HIAlgorithm']


class HIAlgorithm(IntEnum):
    """[HIAlgorithm] HI Algorithm"""

    _ignore_ = 'HIAlgorithm _'
    HIAlgorithm = vars()

    #: [:rfc:`7401`]
    HIAlgorithm['RESERVED'] = 0

    #: [:rfc:`2410`]
    HIAlgorithm['NULL_ENCRYPT'] = 1

    HIAlgorithm['Unassigned_2'] = 2

    #: [:rfc:`7401`]
    HIAlgorithm['DSA'] = 3

    HIAlgorithm['Unassigned_4'] = 4

    #: [:rfc:`7401`]
    HIAlgorithm['RSA'] = 5

    HIAlgorithm['Unassigned_6'] = 6

    #: [:rfc:`7401`]
    HIAlgorithm['ECDSA'] = 7

    HIAlgorithm['Unassigned_8'] = 8

    #: [:rfc:`7401`]
    HIAlgorithm['ECDSA_LOW'] = 9

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return HIAlgorithm(key)
        if key not in HIAlgorithm._member_map_:  # pylint: disable=no-member
            extend_enum(HIAlgorithm, key, default)
        return HIAlgorithm[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 10 <= value <= 65535:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        return super()._missing_(value)
