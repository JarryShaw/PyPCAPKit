# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""HI Algorithm"""

from aenum import IntEnum, extend_enum

__all__ = ['HIAlgorithm']


class HIAlgorithm(IntEnum):
    """[HIAlgorithm] HI Algorithm"""

    #: RESERVED [:rfc:`7401`]
    RESERVED = 0

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
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        return super()._missing_(value)
