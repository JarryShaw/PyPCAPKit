# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""HIT Suite ID"""

from aenum import IntEnum, extend_enum

__all__ = ['HITSuite']


class HITSuite(IntEnum):
    """[HITSuite] HIT Suite ID"""

    #: RESERVED [:rfc:`7401`]
    RESERVED = 0

    #: RSA,DSA/SHA-256 [:rfc:`7401`]
    RSA_DSA_SHA_256 = 1

    #: ECDSA/SHA-384 [:rfc:`7401`]
    ECDSA_SHA_384 = 2

    #: ECDSA_LOW/SHA-1 [:rfc:`7401`]
    ECDSA_LOW_SHA_1 = 3

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return HITSuite(key)
        if key not in HITSuite._member_map_:  # pylint: disable=no-member
            extend_enum(HITSuite, key, default)
        return HITSuite[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 15):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 4 <= value <= 15:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        return super()._missing_(value)
