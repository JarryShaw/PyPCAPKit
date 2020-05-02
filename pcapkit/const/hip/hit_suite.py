# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""HIT Suite ID"""

from aenum import IntEnum, extend_enum

__all__ = ['HITSuite']


class HITSuite(IntEnum):
    """[HITSuite] HIT Suite ID"""

    _ignore_ = 'HITSuite _'
    HITSuite = vars()

    #: [:rfc:`7401`]
    HITSuite['RESERVED'] = 0

    #: [:rfc:`7401`]
    HITSuite['RSA_DSA_SHA_256'] = 1

    #: [:rfc:`7401`]
    HITSuite['ECDSA_SHA_384'] = 2

    #: [:rfc:`7401`]
    HITSuite['ECDSA_LOW_SHA_1'] = 3

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
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        return super()._missing_(value)
