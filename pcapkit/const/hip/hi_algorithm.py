# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class HI_Algorithm(IntEnum):
    """Enumeration class for HI_Algorithm."""
    _ignore_ = 'HI_Algorithm _'
    HI_Algorithm = vars()

    # HI Algorithm
    HI_Algorithm['RESERVED'] = 0                                                # [RFC 7401]
    HI_Algorithm['NULL-ENCRYPT'] = 1                                            # [RFC 2410]
    HI_Algorithm['Unassigned [2]'] = 2
    HI_Algorithm['DSA'] = 3                                                     # [RFC 7401]
    HI_Algorithm['Unassigned [4]'] = 4
    HI_Algorithm['RSA'] = 5                                                     # [RFC 7401]
    HI_Algorithm['Unassigned [6]'] = 6
    HI_Algorithm['ECDSA'] = 7                                                   # [RFC 7401]
    HI_Algorithm['Unassigned [8]'] = 8
    HI_Algorithm['ECDSA_LOW'] = 9                                               # [RFC 7401]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return HI_Algorithm(key)
        if key not in HI_Algorithm._member_map_:
            extend_enum(HI_Algorithm, key, default)
        return HI_Algorithm[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 10 <= value <= 65535:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
