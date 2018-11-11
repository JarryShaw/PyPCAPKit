# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class HIT_Suite(IntEnum):
    """Enumeration class for HIT_Suite."""
    _ignore_ = 'HIT_Suite _'
    HIT_Suite = vars()

    # HIT Suite ID
    HIT_Suite['RESERVED'] = 0                                                   # [RFC 7401]
    HIT_Suite['RSA,DSA/SHA-256'] = 1                                            # [RFC 7401]
    HIT_Suite['ECDSA/SHA-384'] = 2                                              # [RFC 7401]
    HIT_Suite['ECDSA_LOW/SHA-1'] = 3                                            # [RFC 7401]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return HIT_Suite(key)
        if key not in HIT_Suite._member_map_:
            extend_enum(HIT_Suite, key, default)
        return HIT_Suite[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 15):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 4 <= value <= 15:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
