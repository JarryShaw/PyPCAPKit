# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class HI_ALG(IntEnum):
    """Enumeration class for HI_ALG."""
    _ignore_ = 'HI_ALG _'
    HI_ALG = vars()

    # HI Algorithm
    HI_ALG['RESERVED'] = 0                                                      # [RFC 7401]
    HI_ALG['NULL-ENCRYPT'] = 1                                                  # [RFC 2410]
    HI_ALG['Unassigned [2]'] = 2
    HI_ALG['DSA'] = 3                                                           # [RFC 7401]
    HI_ALG['Unassigned [4]'] = 4
    HI_ALG['RSA'] = 5                                                           # [RFC 7401]
    HI_ALG['Unassigned [6]'] = 6
    HI_ALG['ECDSA'] = 7                                                         # [RFC 7401]
    HI_ALG['Unassigned [8]'] = 8
    HI_ALG['ECDSA_LOW'] = 9                                                     # [RFC 7401]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return HI_ALG(key)
        if key not in HI_ALG._member_map_:
            extend_enum(HI_ALG, key, default)
        return HI_ALG[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 10 <= value <= 65535:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
