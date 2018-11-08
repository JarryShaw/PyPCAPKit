# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class HIT_SuiteID(IntEnum):
    """Enumeration class for HIT_SuiteID."""
    _ignore_ = 'HIT_SuiteID _'
    HIT_SuiteID = vars()

    # HIT Suite ID
    HIT_SuiteID['RESERVED'] = 0                                                 # [RFC 7401]
    HIT_SuiteID['RSA,DSA/SHA-256'] = 1                                          # [RFC 7401]
    HIT_SuiteID['ECDSA/SHA-384'] = 2                                            # [RFC 7401]
    HIT_SuiteID['ECDSA_LOW/SHA-1'] = 3                                          # [RFC 7401]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return HIT_SuiteID(key)
        if key not in HIT_SuiteID._member_map_:
            extend_enum(HIT_SuiteID, key, default)
        return HIT_SuiteID[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 15):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 4 <= value <= 15:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
