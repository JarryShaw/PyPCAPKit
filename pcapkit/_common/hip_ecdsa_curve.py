# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class ECDSA(IntEnum):
    """Enumeration class for ECDSA."""
    _ignore_ = 'ECDSA _'
    ECDSA = vars()

    # ECDSA Curve Label
    ECDSA['RESERVED'] = 0                                                       # [RFC 7401]
    ECDSA['NIST P-256'] = 1                                                     # [RFC 7401]
    ECDSA['NIST P-384'] = 2                                                     # [RFC 7401]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ECDSA(key)
        if key not in ECDSA._member_map_:
            extend_enum(ECDSA, key, default)
        return ECDSA[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 3 <= value <= 65535:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
