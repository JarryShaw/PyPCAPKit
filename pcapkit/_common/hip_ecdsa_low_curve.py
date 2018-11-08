# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class ECDSA_LOW(IntEnum):
    """Enumeration class for ECDSA_LOW."""
    _ignore_ = 'ECDSA_LOW _'
    ECDSA_LOW = vars()

    # ECDSA_LOW Curve Label
    ECDSA_LOW['RESERVED'] = 0                                                   # [RFC 7401]
    ECDSA_LOW['SECP160R1'] = 1                                                  # [RFC 7401]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ECDSA_LOW(key)
        if key not in ECDSA_LOW._member_map_:
            extend_enum(ECDSA_LOW, key, default)
        return ECDSA_LOW[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 2 <= value <= 65535:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
