# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class Cipher(IntEnum):
    """Enumeration class for Cipher."""
    _ignore_ = 'Cipher _'
    Cipher = vars()

    # Cipher IDs
    Cipher['RESERVED [0]'] = 0                                                  # [RFC 7401]
    Cipher['NULL-ENCRYPT'] = 1                                                  # [RFC 7401]
    Cipher['AES-128-CBC'] = 2                                                   # [RFC 7401]
    Cipher['RESERVED [3]'] = 3                                                  # [RFC 7401]
    Cipher['AES-256-CBC'] = 4                                                   # [RFC 7401]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Cipher(key)
        if key not in Cipher._member_map_:
            extend_enum(Cipher, key, default)
        return Cipher[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 5 <= value <= 65535:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
