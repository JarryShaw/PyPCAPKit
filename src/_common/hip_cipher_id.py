# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class CipherID(IntEnum):
    """Enumeration class for CipherID."""
    _ignore_ = 'CipherID _'
    CipherID = vars()

    # Cipher IDs
    CipherID['RESERVED [0]'] = 0                                                # [RFC 7401]
    CipherID['NULL-ENCRYPT'] = 1                                                # [RFC 7401]
    CipherID['AES-128-CBC'] = 2                                                 # [RFC 7401]
    CipherID['RESERVED [3]'] = 3                                                # [RFC 7401]
    CipherID['AES-256-CBC'] = 4                                                 # [RFC 7401]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return CipherID(key)
        if key not in CipherID._member_map_:
            extend_enum(CipherID, key, default)
        return CipherID[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 5 <= value <= 65535:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
