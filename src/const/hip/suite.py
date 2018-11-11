# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class Suite(IntEnum):
    """Enumeration class for Suite."""
    _ignore_ = 'Suite _'
    Suite = vars()

    # Suite IDs
    Suite['Reserved'] = 0                                                       # [RFC 5201]
    Suite['AES-CBC with HMAC-SHA1'] = 1                                         # [RFC 5201]
    Suite['3DES-CBC with HMAC-SHA1'] = 2                                        # [RFC 5201]
    Suite['3DES-CBC with HMAC-MD5'] = 3                                         # [RFC 5201]
    Suite['BLOWFISH-CBC with HMAC-SHA1'] = 4                                    # [RFC 5201]
    Suite['NULL-ENCRYPT with HMAC-SHA1'] = 5                                    # [RFC 5201]
    Suite['NULL-ENCRYPT with HMAC-MD5'] = 6                                     # [RFC 5201]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Suite(key)
        if key not in Suite._member_map_:
            extend_enum(Suite, key, default)
        return Suite[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 7 <= value <= 65535:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
