# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class SuiteID(IntEnum):
    """Enumeration class for SuiteID."""
    _ignore_ = 'SuiteID _'
    SuiteID = vars()

    # Suite IDs
    SuiteID['Reserved'] = 0                                                     # [RFC 5201]
    SuiteID['AES-CBC with HMAC-SHA1'] = 1                                       # [RFC 5201]
    SuiteID['3DES-CBC with HMAC-SHA1'] = 2                                      # [RFC 5201]
    SuiteID['3DES-CBC with HMAC-MD5'] = 3                                       # [RFC 5201]
    SuiteID['BLOWFISH-CBC with HMAC-SHA1'] = 4                                  # [RFC 5201]
    SuiteID['NULL-ENCRYPT with HMAC-SHA1'] = 5                                  # [RFC 5201]
    SuiteID['NULL-ENCRYPT with HMAC-MD5'] = 6                                   # [RFC 5201]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return SuiteID(key)
        if key not in SuiteID._member_map_:
            extend_enum(SuiteID, key, default)
        return SuiteID[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 7 <= value <= 65535:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
