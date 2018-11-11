# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class Authentication(IntEnum):
    """Enumeration class for Authentication."""
    _ignore_ = 'Authentication _'
    Authentication = vars()

    # Authentication Types
    Authentication['No Authentication'] = 0                                     # [RFC 1583]
    Authentication['Simple Password Authentication'] = 1                        # [RFC 1583]
    Authentication['Cryptographic authentication'] = 2                          # [RFC 2328][RFC 5709]
    Authentication['Cryptographic Authentication with Extended Sequence Numbers'] = 3# [RFC 7474]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Authentication(key)
        if key not in Authentication._member_map_:
            extend_enum(Authentication, key, default)
        return Authentication[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 4 <= value <= 255:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 256 <= value <= 65535:
            # [RFC 6549]
            extend_enum(cls, 'Deprecated [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
