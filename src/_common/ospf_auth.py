# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class AuthType(IntEnum):
    """Enumeration class for AuthType."""
    _ignore_ = 'AuthType _'
    AuthType = vars()

    # Authentication Types
    AuthType['No Authentication'] = 0                                           # [RFC 1583]
    AuthType['Simple Password Authentication'] = 1                              # [RFC 1583]
    AuthType['Cryptographic authentication'] = 2                                # [RFC 2328][RFC 5709]
    AuthType['Cryptographic Authentication with Extended Sequence Numbers'] = 3 # [RFC 7474]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return AuthType(key)
        if key not in AuthType._member_map_:
            extend_enum(AuthType, key, default)
        return AuthType[key]

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
