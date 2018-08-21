# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class CertType(IntEnum):
    """Enumeration class for CertType."""
    _ignore_ = 'CertType _'
    CertType = vars()

    # HIP Certificate Types
    CertType['Reserved'] = 0                                                    # [RFC 8002]
    CertType['X.509 v3'] = 1                                                    # [RFC 8002]
    CertType['Obsoleted [2]'] = 2                                               # [RFC 8002]
    CertType['Hash and URL of X.509 v3'] = 3                                    # [RFC 8002]
    CertType['Obsoleted [4]'] = 4                                               # [RFC 8002]
    CertType['LDAP URL of X.509 v3'] = 5                                        # [RFC 8002]
    CertType['Obsoleted [6]'] = 6                                               # [RFC 8002]
    CertType['Distinguished Name of X.509 v3'] = 7                              # [RFC 8002]
    CertType['Obsoleted [8]'] = 8                                               # [RFC 8002]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return CertType(key)
        if key not in CertType._member_map_:
            extend_enum(CertType, key, default)
        return CertType[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 9 <= value <= 255:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
