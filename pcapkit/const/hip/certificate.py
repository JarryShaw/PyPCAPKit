# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class Certificate(IntEnum):
    """Enumeration class for Certificate."""
    _ignore_ = 'Certificate _'
    Certificate = vars()

    # HIP Certificate Types
    Certificate['Reserved'] = 0                                                 # [RFC 8002]
    Certificate['X.509 v3'] = 1                                                 # [RFC 8002]
    Certificate['Obsoleted [2]'] = 2                                            # [RFC 8002]
    Certificate['Hash and URL of X.509 v3'] = 3                                 # [RFC 8002]
    Certificate['Obsoleted [4]'] = 4                                            # [RFC 8002]
    Certificate['LDAP URL of X.509 v3'] = 5                                     # [RFC 8002]
    Certificate['Obsoleted [6]'] = 6                                            # [RFC 8002]
    Certificate['Distinguished Name of X.509 v3'] = 7                           # [RFC 8002]
    Certificate['Obsoleted [8]'] = 8                                            # [RFC 8002]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Certificate(key)
        if key not in Certificate._member_map_:
            extend_enum(Certificate, key, default)
        return Certificate[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 9 <= value <= 255:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
