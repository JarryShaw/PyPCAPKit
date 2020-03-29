# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""HIP Certificate Types"""

from aenum import IntEnum, extend_enum

__all__ = ['Certificate']


class Certificate(IntEnum):
    """[Certificate] HIP Certificate Types"""

    _ignore_ = 'Certificate _'
    Certificate = vars()

    #: [:rfc:`8002`]
    Certificate['Reserved'] = 0

    #: [:rfc:`8002`]
    Certificate['X.509 v3'] = 1

    #: [:rfc:`8002`]
    Certificate['Obsoleted [2]'] = 2

    #: [:rfc:`8002`]
    Certificate['Hash and URL of X.509 v3'] = 3

    #: [:rfc:`8002`]
    Certificate['Obsoleted [4]'] = 4

    #: [:rfc:`8002`]
    Certificate['LDAP URL of X.509 v3'] = 5

    #: [:rfc:`8002`]
    Certificate['Obsoleted [6]'] = 6

    #: [:rfc:`8002`]
    Certificate['Distinguished Name of X.509 v3'] = 7

    #: [:rfc:`8002`]
    Certificate['Obsoleted [8]'] = 8

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Certificate(key)
        if key not in Certificate._member_map_:  # pylint: disable=no-member
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
        return super()._missing_(value)
