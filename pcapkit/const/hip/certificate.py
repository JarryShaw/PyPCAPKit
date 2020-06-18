# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""HIP Certificate Types"""

from aenum import IntEnum, extend_enum

__all__ = ['Certificate']


class Certificate(IntEnum):
    """[Certificate] HIP Certificate Types"""

    #: Reserved [:rfc:`8002`]
    Reserved = 0

    #: X.509 v3 [:rfc:`8002`]
    X_509_v3 = 1

    #: Obsoleted [:rfc:`8002`]
    Obsoleted_2 = 2

    #: Hash and URL of X.509 v3 [:rfc:`8002`]
    Hash_and_URL_of_X_509_v3 = 3

    #: Obsoleted [:rfc:`8002`]
    Obsoleted_4 = 4

    #: LDAP URL of X.509 v3 [:rfc:`8002`]
    LDAP_URL_of_X_509_v3 = 5

    #: Obsoleted [:rfc:`8002`]
    Obsoleted_6 = 6

    #: Distinguished Name of X.509 v3 [:rfc:`8002`]
    Distinguished_Name_of_X_509_v3 = 7

    #: Obsoleted [:rfc:`8002`]
    Obsoleted_8 = 8

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
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        return super()._missing_(value)
