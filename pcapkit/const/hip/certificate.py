# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HIP Certificate Types
===========================

.. module:: pcapkit.const.hip.certificate

This module contains the constant enumeration for **HIP Certificate Types**,
which is automatically generated from :class:`pcapkit.vendor.hip.certificate.Certificate`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Certificate']


class Certificate(IntEnum):
    """[Certificate] HIP Certificate Types"""

    #: Reserved [:rfc:`8002`]
    Reserved_0 = 0

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
    def get(key: 'int | str', default: 'int' = -1) -> 'Certificate':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return Certificate(key)
        if key not in Certificate._member_map_:  # pylint: disable=no-member
            return extend_enum(Certificate, key, default)
        return Certificate[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'Certificate':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 9 <= value <= 255:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
