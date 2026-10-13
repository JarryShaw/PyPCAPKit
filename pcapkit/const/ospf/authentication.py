# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Authentication Types
==========================

.. module:: pcapkit.const.ospf.authentication

This module contains the constant enumeration for **Authentication Types**,
which is automatically generated from :class:`pcapkit.vendor.ospf.authentication.Authentication`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['Authentication']


class Authentication(EnumRegistry, IntEnum):
    """[Authentication] Authentication Types"""

    #: No Authentication [:rfc:`1583`]
    No_Authentication = 0

    #: Simple Password Authentication [:rfc:`1583`]
    Simple_Password_Authentication = 1

    #: Cryptographic authentication [:rfc:`2328`][:rfc:`5709`]
    Cryptographic_authentication = 2

    #: Cryptographic Authentication with Extended Sequence Numbers [:rfc:`7474`]
    Cryptographic_Authentication_with_Extended_Sequence_Numbers = 3

    @classmethod
    def _missing_(cls, value: 'int') -> 'Authentication':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 4 <= value <= 255:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 256 <= value <= 65535:
            #: Deprecated [:rfc:`6549`]
            return cls._unregistered_member(value, 'Deprecated')
        return super()._missing_(value)
