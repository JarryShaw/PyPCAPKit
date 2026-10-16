# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HIP Certificate Types
===========================

.. module:: pcapkit.const.hip.certificate

This module contains the constant enumeration for **HIP Certificate Types**,
which is automatically generated from :class:`pcapkit.vendor.hip.certificate.Certificate`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['Certificate']


class Certificate(EnumRegistry, IntEnum):
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

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it passes the range check :meth:`_missing_` makes.

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value`
        with that check and the message it raises, so
        :meth:`~pcapkit.corekit.enum.EnumRegistry.register` refuses exactly the
        values :meth:`~pcapkit.corekit.enum.EnumLookup.get` refuses, in the
        same words (:issue:`1816`).

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` fails that check. A
                :exc:`ValueError`, so an ``except ValueError`` caller is
                unaffected.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

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
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
