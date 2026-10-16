# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Suite IDs
===============

.. module:: pcapkit.const.hip.suite

This module contains the constant enumeration for **Suite IDs**,
which is automatically generated from :class:`pcapkit.vendor.hip.suite.Suite`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['Suite']


class Suite(EnumRegistry, IntEnum):
    """[Suite] Suite IDs"""

    #: Reserved [:rfc:`5201`]
    Reserved_0 = 0

    #: AES-CBC with HMAC-SHA1 [:rfc:`5201`]
    AES_CBC_with_HMAC_SHA1 = 1

    #: 3DES-CBC with HMAC-SHA1 [:rfc:`5201`]
    Suite_3DES_CBC_with_HMAC_SHA1 = 2

    #: 3DES-CBC with HMAC-MD5 [:rfc:`5201`]
    Suite_3DES_CBC_with_HMAC_MD5 = 3

    #: BLOWFISH-CBC with HMAC-SHA1 [:rfc:`5201`]
    BLOWFISH_CBC_with_HMAC_SHA1 = 4

    #: NULL-ENCRYPT with HMAC-SHA1 [:rfc:`5201`]
    NULL_ENCRYPT_with_HMAC_SHA1 = 5

    #: NULL-ENCRYPT with HMAC-MD5 [:rfc:`5201`]
    NULL_ENCRYPT_with_HMAC_MD5 = 6

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
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'Suite':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 7 <= value <= 65535:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
