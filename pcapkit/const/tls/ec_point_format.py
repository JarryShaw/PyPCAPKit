# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""TLS EC Point Formats
==========================

.. module:: pcapkit.const.tls.ec_point_format

This module contains the constant enumeration for **TLS EC Point Formats**,
which is automatically generated from :class:`pcapkit.vendor.tls.ec_point_format.ECPointFormat`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['ECPointFormat']


class ECPointFormat(EnumRegistry, IntEnum):
    """[ECPointFormat] TLS EC Point Formats"""

    #: uncompressed [:rfc:`8422`]
    uncompressed = 0

    #: ansiX962_compressed_prime [:rfc:`8422`]
    ansiX962_compressed_prime = 1

    #: ansiX962_compressed_char2 [:rfc:`8422`]
    ansiX962_compressed_char2 = 2

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
    def _missing_(cls, value: 'int') -> 'ECPointFormat':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 3 <= value <= 247:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 248 <= value <= 255:
            #: Reserved for Private Use [:rfc:`8422`]
            return cls._unregistered_member(value, 'Reserved_for_Private_Use')
        return super()._missing_(value)
