# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""ICMPv6 Time Exceeded Codes
================================

.. module:: pcapkit.const.icmpv6.time_exceeded_code

This module contains the constant enumeration for **ICMPv6 Time Exceeded Codes**,
which is automatically generated from :class:`pcapkit.vendor.icmpv6.time_exceeded_code.TimeExceededCode`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['TimeExceededCode']


class TimeExceededCode(EnumRegistry, IntEnum):
    """[TimeExceededCode] ICMPv6 Time Exceeded Codes [:rfc:`4443`]"""

    #: hop limit exceeded in transit
    hop_limit_exceeded_in_transit = 0

    #: fragment reassembly time exceeded
    fragment_reassembly_time_exceeded = 1

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
    def _missing_(cls, value: 'int') -> 'TimeExceededCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')
