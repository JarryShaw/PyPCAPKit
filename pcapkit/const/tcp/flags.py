# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""TCP Header Flags
======================

.. module:: pcapkit.const.tcp.flags

This module contains the constant enumeration for **TCP Header Flags**,
which is automatically generated from :class:`pcapkit.vendor.tcp.flags.Flags`.

"""

from typing import TYPE_CHECKING

from aenum import IntFlag

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['Flags']

class Flags(EnumRegistry, IntFlag):
    """[Flags] TCP Header Flags"""

    #: Reserved for future use [:rfc:`9293`]
    Reserved_4 = 1 << 11

    #: Reserved for future use [:rfc:`9293`]
    Reserved_5 = 1 << 10

    #: Reserved for future use [:rfc:`9293`]
    Reserved_6 = 1 << 9

    #: AE (Accurate ECN) [:rfc:`9768`]
    AE = 1 << 8

    #: CWR (Congestion Window Reduced) [:rfc:`3168`]
    CWR = 1 << 7

    #: ECE (ECN-Echo) [:rfc:`3168`]
    ECE = 1 << 6

    #: Urgent Pointer field is significant (URG) [:rfc:`9293`]
    URG = 1 << 5

    #: Acknowledgment field is significant (ACK) [:rfc:`9293`]
    ACK = 1 << 4

    #: Push Function (PSH) [:rfc:`9293`]
    PSH = 1 << 3

    #: Reset the connection (RST) [:rfc:`9293`]
    RST = 1 << 2

    #: Synchronize sequence numbers (SYN) [:rfc:`9293`]
    SYN = 1 << 1

    #: No more data from sender (FIN) [:rfc:`9293`]
    FIN = 1 << 0

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
        if not (isinstance(value, int) and 0 <= value <= 0xFFF):
            raise EnumValueError(f'{value!r} is not a valid {cls.__name__}')

    @classmethod
    def _missing_(cls, value: 'int') -> 'Flags':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFFF):
            raise ValueError(f'{value!r} is not a valid {cls.__name__}')
        return super()._missing_(value)
