# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Handover Initiate Status Codes
====================================

.. module:: pcapkit.const.mh.handover_initiate_status

This module contains the constant enumeration for **Handover Initiate Status Codes**,
which is automatically generated from :class:`pcapkit.vendor.mh.handover_initiate_status.HandoverInitiateStatus`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['HandoverInitiateStatus']


class HandoverInitiateStatus(EnumRegistry, IntEnum):
    """[HandoverInitiateStatus] Handover Initiate Status Codes"""

    #: FBU with the PCoA as source IP address [:rfc:`5568`]
    FBU_with_the_PCoA_as_source_IP_address = 0

    #: FBU whose source IP address is not PCoA [:rfc:`5568`]
    FBU_whose_source_IP_address_is_not_PCoA = 1

    #: Indicate the completion of forwarding [:rfc:`5949`]
    Indicate_the_completion_of_forwarding = 2

    #: All available context transferred [:rfc:`5949`]
    All_available_context_transferred = 3

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
    def _missing_(cls, value: 'int') -> 'HandoverInitiateStatus':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 4 <= value <= 255:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
