# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Flow Binding Indication Triggers
======================================

.. module:: pcapkit.const.mh.fb_indication_trigger

This module contains the constant enumeration for **Flow Binding Indication Triggers**,
which is automatically generated from :class:`pcapkit.vendor.mh.fb_indication_trigger.FlowBindingIndicationTrigger`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['FlowBindingIndicationTrigger']


class FlowBindingIndicationTrigger(EnumRegistry, IntEnum):
    """[FlowBindingIndicationTrigger] Flow Binding Indication Triggers"""

    #: Reserved [:rfc:`7109`]
    Reserved_0 = 0

    #: Unspecified [:rfc:`7109`]
    Unspecified = 1

    #: Administrative Reason [:rfc:`7109`]
    Administrative_Reason = 2

    #: Possible Out-of-Sync BCE State [:rfc:`7109`]
    Possible_Out_of_Sync_BCE_State = 3

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
    def _missing_(cls, value: 'int') -> 'FlowBindingIndicationTrigger':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 4 <= value <= 249:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 250 <= value <= 255:
            #: Reserved for Testing Purposes Only [:rfc:`7109`]
            return cls._unregistered_member(value, 'Reserved_for_Testing_Purposes_Only')
        return super()._missing_(value)
