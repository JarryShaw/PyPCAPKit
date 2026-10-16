# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Update Notification Reasons Registry
==========================================

.. module:: pcapkit.const.mh.upn_reason

This module contains the constant enumeration for **Update Notification Reasons Registry**,
which is automatically generated from :class:`pcapkit.vendor.mh.upn_reason.UpdateNotificationReason`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['UpdateNotificationReason']


class UpdateNotificationReason(EnumRegistry, IntEnum):
    """[UpdateNotificationReason] Update Notification Reasons Registry"""

    #: Reserved [:rfc:`7077`]
    Reserved_0 = 0

    #: FORCE-REREGISTRATION [:rfc:`7077`]
    FORCE_REREGISTRATION = 1

    #: UPDATE-SESSION-PARAMETERS [:rfc:`7077`]
    UPDATE_SESSION_PARAMETERS = 2

    #: VENDOR-SPECIFIC-REASON [:rfc:`7077`]
    VENDOR_SPECIFIC_REASON = 3

    #: ANI-PARAMS-REQUESTED [:rfc:`7077`]
    ANI_PARAMS_REQUESTED = 4

    #: QOS_SERVICE_REQUEST [:rfc:`7222`]
    QOS_SERVICE_REQUEST = 5

    #: PGW-TRIGGERED-PCSCF-RESTORATION-PCO [3GPP TS 29.275][Kimmo Kymalainen]
    PGW_TRIGGERED_PCSCF_RESTORATION_PCO = 6

    #: PGW-TRIGGERED-PCSCF-RESTORATION-DHCP [3GPP TS 29.275][Kimmo Kymalainen]
    PGW_TRIGGERED_PCSCF_RESTORATION_DHCP = 7

    #: FLOW-MOBILITY [:rfc:`7864`]
    FLOW_MOBILITY = 8

    #: Reserved [:rfc:`7077`]
    Reserved_255 = 255

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
    def _missing_(cls, value: 'int') -> 'UpdateNotificationReason':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 9 <= value <= 254:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
