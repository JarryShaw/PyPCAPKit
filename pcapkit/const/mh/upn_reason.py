# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Update Notification Reasons Registry
==========================================

.. module:: pcapkit.const.mh.upn_reason

This module contains the constant enumeration for **Update Notification Reasons Registry**,
which is automatically generated from :class:`pcapkit.vendor.mh.upn_reason.UpdateNotificationReason`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['UpdateNotificationReason']


class UpdateNotificationReason(IntEnum):
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

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'UpdateNotificationReason':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return UpdateNotificationReason(key)
        if key not in UpdateNotificationReason._member_map_:  # pylint: disable=no-member
            return extend_enum(UpdateNotificationReason, key, default)
        return UpdateNotificationReason[key]  # type: ignore[misc]

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
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
