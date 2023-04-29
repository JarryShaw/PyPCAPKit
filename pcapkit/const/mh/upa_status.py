# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Update Notification Acknowledgement Status Registry
=========================================================

.. module:: pcapkit.const.mh.upa_status

This module contains the constant enumeration for **Update Notification Acknowledgement Status Registry**,
which is automatically generated from :class:`pcapkit.vendor.mh.upa_status.UpdateNotificationACKStatus`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['UpdateNotificationACKStatus']


class UpdateNotificationACKStatus(IntEnum):
    """[UpdateNotificationACKStatus] Update Notification Acknowledgement Status Registry"""

    #: SUCCESS [:rfc:`7077`]
    SUCCESS = 0

    #: FAILED-TO-UPDATE-SESSION-PARAMETERS [:rfc:`7077`]
    FAILED_TO_UPDATE_SESSION_PARAMETERS = 128

    #: MISSING-VENDOR-SPECIFIC-OPTION [:rfc:`7077`]
    MISSING_VENDOR_SPECIFIC_OPTION = 129

    #: CANNOT_MEET_QOS_SERVICE_REQUEST [:rfc:`7222`]
    CANNOT_MEET_QOS_SERVICE_REQUEST = 130

    #: Reason unspecified. [:rfc:`7864`]
    Reason_unspecified = 131

    #: MN not attached. [:rfc:`7864`]
    MN_not_attached = 132

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'UpdateNotificationACKStatus':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return UpdateNotificationACKStatus(key)
        if key not in UpdateNotificationACKStatus._member_map_:  # pylint: disable=no-member
            return extend_enum(UpdateNotificationACKStatus, key, default)
        return UpdateNotificationACKStatus[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'UpdateNotificationACKStatus':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 1 <= value <= 127:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 133 <= value <= 255:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
