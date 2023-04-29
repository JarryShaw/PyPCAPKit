# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Handover Acknowledge Status Codes
=======================================

.. module:: pcapkit.const.mh.handover_ack_status

This module contains the constant enumeration for **Handover Acknowledge Status Codes**,
which is automatically generated from :class:`pcapkit.vendor.mh.handover_ack_status.HandoverACKStatus`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['HandoverACKStatus']


class HandoverACKStatus(IntEnum):
    """[HandoverACKStatus] Handover Acknowledge Status Codes"""

    #: Handover Accepted or Successful (when 'P' flag is set) [:rfc:`5949`]
    Handover_Accepted_or_Successful = 0

    #: Handover Accepted with NCoA valid [:rfc:`5568`]
    Handover_Accepted_with_NCoA_valid = 0

    #: Handover Accepted, NCoA not valid [:rfc:`5568`]
    Handover_Accepted_NCoA_not_valid = 1

    #: Handover Accepted, NCoA assigned [:rfc:`5568`]
    Handover_Accepted_NCoA_assigned = 2

    #: Handover Accepted, use PCoA [:rfc:`5568`]
    Handover_Accepted_use_PCoA = 3

    #: Message sent unsolicited [:rfc:`5568`]
    Message_sent_unsolicited = 4

    #: Context Transfer Accepted or Successful [:rfc:`5949`]
    Context_Transfer_Accepted_or_Successful = 5

    #: All available Context Transferred [:rfc:`5949`]
    All_available_Context_Transferred = 6

    #: Handover Not Accepted, reason unspecified [:rfc:`5568`]
    Handover_Not_Accepted_reason_unspecified = 128

    #: Administratively prohibited [:rfc:`5568`]
    Administratively_prohibited = 129

    #: Insufficient resources [:rfc:`5568`]
    Insufficient_resources = 130

    #: Requested Context Not Available [:rfc:`5949`]
    Requested_Context_Not_Available = 131

    #: Forwarding Not Available [:rfc:`5949`]
    Forwarding_Not_Available = 132

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'HandoverACKStatus':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return HandoverACKStatus(key)
        if key not in HandoverACKStatus._member_map_:  # pylint: disable=no-member
            return extend_enum(HandoverACKStatus, key, default)
        return HandoverACKStatus[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'HandoverACKStatus':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 7 <= value <= 127:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 133 <= value <= 255:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
