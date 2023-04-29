# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Revocation Trigger Values
===============================

.. module:: pcapkit.const.mh.revocation_trigger

This module contains the constant enumeration for **Revocation Trigger Values**,
which is automatically generated from :class:`pcapkit.vendor.mh.revocation_trigger.RevocationTrigger`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['RevocationTrigger']


class RevocationTrigger(IntEnum):
    """[RevocationTrigger] Revocation Trigger Values"""

    #: Unspecified [:rfc:`5846`]
    Unspecified = 0

    #: Administrative Reason [:rfc:`5846`]
    Administrative_Reason = 1

    #: Inter-MAG Handover - same Access Type [:rfc:`5846`]
    Inter_MAG_Handover_same_Access_Type = 2

    #: Inter-MAG Handover - different Access Type [:rfc:`5846`]
    Inter_MAG_Handover_different_Access_Type = 3

    #: Inter-MAG Handover - Unknown [:rfc:`5846`]
    Inter_MAG_Handover_Unknown = 4

    #: User Initiated Session(s) Termination [:rfc:`5846`]
    User_Initiated_Session_Termination = 5

    #: Access Network Session(s) Termination [:rfc:`5846`]
    Access_Network_Session_Termination = 6

    #: Possible Out-of Sync BCE State [:rfc:`5846`]
    Possible_Out_of_Sync_BCE_State = 7

    #: Per-Peer Policy [:rfc:`5846`]
    Per_Peer_Policy = 128

    #: Revoking Mobility Node Local Policy [:rfc:`5846`]
    Revoking_Mobility_Node_Local_Policy = 129

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'RevocationTrigger':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return RevocationTrigger(key)
        if key not in RevocationTrigger._member_map_:  # pylint: disable=no-member
            return extend_enum(RevocationTrigger, key, default)
        return RevocationTrigger[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'RevocationTrigger':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 8 <= value <= 127:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 130 <= value <= 249:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 250 <= value <= 255:
            #: Reserved for Testing Purposes Only [:rfc:`5846`]
            return extend_enum(cls, 'Reserved_for_Testing_Purposes_Only_%d' % value, value)
        return super()._missing_(value)
