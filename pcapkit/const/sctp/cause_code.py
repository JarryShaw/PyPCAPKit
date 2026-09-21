# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""SCTP Error Cause Codes
============================

.. module:: pcapkit.const.sctp.cause_code

This module contains the constant enumeration for **SCTP Error Cause Codes**,
which is automatically generated from :class:`pcapkit.vendor.sctp.cause_code.CauseCode`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['CauseCode']


class CauseCode(IntEnum):
    """[CauseCode] SCTP Error Cause Codes"""

    #: Invalid Stream Identifier [:rfc:`9260`]
    Invalid_Stream_Identifier = 1

    #: Missing Mandatory Parameter [:rfc:`9260`]
    Missing_Mandatory_Parameter = 2

    #: Stale Cookie [:rfc:`9260`]
    Stale_Cookie = 3

    #: Out of Resource [:rfc:`9260`]
    Out_of_Resource = 4

    #: Unresolvable Address [:rfc:`9260`]
    Unresolvable_Address = 5

    #: Unrecognized Chunk Type [:rfc:`9260`]
    Unrecognized_Chunk_Type = 6

    #: Invalid Mandatory Parameter [:rfc:`9260`]
    Invalid_Mandatory_Parameter = 7

    #: Unrecognized Parameters [:rfc:`9260`]
    Unrecognized_Parameters = 8

    #: No User Data [:rfc:`9260`]
    No_User_Data = 9

    #: Cookie Received While Shutting Down [:rfc:`9260`]
    Cookie_Received_While_Shutting_Down = 10

    #: Restart of an Association with New Addresses [:rfc:`9260`]
    Restart_of_an_Association_with_New_Addresses = 11

    #: User-Initiated Abort [:rfc:`9260`]
    User_Initiated_Abort = 12

    #: Protocol Violation [:rfc:`9260`]
    Protocol_Violation = 13

    #: Missing DTLS Chunk Support (TEMPORARY - registered 2026-08-13, expires
    #: 2027-08-13) [draft-ietf-tsvwg-sctp-dtls-chunk-04]
    Missing_DTLS_Chunk_Support = 100

    #: No Common DTLS Key Management Method (TEMPORARY - registered 2026-08-13,
    #: expires 2027-08-13) [draft-ietf-tsvwg-sctp-dtls-chunk-04]
    No_Common_DTLS_Key_Management_Method = 101

    #: DTLS Key Management Tie Breaker Collision (TEMPORARY - registered
    #: 2026-08-13, expires 2027-08-13) [draft-ietf-tsvwg-sctp-dtls-chunk-04]
    DTLS_Key_Management_Tie_Breaker_Collision = 102

    #: Incompatible DTLS Key Management Roles (TEMPORARY - registered 2026-08-13,
    #: expires 2027-08-13) [draft-ietf-tsvwg-sctp-dtls-chunk-04]
    Incompatible_DTLS_Key_Management_Roles = 103

    #: Request to Delete Last Remaining IP Address [:rfc:`5061`]
    Request_to_Delete_Last_Remaining_IP_Address = 160

    #: Operation Refused Due to Resource Shortage [:rfc:`5061`]
    Operation_Refused_Due_to_Resource_Shortage = 161

    #: Request to Delete Source IP Address [:rfc:`5061`]
    Request_to_Delete_Source_IP_Address = 162

    #: Association Aborted due to illegal ASCONF-ACK [:rfc:`5061`]
    Association_Aborted_due_to_illegal_ASCONF_ACK = 163

    #: Request refused - no authorization [:rfc:`5061`]
    Request_refused_no_authorization = 164

    #: Unsupported HMAC Identifier [:rfc:`4895`]
    Unsupported_HMAC_Identifier = 261

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'CauseCode':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found. The placeholder ``-1`` stands
                for *no default*, in which case an unresolvable key propagates
                the lookup error instead of falling back.

        :meta private:
        """
        if isinstance(key, int):
            try:
                return CauseCode(key)
            except ValueError:
                if default == -1:
                    raise
                return CauseCode(default)
        if key not in CauseCode._member_map_:  # pylint: disable=no-member
            return extend_enum(CauseCode, key, default)
        return CauseCode[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'CauseCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 14 <= value <= 99:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 104 <= value <= 159:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 165 <= value <= 260:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 262 <= value <= 65535:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
