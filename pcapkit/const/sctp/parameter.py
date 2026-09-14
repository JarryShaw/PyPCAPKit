# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""SCTP Chunk Parameter Types
================================

.. module:: pcapkit.const.sctp.parameter

This module contains the constant enumeration for **SCTP Chunk Parameter Types**,
which is automatically generated from :class:`pcapkit.vendor.sctp.parameter.Parameter`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Parameter']


class Parameter(IntEnum):
    """[Parameter] SCTP Chunk Parameter Types"""

    #: Heartbeat Info [:rfc:`9260`]
    Heartbeat_Info = 1

    #: IPv4 Address [:rfc:`9260`]
    IPv4_Address = 5

    #: IPv6 Address [:rfc:`9260`]
    IPv6_Address = 6

    #: State Cookie [:rfc:`9260`]
    State_Cookie = 7

    #: Unrecognized Parameter [:rfc:`9260`]
    Unrecognized_Parameter = 8

    #: Cookie Preservative [:rfc:`9260`]
    Cookie_Preservative = 9

    #: Unassigned
    Unassigned_10 = 10

    #: Host Name Address [:rfc:`9260`]
    Host_Name_Address = 11

    #: Supported Address Types [:rfc:`9260`]
    Supported_Address_Types = 12

    #: Outgoing SSN Reset Request Parameter [:rfc:`6525`]
    Outgoing_SSN_Reset_Request_Parameter = 13

    #: Incoming SSN Reset Request Parameter [:rfc:`6525`]
    Incoming_SSN_Reset_Request_Parameter = 14

    #: SSN/TSN Reset Request Parameter [:rfc:`6525`]
    SSN_TSN_Reset_Request_Parameter = 15

    #: Re-configuration Response Parameter [:rfc:`6525`]
    Re_configuration_Response_Parameter = 16

    #: Add Outgoing Streams Request Parameter [:rfc:`6525`]
    Add_Outgoing_Streams_Request_Parameter = 17

    #: Add Incoming Streams Request Parameter [:rfc:`6525`]
    Add_Incoming_Streams_Request_Parameter = 18

    #: Reserved for ECN Capable (0x8000) [:rfc:`9260`]
    Reserved_for_ECN_Capable = 32768

    #: Zero Checksum Acceptable (0x8001) [:rfc:`9653`]
    Zero_Checksum_Acceptable = 32769

    #: Random  (0x8002) [:rfc:`4895`]
    Random = 32770

    #: Chunk List  (0x8003) [:rfc:`4895`]
    Chunk_List = 32771

    #: Requested HMAC Algorithm Parameter  (0x8004) [:rfc:`4895`]
    Requested_HMAC_Algorithm_Parameter = 32772

    #: Padding  (0x8005)
    Padding = 32773

    #: DTLS Key Management (0x8006) (TEMPORARY - registered 2026-02-20, expires
    #: 2027-02-20) [draft-ietf-tsvwg-sctp-dtls-chunk-01]
    DTLS_Key_Management = 32774

    #: Unassigned
    Unassigned_32775 = 32775

    #: Supported Extensions (0x8008) [:rfc:`5061`]
    Supported_Extensions = 32776

    #: Forward TSN supported  (0xC000) [:rfc:`3758`]
    Forward_TSN_supported = 49152

    #: Add IP Address  (0xC001) [:rfc:`5061`]
    Add_IP_Address = 49153

    #: Delete IP Address  (0xC002) [:rfc:`5061`]
    Delete_IP_Address = 49154

    #: Error Cause Indication  (0xC003) [:rfc:`5061`]
    Error_Cause_Indication = 49155

    #: Set Primary Address  (0xC004) [:rfc:`5061`]
    Set_Primary_Address = 49156

    #: Success Indication  (0xC005) [:rfc:`5061`]
    Success_Indication = 49157

    #: Adaptation Layer Indication  (0xC006) [:rfc:`5061`]
    Adaptation_Layer_Indication = 49158

    #: Reserved for IETF-defined Chunk Extensions [:rfc:`9260`]
    Reserved_for_IETF_defined_Chunk_Extensions = 65535

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Parameter':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return Parameter(key)
        if key not in Parameter._member_map_:  # pylint: disable=no-member
            return extend_enum(Parameter, key, default)
        return Parameter[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'Parameter':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 2 <= value <= 4:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 19 <= value <= 32767:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 32777 <= value <= 49151:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 49159 <= value <= 65534:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
