# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""SCTP Chunk Types
======================

.. module:: pcapkit.const.sctp.chunk

This module contains the constant enumeration for **SCTP Chunk Types**,
which is maintained manually against the `IANA`_ registry, as there
is currently no vendor crawler for SCTP under :mod:`pcapkit.vendor`.

.. _IANA: https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-1

"""

from aenum import IntEnum, extend_enum

__all__ = ['Chunk']


class Chunk(IntEnum):
    """[Chunk] SCTP Chunk Types"""

    #: Payload Data (DATA) [:rfc:`9260`]
    Payload_Data = 0

    #: Initiation (INIT) [:rfc:`9260`]
    Initiation = 1

    #: Initiation Acknowledgement (INIT ACK) [:rfc:`9260`]
    Initiation_Acknowledgement = 2

    #: Selective Acknowledgement (SACK) [:rfc:`9260`]
    Selective_Acknowledgement = 3

    #: Heartbeat Request (HEARTBEAT) [:rfc:`9260`]
    Heartbeat_Request = 4

    #: Heartbeat Acknowledgement (HEARTBEAT ACK) [:rfc:`9260`]
    Heartbeat_Acknowledgement = 5

    #: Abort (ABORT) [:rfc:`9260`]
    Abort = 6

    #: Shutdown (SHUTDOWN) [:rfc:`9260`]
    Shutdown = 7

    #: Shutdown Acknowledgement (SHUTDOWN ACK) [:rfc:`9260`]
    Shutdown_Acknowledgement = 8

    #: Operation Error (ERROR) [:rfc:`9260`]
    Operation_Error = 9

    #: State Cookie (COOKIE ECHO) [:rfc:`9260`]
    State_Cookie = 10

    #: Cookie Acknowledgement (COOKIE ACK) [:rfc:`9260`]
    Cookie_Acknowledgement = 11

    #: Reserved for Explicit Congestion Notification Echo (ECNE) [:rfc:`9260`]
    Reserved_for_Explicit_Congestion_Notification_Echo = 12

    #: Reserved for Congestion Window Reduced (CWR) [:rfc:`9260`]
    Reserved_for_Congestion_Window_Reduced = 13

    #: Shutdown Complete (SHUTDOWN COMPLETE) [:rfc:`9260`]
    Shutdown_Complete = 14

    #: Authentication Chunk (AUTH) [:rfc:`4895`]
    Authentication_Chunk = 15

    #: Reserved for IETF-defined Chunk Extensions [:rfc:`9260`]
    Reserved_for_IETF_defined_Chunk_Extensions_63 = 63

    #: Payload Data supporting Interleaving (I-DATA) [:rfc:`8260`]
    Payload_Data_supporting_Interleaving = 64

    #: DTLS (TEMPORARY - registered 2026-02-20, expires 2027-02-20) [draft-ietf-
    #: tsvwg-sctp-dtls-chunk-01]
    DTLS = 65

    #: Reserved for IETF-defined Chunk Extensions [:rfc:`9260`]
    Reserved_for_IETF_defined_Chunk_Extensions_127 = 127

    #: Address Configuration Acknowledgment (ASCONF-ACK) [:rfc:`5061`]
    Address_Configuration_Acknowledgment = 128

    #: Unassigned
    Unassigned_129 = 129

    #: Re-configuration Chunk (RE-CONFIG) [:rfc:`6525`]
    Re_configuration_Chunk = 130

    #: Unassigned
    Unassigned_131 = 131

    #: Padding Chunk (PAD) [:rfc:`4820`]
    Padding_Chunk = 132

    #: Reserved for IETF-defined Chunk Extensions [:rfc:`9260`]
    Reserved_for_IETF_defined_Chunk_Extensions_191 = 191

    #: Forward TSN [:rfc:`3758`]
    Forward_TSN = 192

    #: Address Configuration Change Chunk (ASCONF) [:rfc:`5061`]
    Address_Configuration_Change_Chunk = 193

    #: I-FORWARD-TSN [:rfc:`8260`]
    I_FORWARD_TSN = 194

    #: Reserved for IETF-defined Chunk Extensions [:rfc:`9260`]
    Reserved_for_IETF_defined_Chunk_Extensions_255 = 255

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Chunk':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return Chunk(key)
        if key not in Chunk._member_map_:  # pylint: disable=no-member
            return extend_enum(Chunk, key, default)
        return Chunk[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'Chunk':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 16 <= value <= 62:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 66 <= value <= 126:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 133 <= value <= 190:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 195 <= value <= 254:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
