# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Notify Message Types
==========================

.. module:: pcapkit.const.hip.notify_message

This module contains the constant enumeration for **Notify Message Types**,
which is automatically generated from :class:`pcapkit.vendor.hip.notify_message.NotifyMessage`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['NotifyMessage']


class NotifyMessage(IntEnum):
    """[NotifyMessage] Notify Message Types"""

    #: Reserved [:rfc:`7401`]
    Reserved_0 = 0

    #: UNSUPPORTED_CRITICAL_PARAMETER_TYPE [:rfc:`7401`]
    UNSUPPORTED_CRITICAL_PARAMETER_TYPE = 1

    #: INVALID_SYNTAX [:rfc:`7401`]
    INVALID_SYNTAX = 7

    #: NO_DH_PROPOSAL_CHOSEN [:rfc:`7401`]
    NO_DH_PROPOSAL_CHOSEN = 14

    #: INVALID_DH_CHOSEN [:rfc:`7401`]
    INVALID_DH_CHOSEN = 15

    #: NO_HIP_PROPOSAL_CHOSEN [:rfc:`7401`]
    NO_HIP_PROPOSAL_CHOSEN = 16

    #: INVALID_HIP_CIPHER_CHOSEN [:rfc:`7401`]
    INVALID_HIP_CIPHER_CHOSEN = 17

    #: NO_ESP_PROPOSAL_CHOSEN [:rfc:`7402`]
    NO_ESP_PROPOSAL_CHOSEN = 18

    #: INVALID_ESP_TRANSFORM_CHOSEN [:rfc:`7402`]
    INVALID_ESP_TRANSFORM_CHOSEN = 19

    #: UNSUPPORTED_HIT_SUITE [:rfc:`7401`]
    UNSUPPORTED_HIT_SUITE = 20

    #: AUTHENTICATION_FAILED [:rfc:`7401`]
    AUTHENTICATION_FAILED = 24

    #: Unassigned
    Unassigned_25 = 25

    #: CHECKSUM_FAILED [:rfc:`7401`]
    CHECKSUM_FAILED = 26

    #: Unassigned
    Unassigned_27 = 27

    #: HIP_MAC_FAILED [:rfc:`7401`]
    HIP_MAC_FAILED = 28

    #: ENCRYPTION_FAILED [:rfc:`7401`]
    ENCRYPTION_FAILED = 32

    #: INVALID_HIT [:rfc:`7401`]
    INVALID_HIT = 40

    #: Unassigned
    Unassigned_41 = 41

    #: BLOCKED_BY_POLICY [:rfc:`7401`]
    BLOCKED_BY_POLICY = 42

    #: Unassigned
    Unassigned_43 = 43

    #: RESPONDER_BUSY_PLEASE_RETRY [:rfc:`7401`]
    RESPONDER_BUSY_PLEASE_RETRY = 44

    #: Unassigned
    Unassigned_45 = 45

    #: LOCATOR_TYPE_UNSUPPORTED [:rfc:`8046`]
    LOCATOR_TYPE_UNSUPPORTED = 46

    #: Unassigned
    Unassigned_47 = 47

    #: CREDENTIALS_REQUIRED [:rfc:`8002`]
    CREDENTIALS_REQUIRED = 48

    #: Unassigned
    Unassigned_49 = 49

    #: INVALID_CERTIFICATE [:rfc:`8002`]
    INVALID_CERTIFICATE = 50

    #: REG_REQUIRED [:rfc:`8003`]
    REG_REQUIRED = 51

    #: NO_VALID_NAT_TRAVERSAL_MODE_PARAMETER [:rfc:`5770`]
    NO_VALID_NAT_TRAVERSAL_MODE_PARAMETER = 60

    #: CONNECTIVITY_CHECKS_FAILED [:rfc:`5770`]
    CONNECTIVITY_CHECKS_FAILED = 61

    #: MESSAGE_NOT_RELAYED [:rfc:`5770`]
    MESSAGE_NOT_RELAYED = 62

    #: SERVER_REFLEXIVE_CANDIDATE_ALLOCATION_FAILED [:rfc:`9028`]
    SERVER_REFLEXIVE_CANDIDATE_ALLOCATION_FAILED = 63

    #: RVS_HMAC_PROHIBITED_WITH_RELAY [:rfc:`9028`]
    RVS_HMAC_PROHIBITED_WITH_RELAY = 64

    #: OVERLAY_TTL_EXCEEDED [:rfc:`6079`]
    OVERLAY_TTL_EXCEEDED = 70

    #: UNKNOWN_NEXT_HOP [:rfc:`6028`]
    UNKNOWN_NEXT_HOP = 90

    #: NO_VALID_HIP_TRANSPORT_MODE [:rfc:`6261`]
    NO_VALID_HIP_TRANSPORT_MODE = 100

    #: I2_ACKNOWLEDGEMENT [:rfc:`7401`]
    I2_ACKNOWLEDGEMENT = 16384

    #: NAT_KEEPALIVE [:rfc:`9028`]
    NAT_KEEPALIVE = 16385

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'NotifyMessage':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return NotifyMessage(key)
        if key not in NotifyMessage._member_map_:  # pylint: disable=no-member
            return extend_enum(NotifyMessage, key, default)
        return NotifyMessage[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'NotifyMessage':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 2 <= value <= 6:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 8 <= value <= 13:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 21 <= value <= 23:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 29 <= value <= 31:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 33 <= value <= 39:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 52 <= value <= 59:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 65 <= value <= 69:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 71 <= value <= 89:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 91 <= value <= 99:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 101 <= value <= 8191:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 8192 <= value <= 16383:
            #: Reserved for Private Use [:rfc:`7401`]
            return extend_enum(cls, 'Reserved_for_Private_Use_%d' % value, value)
        if 16386 <= value <= 40959:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 40960 <= value <= 65535:
            #: Reserved for Private Use [:rfc:`7401`]
            return extend_enum(cls, 'Reserved_for_Private_Use_%d' % value, value)
        return super()._missing_(value)
