# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Notify Message Types"""

from aenum import IntEnum, extend_enum

__all__ = ['NotifyMessage']


class NotifyMessage(IntEnum):
    """[NotifyMessage] Notify Message Types"""

    #: Reserved [:rfc:`7401`]
    Reserved = 0

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

    #: OVERLAY_TTL_EXCEEDED [:rfc:`6079`]
    OVERLAY_TTL_EXCEEDED = 70

    #: UNKNOWN_NEXT_HOP [:rfc:`6028`]
    UNKNOWN_NEXT_HOP = 90

    #: NO_VALID_HIP_TRANSPORT_MODE [:rfc:`6261`]
    NO_VALID_HIP_TRANSPORT_MODE = 100

    #: I2_ACKNOWLEDGEMENT [:rfc:`7401`]
    I2_ACKNOWLEDGEMENT = 16384

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return NotifyMessage(key)
        if key not in NotifyMessage._member_map_:  # pylint: disable=no-member
            extend_enum(NotifyMessage, key, default)
        return NotifyMessage[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 2 <= value <= 6:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 8 <= value <= 13:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 21 <= value <= 23:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 29 <= value <= 31:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 33 <= value <= 39:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 52 <= value <= 59:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 63 <= value <= 69:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 71 <= value <= 89:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 91 <= value <= 99:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 101 <= value <= 8191:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 8192 <= value <= 16383:
            #: Reserved for Private Use [:rfc:`7401`]
            extend_enum(cls, 'Reserved_for_Private_Use_%d' % value, value)
            return cls(value)
        if 16385 <= value <= 40959:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 40960 <= value <= 65535:
            #: Reserved for Private Use [:rfc:`7401`]
            extend_enum(cls, 'Reserved_for_Private_Use_%d' % value, value)
            return cls(value)
        return super()._missing_(value)
