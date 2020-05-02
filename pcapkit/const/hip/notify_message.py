# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Notify Message Types"""

from aenum import IntEnum, extend_enum

__all__ = ['NotifyMessage']


class NotifyMessage(IntEnum):
    """[NotifyMessage] Notify Message Types"""

    _ignore_ = 'NotifyMessage _'
    NotifyMessage = vars()

    #: [:rfc:`7401`]
    NotifyMessage['Reserved'] = 0

    #: [:rfc:`7401`]
    NotifyMessage['UNSUPPORTED_CRITICAL_PARAMETER_TYPE'] = 1

    #: [:rfc:`7401`]
    NotifyMessage['INVALID_SYNTAX'] = 7

    #: [:rfc:`7401`]
    NotifyMessage['NO_DH_PROPOSAL_CHOSEN'] = 14

    #: [:rfc:`7401`]
    NotifyMessage['INVALID_DH_CHOSEN'] = 15

    #: [:rfc:`7401`]
    NotifyMessage['NO_HIP_PROPOSAL_CHOSEN'] = 16

    #: [:rfc:`7401`]
    NotifyMessage['INVALID_HIP_CIPHER_CHOSEN'] = 17

    #: [:rfc:`7402`]
    NotifyMessage['NO_ESP_PROPOSAL_CHOSEN'] = 18

    #: [:rfc:`7402`]
    NotifyMessage['INVALID_ESP_TRANSFORM_CHOSEN'] = 19

    #: [:rfc:`7401`]
    NotifyMessage['UNSUPPORTED_HIT_SUITE'] = 20

    #: [:rfc:`7401`]
    NotifyMessage['AUTHENTICATION_FAILED'] = 24

    NotifyMessage['Unassigned_25'] = 25

    #: [:rfc:`7401`]
    NotifyMessage['CHECKSUM_FAILED'] = 26

    NotifyMessage['Unassigned_27'] = 27

    #: [:rfc:`7401`]
    NotifyMessage['HIP_MAC_FAILED'] = 28

    #: [:rfc:`7401`]
    NotifyMessage['ENCRYPTION_FAILED'] = 32

    #: [:rfc:`7401`]
    NotifyMessage['INVALID_HIT'] = 40

    NotifyMessage['Unassigned_41'] = 41

    #: [:rfc:`7401`]
    NotifyMessage['BLOCKED_BY_POLICY'] = 42

    NotifyMessage['Unassigned_43'] = 43

    #: [:rfc:`7401`]
    NotifyMessage['RESPONDER_BUSY_PLEASE_RETRY'] = 44

    NotifyMessage['Unassigned_45'] = 45

    #: [:rfc:`8046`]
    NotifyMessage['LOCATOR_TYPE_UNSUPPORTED'] = 46

    NotifyMessage['Unassigned_47'] = 47

    #: [:rfc:`8002`]
    NotifyMessage['CREDENTIALS_REQUIRED'] = 48

    NotifyMessage['Unassigned_49'] = 49

    #: [:rfc:`8002`]
    NotifyMessage['INVALID_CERTIFICATE'] = 50

    #: [:rfc:`8003`]
    NotifyMessage['REG_REQUIRED'] = 51

    #: [:rfc:`5770`]
    NotifyMessage['NO_VALID_NAT_TRAVERSAL_MODE_PARAMETER'] = 60

    #: [:rfc:`5770`]
    NotifyMessage['CONNECTIVITY_CHECKS_FAILED'] = 61

    #: [:rfc:`5770`]
    NotifyMessage['MESSAGE_NOT_RELAYED'] = 62

    #: [:rfc:`6079`]
    NotifyMessage['OVERLAY_TTL_EXCEEDED'] = 70

    #: [:rfc:`6028`]
    NotifyMessage['UNKNOWN_NEXT_HOP'] = 90

    #: [:rfc:`6261`]
    NotifyMessage['NO_VALID_HIP_TRANSPORT_MODE'] = 100

    #: [:rfc:`7401`]
    NotifyMessage['I2_ACKNOWLEDGEMENT'] = 16384

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
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 8 <= value <= 13:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 21 <= value <= 23:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 29 <= value <= 31:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 33 <= value <= 39:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 52 <= value <= 59:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 63 <= value <= 69:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 71 <= value <= 89:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 91 <= value <= 99:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 101 <= value <= 8191:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 8192 <= value <= 16383:
            #: [:rfc:`7401`]
            extend_enum(cls, 'Reserved for Private Use [%d]' % value, value)
            return cls(value)
        if 16385 <= value <= 40959:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 40960 <= value <= 65535:
            #: [:rfc:`7401`]
            extend_enum(cls, 'Reserved for Private Use [%d]' % value, value)
            return cls(value)
        return super()._missing_(value)
