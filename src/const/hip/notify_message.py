# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class NotifyMessage(IntEnum):
    """Enumeration class for NotifyMessage."""
    _ignore_ = 'NotifyMessage _'
    NotifyMessage = vars()

    # Notify Message Types
    NotifyMessage['Reserved'] = 0                                               # [RFC 7401]
    NotifyMessage['UNSUPPORTED_CRITICAL_PARAMETER_TYPE'] = 1                    # [RFC 7401]
    NotifyMessage['INVALID_SYNTAX'] = 7                                         # [RFC 7401]
    NotifyMessage['NO_DH_PROPOSAL_CHOSEN'] = 14                                 # [RFC 7401]
    NotifyMessage['INVALID_DH_CHOSEN'] = 15                                     # [RFC 7401]
    NotifyMessage['NO_HIP_PROPOSAL_CHOSEN'] = 16                                # [RFC 7401]
    NotifyMessage['INVALID_HIP_CIPHER_CHOSEN'] = 17                             # [RFC 7401]
    NotifyMessage['NO_ESP_PROPOSAL_CHOSEN'] = 18                                # [RFC 7402]
    NotifyMessage['INVALID_ESP_TRANSFORM_CHOSEN'] = 19                          # [RFC 7402]
    NotifyMessage['UNSUPPORTED_HIT_SUITE'] = 20                                 # [RFC 7401]
    NotifyMessage['AUTHENTICATION_FAILED'] = 24                                 # [RFC 7401]
    NotifyMessage['Unassigned [25]'] = 25
    NotifyMessage['CHECKSUM_FAILED'] = 26                                       # [RFC 7401]
    NotifyMessage['Unassigned [27]'] = 27
    NotifyMessage['HIP_MAC_FAILED'] = 28                                        # [RFC 7401]
    NotifyMessage['ENCRYPTION_FAILED'] = 32                                     # [RFC 7401]
    NotifyMessage['INVALID_HIT'] = 40                                           # [RFC 7401]
    NotifyMessage['Unassigned [41]'] = 41
    NotifyMessage['BLOCKED_BY_POLICY'] = 42                                     # [RFC 7401]
    NotifyMessage['Unassigned [43]'] = 43
    NotifyMessage['RESPONDER_BUSY_PLEASE_RETRY'] = 44                           # [RFC 7401]
    NotifyMessage['Unassigned [45]'] = 45
    NotifyMessage['LOCATOR_TYPE_UNSUPPORTED'] = 46                              # [RFC 8046]
    NotifyMessage['Unassigned [47]'] = 47
    NotifyMessage['CREDENTIALS_REQUIRED'] = 48                                  # [RFC 8002]
    NotifyMessage['Unassigned [49]'] = 49
    NotifyMessage['INVALID_CERTIFICATE'] = 50                                   # [RFC 8002]
    NotifyMessage['REG_REQUIRED'] = 51                                          # [RFC 8003]
    NotifyMessage['NO_VALID_NAT_TRAVERSAL_MODE_PARAMETER'] = 60                 # [RFC 5770]
    NotifyMessage['CONNECTIVITY_CHECKS_FAILED'] = 61                            # [RFC 5770]
    NotifyMessage['MESSAGE_NOT_RELAYED'] = 62                                   # [RFC 5770]
    NotifyMessage['OVERLAY_TTL_EXCEEDED'] = 70                                  # [RFC 6079]
    NotifyMessage['UNKNOWN_NEXT_HOP'] = 90                                      # [RFC 6028]
    NotifyMessage['NO_VALID_HIP_TRANSPORT_MODE'] = 100                          # [RFC 6261]
    NotifyMessage['I2_ACKNOWLEDGEMENT'] = 16384                                 # [RFC 7401]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return NotifyMessage(key)
        if key not in NotifyMessage._member_map_:
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
            # [RFC 7401]
            extend_enum(cls, 'Reserved for Private Use [%d]' % value, value)
            return cls(value)
        if 16385 <= value <= 40959:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 40960 <= value <= 65535:
            # [RFC 7401]
            extend_enum(cls, 'Reserved for Private Use [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
