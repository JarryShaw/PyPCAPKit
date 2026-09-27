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
            default: Default value if not found. The placeholder ``-1`` stands
                for *no default*, in which case an unresolvable key propagates
                the lookup error instead of falling back.

        :meta private:
        """
        if isinstance(key, int):
            try:
                return NotifyMessage(key)
            except ValueError:
                if default == -1:
                    raise
                return NotifyMessage(default)
        try:
            return NotifyMessage[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return NotifyMessage(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'NotifyMessage':
        """Explicitly register a new member.

        Unlike :meth:`get` and :meth:`_missing_`, which resolve a key or a
        value without minting anything new, this is the caller-named entry
        point that still grows the registry, via :func:`aenum.extend_enum`.

        Args:
            value: Value of the new member.
            name: Name of the new member.

        Returns:
            The newly registered member.

        """
        return extend_enum(cls, name, value)

    @classmethod
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'NotifyMessage':
        """Build a member absent from this registry's own lookup tables.

        Used by :meth:`_missing_` for a bounded-but-unassigned value it
        resolves without anyone asking for a name, so that such a lookup no
        longer grows the registry -- contrast :meth:`register`, the explicit
        path that still does.

        Args:
            value: The member's value.
            name: The member's name.

        Returns:
            The unregistered member.

        """
        obj = int.__new__(cls, value)
        obj._name_ = name  # pylint: disable=protected-access
        obj._value_ = value  # pylint: disable=protected-access
        return obj

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
            return cls._unregistered_member(value, 'Unassigned')
        if 8 <= value <= 13:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 21 <= value <= 23:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 29 <= value <= 31:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 33 <= value <= 39:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 52 <= value <= 59:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 65 <= value <= 69:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 71 <= value <= 89:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 91 <= value <= 99:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 101 <= value <= 8191:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 8192 <= value <= 16383:
            #: Reserved for Private Use [:rfc:`7401`]
            return cls._unregistered_member(value, 'Reserved_for_Private_Use')
        if 16386 <= value <= 40959:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 40960 <= value <= 65535:
            #: Reserved for Private Use [:rfc:`7401`]
            return cls._unregistered_member(value, 'Reserved_for_Private_Use')
        return super()._missing_(value)
