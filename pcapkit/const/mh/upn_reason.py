# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Update Notification Reasons Registry
==========================================

.. module:: pcapkit.const.mh.upn_reason

This module contains the constant enumeration for **Update Notification Reasons Registry**,
which is automatically generated from :class:`pcapkit.vendor.mh.upn_reason.UpdateNotificationReason`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['UpdateNotificationReason']


class UpdateNotificationReason(IntEnum):
    """[UpdateNotificationReason] Update Notification Reasons Registry"""

    #: Reserved [:rfc:`7077`]
    Reserved_0 = 0

    #: FORCE-REREGISTRATION [:rfc:`7077`]
    FORCE_REREGISTRATION = 1

    #: UPDATE-SESSION-PARAMETERS [:rfc:`7077`]
    UPDATE_SESSION_PARAMETERS = 2

    #: VENDOR-SPECIFIC-REASON [:rfc:`7077`]
    VENDOR_SPECIFIC_REASON = 3

    #: ANI-PARAMS-REQUESTED [:rfc:`7077`]
    ANI_PARAMS_REQUESTED = 4

    #: QOS_SERVICE_REQUEST [:rfc:`7222`]
    QOS_SERVICE_REQUEST = 5

    #: PGW-TRIGGERED-PCSCF-RESTORATION-PCO [3GPP TS 29.275][Kimmo Kymalainen]
    PGW_TRIGGERED_PCSCF_RESTORATION_PCO = 6

    #: PGW-TRIGGERED-PCSCF-RESTORATION-DHCP [3GPP TS 29.275][Kimmo Kymalainen]
    PGW_TRIGGERED_PCSCF_RESTORATION_DHCP = 7

    #: FLOW-MOBILITY [:rfc:`7864`]
    FLOW_MOBILITY = 8

    #: Reserved [:rfc:`7077`]
    Reserved_255 = 255

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'UpdateNotificationReason':
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
                return UpdateNotificationReason(key)
            except ValueError:
                if default == -1:
                    raise
                return UpdateNotificationReason(default)
        try:
            return UpdateNotificationReason[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return UpdateNotificationReason(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'UpdateNotificationReason':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'UpdateNotificationReason':
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
    def _missing_(cls, value: 'int') -> 'UpdateNotificationReason':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 9 <= value <= 254:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
