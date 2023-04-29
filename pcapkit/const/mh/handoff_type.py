# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Handoff Indicator Option Type Values
==========================================

.. module:: pcapkit.const.mh.handoff_type

This module contains the constant enumeration for **Handoff Indicator Option Type Values**,
which is automatically generated from :class:`pcapkit.vendor.mh.handoff_type.HandoffType`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['HandoffType']


class HandoffType(IntEnum):
    """[HandoffType] Handoff Indicator Option Type Values"""

    #: Reserved [:rfc:`5213`]
    Reserved_0 = 0

    #: Attachment over a new interface [:rfc:`5213`]
    Attachment_over_a_new_interface = 1

    #: Handoff between two different interfaces of the mobile node [:rfc:`5213`]
    Handoff_between_two_different_interfaces_of_the_mobile_node = 2

    #: Handoff between mobile access gateways for the same interface [:rfc:`5213`]
    Handoff_between_mobile_access_gateways_for_the_same_interface = 3

    #: Handoff state unknown [:rfc:`5213`]
    Handoff_state_unknown = 4

    #: Handoff state not changed (Re-registration) [:rfc:`5213`]
    Handoff_state_not_changed = 5

    #: Attachment over a new interface sharing prefixes [:rfc:`7864`]
    Attachment_over_a_new_interface_sharing_prefixes = 6

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'HandoffType':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return HandoffType(key)
        if key not in HandoffType._member_map_:  # pylint: disable=no-member
            return extend_enum(HandoffType, key, default)
        return HandoffType[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'HandoffType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 7 <= value <= 255:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
