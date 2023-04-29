# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Flow Binding Indication Triggers
======================================

.. module:: pcapkit.const.mh.fb_indication_trigger

This module contains the constant enumeration for **Flow Binding Indication Triggers**,
which is automatically generated from :class:`pcapkit.vendor.mh.fb_indication_trigger.FlowBindingIndicationTrigger`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['FlowBindingIndicationTrigger']


class FlowBindingIndicationTrigger(IntEnum):
    """[FlowBindingIndicationTrigger] Flow Binding Indication Triggers"""

    #: Reserved [:rfc:`7109`]
    Reserved_0 = 0

    #: Unspecified [:rfc:`7109`]
    Unspecified = 1

    #: Administrative Reason [:rfc:`7109`]
    Administrative_Reason = 2

    #: Possible Out-of-Sync BCE State [:rfc:`7109`]
    Possible_Out_of_Sync_BCE_State = 3

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'FlowBindingIndicationTrigger':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return FlowBindingIndicationTrigger(key)
        if key not in FlowBindingIndicationTrigger._member_map_:  # pylint: disable=no-member
            return extend_enum(FlowBindingIndicationTrigger, key, default)
        return FlowBindingIndicationTrigger[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'FlowBindingIndicationTrigger':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 4 <= value <= 249:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 250 <= value <= 255:
            #: Reserved for Testing Purposes Only [:rfc:`7109`]
            return extend_enum(cls, 'Reserved_for_Testing_Purposes_Only_%d' % value, value)
        return super()._missing_(value)
