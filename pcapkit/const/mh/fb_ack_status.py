# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Flow Binding Acknowledgement Status Codes
===============================================

.. module:: pcapkit.const.mh.fb_ack_status

This module contains the constant enumeration for **Flow Binding Acknowledgement Status Codes**,
which is automatically generated from :class:`pcapkit.vendor.mh.fb_ack_status.FlowBindingACKStatus`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['FlowBindingACKStatus']


class FlowBindingACKStatus(IntEnum):
    """[FlowBindingACKStatus] Flow Binding Acknowledgement Status Codes"""

    #: Success [:rfc:`7109`]
    Success = 0

    #: Binding (target CoA) Does NOT Exist [:rfc:`7109`]
    Binding = 128

    #: Action NOT Authorized [:rfc:`7109`]
    Action_NOT_Authorized = 129

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'FlowBindingACKStatus':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return FlowBindingACKStatus(key)
        if key not in FlowBindingACKStatus._member_map_:  # pylint: disable=no-member
            return extend_enum(FlowBindingACKStatus, key, default)
        return FlowBindingACKStatus[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'FlowBindingACKStatus':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 1 <= value <= 127:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 130 <= value <= 255:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
