# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Flow Binding Action Values
================================

.. module:: pcapkit.const.mh.fb_action

This module contains the constant enumeration for **Flow Binding Action Values**,
which is automatically generated from :class:`pcapkit.vendor.mh.fb_action.FlowBindingAction`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['FlowBindingAction']


class FlowBindingAction(EnumRegistry, IntEnum):
    """[FlowBindingAction] Flow Binding Action Values"""

    #: Add a flow binding [:rfc:`7109`]
    Add = 11

    #: Delete a flow binding [:rfc:`7109`]
    Delete = 12

    #: Modify a flow binding [:rfc:`7109`]
    Modify = 13

    #: Refresh a flow binding [:rfc:`7109`]
    Refresh = 14

    #: Move a flow binding [:rfc:`7109`]
    Move = 15

    #: Revoke a flow binding [:rfc:`7109`]
    Revoke = 16

    @classmethod
    def _missing_(cls, value: 'int') -> 'FlowBindingAction':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0 <= value <= 10:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 17 <= value <= 255:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
