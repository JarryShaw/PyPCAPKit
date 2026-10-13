# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Flow Binding Type
=======================

.. module:: pcapkit.const.mh.fb_type

This module contains the constant enumeration for **Flow Binding Type**,
which is automatically generated from :class:`pcapkit.vendor.mh.fb_type.FlowBindingType`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['FlowBindingType']


class FlowBindingType(EnumRegistry, IntEnum):
    """[FlowBindingType] Flow Binding Type"""

    #: Unassigned
    Unassigned_0 = 0

    #: Flow Binding Indication [:rfc:`7109`]
    Indication = 1

    #: Flow Binding Acknowledgement [:rfc:`7109`]
    Acknowledgement = 2

    @classmethod
    def _missing_(cls, value: 'int') -> 'FlowBindingType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 3 <= value <= 255:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
