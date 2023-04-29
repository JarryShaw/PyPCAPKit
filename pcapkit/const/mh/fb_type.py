# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Flow Binding Type
=======================

.. module:: pcapkit.const.mh.fb_type

This module contains the constant enumeration for **Flow Binding Type**,
which is automatically generated from :class:`pcapkit.vendor.mh.fb_type.FlowBindingType`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['FlowBindingType']


class FlowBindingType(IntEnum):
    """[FlowBindingType] Flow Binding Type"""

    #: Unassigned
    Unassigned_0 = 0

    #: Flow Binding Indication [:rfc:`7109`]
    Indication = 1

    #: Flow Binding Acknowledgement [:rfc:`7109`]
    Acknowledgement = 2

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'FlowBindingType':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return FlowBindingType(key)
        if key not in FlowBindingType._member_map_:  # pylint: disable=no-member
            return extend_enum(FlowBindingType, key, default)
        return FlowBindingType[key]  # type: ignore[misc]

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
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
