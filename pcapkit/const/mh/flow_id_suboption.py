# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Flow Identification Sub-Options
=====================================

.. module:: pcapkit.const.mh.flow_id_suboption

This module contains the constant enumeration for **Flow Identification Sub-Options**,
which is automatically generated from :class:`pcapkit.vendor.mh.flow_id_suboption.FlowIDSuboption`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['FlowIDSuboption']


class FlowIDSuboption(IntEnum):
    """[FlowIDSuboption] Flow Identification Sub-Options"""

    #: Pad [:rfc:`6089`]
    Pad = 0

    #: PadN [:rfc:`6089`]
    PadN = 1

    #: BID Reference [:rfc:`6089`]
    BID_Reference = 2

    #: Traffic Selector [:rfc:`6089`]
    Traffic_Selector = 3

    #: Flow Binding Action [:rfc:`7109`]
    Flow_Binding_Action = 4

    #: Target Care-of Address [:rfc:`7109`]
    Target_Care_of_Address = 5

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'FlowIDSuboption':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return FlowIDSuboption(key)
        if key not in FlowIDSuboption._member_map_:  # pylint: disable=no-member
            return extend_enum(FlowIDSuboption, key, default)
        return FlowIDSuboption[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'FlowIDSuboption':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 6 <= value <= 250:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 251 <= value <= 255:
            #: Reserved for Experimental Use [:rfc:`6089`]
            return extend_enum(cls, 'Reserved_for_Experimental_Use_%d' % value, value)
        return super()._missing_(value)
