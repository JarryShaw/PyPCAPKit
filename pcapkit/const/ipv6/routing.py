# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""IPv6 Routing Types"""

from aenum import IntEnum, extend_enum

__all__ = ['Routing']


class Routing(IntEnum):
    """[Routing] IPv6 Routing Types"""

    #: Source Route [IPV6][:rfc:`5095`] DEPRECATED
    Source_Route = 0

    #: Nimrod DEPRECATED 2009-05-06
    Nimrod = 1

    #: Type 2 Routing Header [:rfc:`6275`]
    Type_2_Routing_Header = 2

    #: RPL Source Route Header [:rfc:`6554`]
    RPL_Source_Route_Header = 3

    #: Segment Routing Header [:rfc:`8754`] SRH
    Segment_Routing_Header = 4

    #: RFC3692-style Experiment 1 [:rfc:`4727`]
    RFC3692_style_Experiment_1 = 253

    #: RFC3692-style Experiment 2 [:rfc:`4727`]
    RFC3692_style_Experiment_2 = 254

    #: Reserved
    Reserved = 255

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Routing(key)
        if key not in Routing._member_map_:  # pylint: disable=no-member
            extend_enum(Routing, key, default)
        return Routing[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 5 <= value <= 252:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        return super()._missing_(value)
