# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""IPv6 Routing Types
========================

.. module:: pcapkit.const.ipv6.routing

This module contains the constant enumeration for **IPv6 Routing Types**,
which is automatically generated from :class:`pcapkit.vendor.ipv6.routing.Routing`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Routing']


class Routing(IntEnum):
    """[Routing] IPv6 Routing Types"""

    #: Source Route (DEPRECATED) [:rfc:`2460`][:rfc:`5095`]
    Source_Route = 0

    #: Nimrod (DEPRECATED 2009-05-06)
    Nimrod = 1

    #: Type 2 Routing Header [:rfc:`6275`]
    Type_2_Routing_Header = 2

    #: RPL Source Route Header [:rfc:`6554`]
    RPL_Source_Route_Header = 3

    #: Segment Routing Header (SRH) [:rfc:`8754`]
    Segment_Routing_Header = 4

    #: CRH-16 [:rfc:`9631`]
    CRH_16 = 5

    #: CRH-32 [:rfc:`9631`]
    CRH_32 = 6

    #: RFC3692-style Experiment 1 [:rfc:`4727`]
    RFC3692_style_Experiment_1 = 253

    #: RFC3692-style Experiment 2 [:rfc:`4727`]
    RFC3692_style_Experiment_2 = 254

    #: Reserved
    Reserved_255 = 255

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Routing':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return Routing(key)
        if key not in Routing._member_map_:  # pylint: disable=no-member
            return extend_enum(Routing, key, default)
        return Routing[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'Routing':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 7 <= value <= 252:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
