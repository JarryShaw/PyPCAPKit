# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Traffic Selector Format
=============================

.. module:: pcapkit.const.mh.traffic_selector

This module contains the constant enumeration for **Traffic Selector Format**,
which is automatically generated from :class:`pcapkit.vendor.mh.traffic_selector.TrafficSelector`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['TrafficSelector']


class TrafficSelector(IntEnum):
    """[TrafficSelector] Traffic Selector Format"""

    #: Reserved [:rfc:`6089`]
    Reserved_0 = 0

    #: IPv4 Binary Traffic Selector [:rfc:`6088`]
    IPv4_Binary_Traffic_Selector = 1

    #: IPv6 Binary Traffic Selector [:rfc:`6088`]
    IPv6_Binary_Traffic_Selector = 2

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'TrafficSelector':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return TrafficSelector(key)
        if key not in TrafficSelector._member_map_:  # pylint: disable=no-member
            return extend_enum(TrafficSelector, key, default)
        return TrafficSelector[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'TrafficSelector':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 3 <= value <= 250:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 251 <= value <= 255:
            #: Reserved for Experimental Use [:rfc:`6089`]
            return extend_enum(cls, 'Reserved_for_Experimental_Use_%d' % value, value)
        return super()._missing_(value)
