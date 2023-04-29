# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Quality-of-Service Attribute Registry
===========================================

.. module:: pcapkit.const.mh.qos_attribute

This module contains the constant enumeration for **Quality-of-Service Attribute Registry**,
which is automatically generated from :class:`pcapkit.vendor.mh.qos_attribute.QoSAttribute`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['QoSAttribute']


class QoSAttribute(IntEnum):
    """[QoSAttribute] Quality-of-Service Attribute Registry"""

    #: Reserved [:rfc:`7222`]
    Reserved_0 = 0

    #: Per-MN-Agg-Max-DL-Bit-Rate [:rfc:`7222`]
    Per_MN_Agg_Max_DL_Bit_Rate = 1

    #: Per-MN-Agg-Max-UL-Bit-Rate [:rfc:`7222`]
    Per_MN_Agg_Max_UL_Bit_Rate = 2

    #: Per-Session-Agg-Max-DL-Bit-Rate [:rfc:`7222`]
    Per_Session_Agg_Max_DL_Bit_Rate = 3

    #: Per-Session-Agg-Max-UL-Bit-Rate [:rfc:`7222`]
    Per_Session_Agg_Max_UL_Bit_Rate = 4

    #: Allocation-Retention-Priority [:rfc:`7222`]
    Allocation_Retention_Priority = 5

    #: Aggregate-Max-DL-Bit-Rate [:rfc:`7222`]
    Aggregate_Max_DL_Bit_Rate = 6

    #: Aggregate-Max-UL-Bit-Rate [:rfc:`7222`]
    Aggregate_Max_UL_Bit_Rate = 7

    #: Guaranteed-DL-Bit-Rate [:rfc:`7222`]
    Guaranteed_DL_Bit_Rate = 8

    #: Guaranteed-UL-Bit-Rate [:rfc:`7222`]
    Guaranteed_UL_Bit_Rate = 9

    #: QoS-Traffic-Selector [:rfc:`7222`]
    QoS_Traffic_Selector = 10

    #: QoS-Vendor-Specific-Attribute [:rfc:`7222`]
    QoS_Vendor_Specific_Attribute = 11

    #: Reserved [:rfc:`7222`]
    Reserved_255 = 255

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'QoSAttribute':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return QoSAttribute(key)
        if key not in QoSAttribute._member_map_:  # pylint: disable=no-member
            return extend_enum(QoSAttribute, key, default)
        return QoSAttribute[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'QoSAttribute':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 12 <= value <= 254:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
