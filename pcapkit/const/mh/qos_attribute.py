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
            default: Default value if not found. The placeholder ``-1`` stands
                for *no default*, in which case an unresolvable key propagates
                the lookup error instead of falling back.

        :meta private:
        """
        if isinstance(key, int):
            try:
                return QoSAttribute(key)
            except ValueError:
                if default == -1:
                    raise
                return QoSAttribute(default)
        try:
            return QoSAttribute[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return QoSAttribute(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'QoSAttribute':
        """Explicitly register a new member.

        Unlike :meth:`get` and :meth:`_missing_`, which resolve a key or a
        value without minting anything new, this is the caller-named entry
        point that still grows the registry, via :func:`aenum.extend_enum`.

        Args:
            value: Value of the new member.
            name: Name of the new member.

        Returns:
            The newly registered member.

        """
        return extend_enum(cls, name, value)

    @classmethod
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'QoSAttribute':
        """Build a member absent from this registry's own lookup tables.

        Used by :meth:`_missing_` for a bounded-but-unassigned value it
        resolves without anyone asking for a name, so that such a lookup no
        longer grows the registry -- contrast :meth:`register`, the explicit
        path that still does.

        Args:
            value: The member's value.
            name: The member's name.

        Returns:
            The unregistered member.

        """
        obj = int.__new__(cls, value)
        obj._name_ = name  # pylint: disable=protected-access
        obj._value_ = value  # pylint: disable=protected-access
        return obj

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
