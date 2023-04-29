# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Access Technology Type Option Type Values
===============================================

.. module:: pcapkit.const.mh.access_type

This module contains the constant enumeration for **Access Technology Type Option Type Values**,
which is automatically generated from :class:`pcapkit.vendor.mh.access_type.AccessType`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['AccessType']


class AccessType(IntEnum):
    """[AccessType] Access Technology Type Option Type Values"""

    #: Reserved [:rfc:`5213`]
    Reserved_0 = 0

    #: Virtual [:rfc:`5213`]
    Virtual = 1

    #: PPP [:rfc:`5213`]
    PPP = 2

    #: IEEE 802.3 [:rfc:`5213`]
    IEEE_802_3 = 3

    #: IEEE 802.11a/b/g [:rfc:`5213`]
    IEEE_802_11a_b_g = 4

    #: IEEE 802.16e [:rfc:`5213`]
    IEEE_802_16e = 5

    #: 3GPP GERAN [3GPP TS 29.275][Julien Laganier]
    AccessType_3GPP_GERAN = 6

    #: 3GPP UTRAN [3GPP TS 29.275][Julien Laganier]
    AccessType_3GPP_UTRAN = 7

    #: 3GPP E-UTRAN [3GPP TS 29.275][Julien Laganier]
    AccessType_3GPP_E_UTRAN = 8

    #: 3GPP2 eHRPD [3GPP2 X.P0057][Kuntal Chowdhury]
    AccessType_3GPP2_eHRPD = 9

    #: 3GPP2 HRPD [3GPP2 X.P0061][Kuntal Chowdhury]
    AccessType_3GPP2_HRPD = 10

    #: 3GPP2 1xRTT [3GPP2 X.S0011][Kuntal Chowdhury]
    AccessType_3GPP2_1xRTT = 11

    #: 3GPP2 UMB [3GPP2 X.S0054][Kuntal Chowdhury]
    AccessType_3GPP2_UMB = 12

    #: 3GPP NB-IOT [3GPP TS 29.275][Kimmo Kymalainen]
    AccessType_3GPP_NB_IOT = 13

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'AccessType':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return AccessType(key)
        if key not in AccessType._member_map_:  # pylint: disable=no-member
            return extend_enum(AccessType, key, default)
        return AccessType[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'AccessType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 14 <= value <= 255:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
