# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""IPv4 Router Alert Option Values
=====================================

.. module:: pcapkit.const.ipv4.router_alert

This module contains the constant enumeration for **IPv4 Router Alert Option Values**,
which is automatically generated from :class:`pcapkit.vendor.ipv4.router_alert.RouterAlert`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['RouterAlert']


class RouterAlert(IntEnum):
    """[RouterAlert] IPv4 Router Alert Option Values"""

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_0 = 1

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_1 = 2

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_2 = 3

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_3 = 4

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_4 = 5

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_5 = 6

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_6 = 7

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_7 = 8

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_8 = 9

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_9 = 10

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_10 = 11

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_11 = 12

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_12 = 13

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_13 = 14

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_14 = 15

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_15 = 16

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_16 = 17

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_17 = 18

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_18 = 19

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_19 = 20

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_20 = 21

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_21 = 22

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_22 = 23

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_23 = 24

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_24 = 25

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_25 = 26

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_26 = 27

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_27 = 28

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_28 = 29

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_29 = 30

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_30 = 31

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_31 = 32

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_0 = 33

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_1 = 34

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_2 = 35

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_3 = 36

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_4 = 37

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_5 = 38

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_6 = 39

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_7 = 40

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_8 = 41

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_9 = 42

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_10 = 43

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_11 = 44

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_12 = 45

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_13 = 46

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_14 = 47

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_15 = 48

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_16 = 49

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_17 = 50

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_18 = 51

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_19 = 52

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_20 = 53

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_21 = 54

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_22 = 55

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_23 = 56

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_24 = 57

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_25 = 58

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_26 = 59

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_27 = 60

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_28 = 61

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_29 = 62

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_30 = 63

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_31 = 64

    #: NSIS NATFW NSLP [:rfc:`5973`]
    NSIS_NATFW_NSLP = 65

    #: Reserved [:rfc:`5350`]
    Reserved_65535 = 65535

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'RouterAlert':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return RouterAlert(key)
        if key not in RouterAlert._member_map_:  # pylint: disable=no-member
            return extend_enum(RouterAlert, key, default)
        return RouterAlert[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'RouterAlert':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 66 <= value <= 65502:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 65503 <= value <= 65534:
            #: Reserved for experimental use [:rfc:`5350`]
            return extend_enum(cls, 'Reserved for experimental use_%d' % value, value)
        return super()._missing_(value)
