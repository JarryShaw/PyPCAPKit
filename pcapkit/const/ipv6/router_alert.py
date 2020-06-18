# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""IPv6 Router Alert Option Values"""

from aenum import IntEnum, extend_enum

__all__ = ['RouterAlert']


class RouterAlert(IntEnum):
    """[RouterAlert] IPv6 Router Alert Option Values"""

    #: Datagram contains a Multicast Listener Discovery message [:rfc:`2710`]
    Datagram_contains_a_Multicast_Listener_Discovery_message = 0

    #: Datagram contains RSVP message [:rfc:`2711`]
    Datagram_contains_RSVP_message = 1

    #: Datagram contains an Active Networks message [:rfc:`2711`]
    Datagram_contains_an_Active_Networks_message = 2

    #: Reserved [:rfc:`5350`]
    Reserved_3 = 3

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_0 = 4

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_1 = 5

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_2 = 6

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_3 = 7

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_4 = 8

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_5 = 9

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_6 = 10

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_7 = 11

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_8 = 12

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_9 = 13

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_10 = 14

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_11 = 15

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_12 = 16

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_13 = 17

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_14 = 18

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_15 = 19

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_16 = 20

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_17 = 21

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_18 = 22

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_19 = 23

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_20 = 24

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_21 = 25

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_22 = 26

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_23 = 27

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_24 = 28

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_25 = 29

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_26 = 30

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_27 = 31

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_28 = 32

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_29 = 33

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_30 = 34

    #: Aggregated Reservation Nesting Level [:rfc:`3175`]
    Aggregated_Reservation_Nesting_Level_31 = 35

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_0 = 36

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_1 = 37

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_2 = 38

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_3 = 39

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_4 = 40

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_5 = 41

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_6 = 42

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_7 = 43

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_8 = 44

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_9 = 45

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_10 = 46

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_11 = 47

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_12 = 48

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_13 = 49

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_14 = 50

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_15 = 51

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_16 = 52

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_17 = 53

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_18 = 54

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_19 = 55

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_20 = 56

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_21 = 57

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_22 = 58

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_23 = 59

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_24 = 60

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_25 = 61

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_26 = 62

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_27 = 63

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_28 = 64

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_29 = 65

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_30 = 66

    #: QoS NSLP Aggregation Levels 0-31 [:rfc:`5974`]
    QoS_NSLP_Aggregation_Level_31 = 67

    #: NSIS NATFW NSLP [:rfc:`5973`]
    NSIS_NATFW_NSLP = 68

    #: MPLS OAM [:rfc:`7506`]
    MPLS_OAM = 69

    #: Reserved [The Internet Assigned Numbers Authority]
    Reserved_65535 = 65535

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return RouterAlert(key)
        if key not in RouterAlert._member_map_:  # pylint: disable=no-member
            extend_enum(RouterAlert, key, default)
        return RouterAlert[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 70 <= value <= 65502:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        if 65503 <= value <= 65534:
            #: Reserved for experimental use [:rfc:`5350`]
            extend_enum(cls, 'Reserved for experimental use_%d' % value, value)
            return cls(value)
        return super()._missing_(value)
