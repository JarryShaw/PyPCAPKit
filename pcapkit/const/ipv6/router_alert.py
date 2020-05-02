# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""IPv6 Router Alert Option Values"""

from aenum import IntEnum, extend_enum

__all__ = ['RouterAlert']


class RouterAlert(IntEnum):
    """[RouterAlert] IPv6 Router Alert Option Values"""

    _ignore_ = 'RouterAlert _'
    RouterAlert = vars()

    #: [:rfc:`2710`]
    RouterAlert['Datagram_Contains_A_Multicast_Listener_Discovery_Message'] = 0

    #: [:rfc:`2711`]
    RouterAlert['Datagram_Contains_RSVP_Message'] = 1

    #: [:rfc:`2711`]
    RouterAlert['Datagram_Contains_An_Active_Networks_Message'] = 2

    #: [:rfc:`5350`]
    RouterAlert['Reserved_3'] = 3

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_0'] = 4

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_1'] = 5

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_2'] = 6

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_3'] = 7

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_4'] = 8

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_5'] = 9

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_6'] = 10

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_7'] = 11

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_8'] = 12

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_9'] = 13

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_10'] = 14

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_11'] = 15

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_12'] = 16

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_13'] = 17

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_14'] = 18

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_15'] = 19

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_16'] = 20

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_17'] = 21

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_18'] = 22

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_19'] = 23

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_20'] = 24

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_21'] = 25

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_22'] = 26

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_23'] = 27

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_24'] = 28

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_25'] = 29

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_26'] = 30

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_27'] = 31

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_28'] = 32

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_29'] = 33

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_30'] = 34

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_31'] = 35

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_0'] = 36

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_1'] = 37

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_2'] = 38

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_3'] = 39

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_4'] = 40

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_5'] = 41

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_6'] = 42

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_7'] = 43

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_8'] = 44

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_9'] = 45

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_10'] = 46

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_11'] = 47

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_12'] = 48

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_13'] = 49

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_14'] = 50

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_15'] = 51

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_16'] = 52

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_17'] = 53

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_18'] = 54

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_19'] = 55

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_20'] = 56

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_21'] = 57

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_22'] = 58

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_23'] = 59

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_24'] = 60

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_25'] = 61

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_26'] = 62

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_27'] = 63

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_28'] = 64

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_29'] = 65

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_30'] = 66

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_31'] = 67

    #: [:rfc:`5973`]
    RouterAlert['NSIS_NATFW_NSLP'] = 68

    #: [:rfc:`7506`]
    RouterAlert['MPLS_OAM'] = 69

    #: [The Internet Assigned Numbers Authority]
    RouterAlert['Reserved_65535'] = 65535

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
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 65503 <= value <= 65534:
            #: [:rfc:`5350`]
            extend_enum(cls, 'Reserved for experimental use [%d]' % value, value)
            return cls(value)
        return super()._missing_(value)
