# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""IPv4 Router Alert Option Values"""

from aenum import IntEnum, extend_enum

__all__ = ['RouterAlert']


class RouterAlert(IntEnum):
    """[RouterAlert] IPv4 Router Alert Option Values"""

    _ignore_ = 'RouterAlert _'
    RouterAlert = vars()

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_0'] = 1

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_1'] = 2

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_2'] = 3

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_3'] = 4

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_4'] = 5

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_5'] = 6

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_6'] = 7

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_7'] = 8

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_8'] = 9

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_9'] = 10

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_10'] = 11

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_11'] = 12

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_12'] = 13

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_13'] = 14

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_14'] = 15

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_15'] = 16

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_16'] = 17

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_17'] = 18

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_18'] = 19

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_19'] = 20

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_20'] = 21

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_21'] = 22

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_22'] = 23

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_23'] = 24

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_24'] = 25

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_25'] = 26

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_26'] = 27

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_27'] = 28

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_28'] = 29

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_29'] = 30

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_30'] = 31

    #: [:rfc:`3175`]
    RouterAlert['Aggregated_Reservation_Nesting_Level_31'] = 32

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_0'] = 33

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_1'] = 34

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_2'] = 35

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_3'] = 36

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_4'] = 37

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_5'] = 38

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_6'] = 39

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_7'] = 40

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_8'] = 41

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_9'] = 42

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_10'] = 43

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_11'] = 44

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_12'] = 45

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_13'] = 46

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_14'] = 47

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_15'] = 48

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_16'] = 49

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_17'] = 50

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_18'] = 51

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_19'] = 52

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_20'] = 53

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_21'] = 54

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_22'] = 55

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_23'] = 56

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_24'] = 57

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_25'] = 58

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_26'] = 59

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_27'] = 60

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_28'] = 61

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_29'] = 62

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_30'] = 63

    #: [:rfc:`5974`]
    RouterAlert['QoS_NSLP_Aggregation_Level_31'] = 64

    #: [:rfc:`5973`]
    RouterAlert['NSIS_NATFW_NSLP'] = 65

    #: [:rfc:`5350`]
    RouterAlert['Reserved'] = 65535

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
        if 66 <= value <= 65502:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 65503 <= value <= 65534:
            #: [:rfc:`5350`]
            extend_enum(cls, 'Reserved for experimental use [%d]' % value, value)
            return cls(value)
        return super()._missing_(value)
