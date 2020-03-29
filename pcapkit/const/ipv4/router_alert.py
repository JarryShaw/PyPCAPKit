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
    RouterAlert['Aggregated Reservation Nesting Level 0'] = 1

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 1'] = 2

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 2'] = 3

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 3'] = 4

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 4'] = 5

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 5'] = 6

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 6'] = 7

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 7'] = 8

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 8'] = 9

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 9'] = 10

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 10'] = 11

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 11'] = 12

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 12'] = 13

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 13'] = 14

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 14'] = 15

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 15'] = 16

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 16'] = 17

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 17'] = 18

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 18'] = 19

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 19'] = 20

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 20'] = 21

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 21'] = 22

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 22'] = 23

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 23'] = 24

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 24'] = 25

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 25'] = 26

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 26'] = 27

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 27'] = 28

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 28'] = 29

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 29'] = 30

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 30'] = 31

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 31'] = 32

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 0'] = 33

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 1'] = 34

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 2'] = 35

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 3'] = 36

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 4'] = 37

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 5'] = 38

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 6'] = 39

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 7'] = 40

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 8'] = 41

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 9'] = 42

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 10'] = 43

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 11'] = 44

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 12'] = 45

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 13'] = 46

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 14'] = 47

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 15'] = 48

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 16'] = 49

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 17'] = 50

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 18'] = 51

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 19'] = 52

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 20'] = 53

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 21'] = 54

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 22'] = 55

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 23'] = 56

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 24'] = 57

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 25'] = 58

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 26'] = 59

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 27'] = 60

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 28'] = 61

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 29'] = 62

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 30'] = 63

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 31'] = 64

    #: [:rfc:`5973`]
    RouterAlert['NSIS NATFW NSLP'] = 65

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
