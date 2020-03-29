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
    RouterAlert['Datagram contains a Multicast Listener Discovery message'] = 0

    #: [:rfc:`2711`]
    RouterAlert['Datagram contains RSVP message'] = 1

    #: [:rfc:`2711`]
    RouterAlert['Datagram contains an Active Networks message'] = 2

    #: [:rfc:`5350`]
    RouterAlert['Reserved [3]'] = 3

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 0'] = 4

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 1'] = 5

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 2'] = 6

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 3'] = 7

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 4'] = 8

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 5'] = 9

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 6'] = 10

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 7'] = 11

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 8'] = 12

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 9'] = 13

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 10'] = 14

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 11'] = 15

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 12'] = 16

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 13'] = 17

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 14'] = 18

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 15'] = 19

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 16'] = 20

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 17'] = 21

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 18'] = 22

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 19'] = 23

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 20'] = 24

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 21'] = 25

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 22'] = 26

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 23'] = 27

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 24'] = 28

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 25'] = 29

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 26'] = 30

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 27'] = 31

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 28'] = 32

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 29'] = 33

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 30'] = 34

    #: [:rfc:`3175`]
    RouterAlert['Aggregated Reservation Nesting Level 31'] = 35

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 0'] = 36

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 1'] = 37

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 2'] = 38

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 3'] = 39

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 4'] = 40

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 5'] = 41

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 6'] = 42

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 7'] = 43

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 8'] = 44

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 9'] = 45

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 10'] = 46

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 11'] = 47

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 12'] = 48

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 13'] = 49

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 14'] = 50

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 15'] = 51

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 16'] = 52

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 17'] = 53

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 18'] = 54

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 19'] = 55

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 20'] = 56

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 21'] = 57

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 22'] = 58

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 23'] = 59

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 24'] = 60

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 25'] = 61

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 26'] = 62

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 27'] = 63

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 28'] = 64

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 29'] = 65

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 30'] = 66

    #: [:rfc:`5974`]
    RouterAlert['QoS NSLP Aggregation Level 31'] = 67

    #: [:rfc:`5973`]
    RouterAlert['NSIS NATFW NSLP'] = 68

    #: [:rfc:`7506`]
    RouterAlert['MPLS OAM'] = 69

    #: [The Internet Assigned Numbers Authority]
    RouterAlert['Reserved [65535]'] = 65535

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
