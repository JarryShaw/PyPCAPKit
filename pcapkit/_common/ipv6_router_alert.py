# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class RT_ALT(IntEnum):
    """Enumeration class for RT_ALT."""
    _ignore_ = 'RT_ALT _'
    RT_ALT = vars()

    # IPv6 Router Alert Option Values
    RT_ALT['Datagram contains a Multicast Listener Discovery message'] = 0      # [RFC 2710]
    RT_ALT['Datagram contains RSVP message'] = 1                                # [RFC 2711]
    RT_ALT['Datagram contains an Active Networks message'] = 2                  # [RFC 2711]
    RT_ALT['Reserved [3]'] = 3                                                  # [RFC 5350]
    RT_ALT['Aggregated Reservation Nesting Level 0'] = 4                        # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 1'] = 5                        # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 2'] = 6                        # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 3'] = 7                        # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 4'] = 8                        # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 5'] = 9                        # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 6'] = 10                       # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 7'] = 11                       # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 8'] = 12                       # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 9'] = 13                       # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 10'] = 14                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 11'] = 15                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 12'] = 16                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 13'] = 17                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 14'] = 18                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 15'] = 19                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 16'] = 20                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 17'] = 21                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 18'] = 22                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 19'] = 23                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 20'] = 24                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 21'] = 25                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 22'] = 26                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 23'] = 27                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 24'] = 28                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 25'] = 29                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 26'] = 30                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 27'] = 31                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 28'] = 32                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 29'] = 33                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 30'] = 34                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 31'] = 35                      # [RFC 3175]
    RT_ALT['QoS NSLP Aggregation Level 0'] = 36                                 # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 1'] = 37                                 # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 2'] = 38                                 # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 3'] = 39                                 # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 4'] = 40                                 # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 5'] = 41                                 # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 6'] = 42                                 # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 7'] = 43                                 # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 8'] = 44                                 # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 9'] = 45                                 # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 10'] = 46                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 11'] = 47                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 12'] = 48                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 13'] = 49                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 14'] = 50                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 15'] = 51                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 16'] = 52                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 17'] = 53                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 18'] = 54                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 19'] = 55                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 20'] = 56                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 21'] = 57                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 22'] = 58                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 23'] = 59                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 24'] = 60                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 25'] = 61                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 26'] = 62                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 27'] = 63                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 28'] = 64                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 29'] = 65                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 30'] = 66                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 31'] = 67                                # [RFC 5974]
    RT_ALT['NSIS NATFW NSLP'] = 68                                              # [RFC 5973]
    RT_ALT['MPLS OAM'] = 69                                                     # [RFC 7506]
    RT_ALT['Reserved [65535]'] = 65535                                          # [The Internet Assigned Numbers Authority]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return RT_ALT(key)
        if key not in RT_ALT._member_map_:
            extend_enum(RT_ALT, key, default)
        return RT_ALT[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 70 <= value <= 65502:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 65503 <= value <= 65534:
            # [RFC 5350]
            extend_enum(cls, 'Reserved for experimental use [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
