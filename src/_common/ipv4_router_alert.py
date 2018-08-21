# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class RT_ALT(IntEnum):
    """Enumeration class for RT_ALT."""
    _ignore_ = 'RT_ALT _'
    RT_ALT = vars()

    # IPv4 Router Alert Option Values
    RT_ALT['Aggregated Reservation Nesting Level 0'] = 1                        # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 1'] = 2                        # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 2'] = 3                        # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 3'] = 4                        # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 4'] = 5                        # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 5'] = 6                        # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 6'] = 7                        # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 7'] = 8                        # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 8'] = 9                        # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 9'] = 10                       # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 10'] = 11                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 11'] = 12                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 12'] = 13                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 13'] = 14                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 14'] = 15                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 15'] = 16                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 16'] = 17                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 17'] = 18                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 18'] = 19                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 19'] = 20                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 20'] = 21                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 21'] = 22                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 22'] = 23                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 23'] = 24                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 24'] = 25                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 25'] = 26                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 26'] = 27                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 27'] = 28                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 28'] = 29                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 29'] = 30                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 30'] = 31                      # [RFC 3175]
    RT_ALT['Aggregated Reservation Nesting Level 31'] = 32                      # [RFC 3175]
    RT_ALT['QoS NSLP Aggregation Level 0'] = 33                                 # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 1'] = 34                                 # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 2'] = 35                                 # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 3'] = 36                                 # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 4'] = 37                                 # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 5'] = 38                                 # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 6'] = 39                                 # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 7'] = 40                                 # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 8'] = 41                                 # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 9'] = 42                                 # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 10'] = 43                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 11'] = 44                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 12'] = 45                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 13'] = 46                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 14'] = 47                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 15'] = 48                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 16'] = 49                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 17'] = 50                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 18'] = 51                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 19'] = 52                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 20'] = 53                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 21'] = 54                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 22'] = 55                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 23'] = 56                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 24'] = 57                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 25'] = 58                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 26'] = 59                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 27'] = 60                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 28'] = 61                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 29'] = 62                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 30'] = 63                                # [RFC 5974]
    RT_ALT['QoS NSLP Aggregation Level 31'] = 64                                # [RFC 5974]
    RT_ALT['NSIS NATFW NSLP'] = 65                                              # [RFC 5973]
    RT_ALT['Reserved'] = 65535                                                  # [RFC 5350]

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
        if 66 <= value <= 65502:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 65503 <= value <= 65534:
            # [RFC 5350]
            extend_enum(cls, 'Reserved for experimental use [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
