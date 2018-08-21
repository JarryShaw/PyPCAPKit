# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class RT_TYPE(IntEnum):
    """Enumeration class for RT_TYPE."""
    _ignore_ = 'RT_TYPE _'
    RT_TYPE = vars()

    # IPv6 Routing Types
    RT_TYPE['Source Route'] = 0                                                 # [IPV6][RFC 5095] DEPRECATED
    RT_TYPE['Nimrod'] = 1                                                       # DEPRECATED 2009-05-06
    RT_TYPE['Type 2 Routing Header'] = 2                                        # [RFC 6275]
    RT_TYPE['RPL Source Route Header'] = 3                                      # [RFC 6554]
    RT_TYPE['RFC3692-style Experiment 1'] = 253                                 # [RFC 4727]
    RT_TYPE['RFC3692-style Experiment 2'] = 254                                 # [RFC 4727]
    RT_TYPE['Reserved'] = 255

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return RT_TYPE(key)
        if key not in RT_TYPE._member_map_:
            extend_enum(RT_TYPE, key, default)
        return RT_TYPE[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 4 <= value <= 252:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
