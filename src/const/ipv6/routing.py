# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class Routing(IntEnum):
    """Enumeration class for Routing."""
    _ignore_ = 'Routing _'
    Routing = vars()

    # IPv6 Routing Types
    Routing['Source Route'] = 0                                                 # [IPV6][RFC 5095] DEPRECATED
    Routing['Nimrod'] = 1                                                       # DEPRECATED 2009-05-06
    Routing['Type 2 Routing Header'] = 2                                        # [RFC 6275]
    Routing['RPL Source Route Header'] = 3                                      # [RFC 6554]
    Routing['RFC3692-style Experiment 1'] = 253                                 # [RFC 4727]
    Routing['RFC3692-style Experiment 2'] = 254                                 # [RFC 4727]
    Routing['Reserved'] = 255

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Routing(key)
        if key not in Routing._member_map_:
            extend_enum(Routing, key, default)
        return Routing[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 4 <= value <= 252:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
