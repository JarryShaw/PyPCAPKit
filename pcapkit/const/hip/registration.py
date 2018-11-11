# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class Registration(IntEnum):
    """Enumeration class for Registration."""
    _ignore_ = 'Registration _'
    Registration = vars()

    # Registration Types
    Registration['Unassigned'] = 0
    Registration['RENDEZVOUS'] = 1                                              # [RFC 8004]
    Registration['RELAY_UDP_HIP'] = 2                                           # [RFC 5770]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Registration(key)
        if key not in Registration._member_map_:
            extend_enum(Registration, key, default)
        return Registration[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 3 <= value <= 200:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        if 201 <= value <= 255:
            # [RFC 8003]
            extend_enum(cls, 'Reserved for Private Use [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
