# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class RegType(IntEnum):
    """Enumeration class for RegType."""
    _ignore_ = 'RegType _'
    RegType = vars()

    # Registration Types
    RegType['Unassigned'] = 0
    RegType['RENDEZVOUS'] = 1                                                   # [RFC 8004]
    RegType['RELAY_UDP_HIP'] = 2                                                # [RFC 5770]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return RegType(key)
        if key not in RegType._member_map_:
            extend_enum(RegType, key, default)
        return RegType[key]

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
