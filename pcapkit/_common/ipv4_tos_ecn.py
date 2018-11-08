# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class ECN(IntEnum):
    """Enumeration class for ECN."""
    _ignore_ = 'ECN _'
    ECN = vars()

    # TOS ECN FIELD
    ECN['Not-ECT'] = 0b00
    ECN['ECT(1)'] = 0b01
    ECN['ECT(0)'] = 0b10
    ECN['CE'] = 0b11

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ECN(key)
        if key not in ECN._member_map_:
            extend_enum(ECN, key, default)
        return ECN[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0b00 <= value <= 0b11):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [0b%s]' % bin(value)[2:].zfill(2), value)
        return cls(value)
