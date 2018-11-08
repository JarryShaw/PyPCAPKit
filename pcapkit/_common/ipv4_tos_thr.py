# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class Throughput(IntEnum):
    """Enumeration class for Throughput."""
    _ignore_ = 'Throughput _'
    Throughput = vars()

    # TOS (DS Field) Throughput
    Throughput['NORMAL'] = 0
    Throughput['HIGH'] = 1

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Throughput(key)
        if key not in Throughput._member_map_:
            extend_enum(Throughput, key, default)
        return Throughput[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 1):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
