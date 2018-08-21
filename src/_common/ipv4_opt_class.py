# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class OptCls(IntEnum):
    """Enumeration class for OptCls."""
    _ignore_ = 'OptCls _'
    OptCls = vars()

    # Option Classes
    OptCls['control'] = 0
    OptCls['reserved for future use [1]'] = 1
    OptCls['debugging and measurement'] = 2
    OptCls['reserved for future use [3]'] = 3

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return OptCls(key)
        if key not in OptCls._member_map_:
            extend_enum(OptCls, key, default)
        return OptCls[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 3):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
