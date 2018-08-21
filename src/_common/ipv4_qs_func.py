# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class QS(IntEnum):
    """Enumeration class for QS."""
    _ignore_ = 'QS _'
    QS = vars()

    # QS Functions
    QS['Quick-Start Request'] = 0
    QS['Report of Approved Rate'] = 8

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return QS(key)
        if key not in QS._member_map_:
            extend_enum(QS, key, default)
        return QS[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 8):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
