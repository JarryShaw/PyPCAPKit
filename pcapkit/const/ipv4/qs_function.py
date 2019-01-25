# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class QS_Function(IntEnum):
    """Enumeration class for QS_Function."""
    _ignore_ = 'QS_Function _'
    QS_Function = vars()

    # QS Functions
    QS_Function['Quick-Start Request'] = 0
    QS_Function['Report of Approved Rate'] = 8

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return QS_Function(key)
        if key not in QS_Function._member_map_:
            extend_enum(QS_Function, key, default)
        return QS_Function[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 8):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
        super()._missing_(value)
