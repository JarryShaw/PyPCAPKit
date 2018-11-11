# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class NAT_Traversal(IntEnum):
    """Enumeration class for NAT_Traversal."""
    _ignore_ = 'NAT_Traversal _'
    NAT_Traversal = vars()

    # HIP NAT Traversal Modes
    NAT_Traversal['Reserved'] = 0                                               # [RFC 5770]
    NAT_Traversal['UDP-ENCAPSULATION'] = 1                                      # [RFC 5770]
    NAT_Traversal['ICE-STUN-UDP'] = 2                                           # [RFC 5770]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return NAT_Traversal(key)
        if key not in NAT_Traversal._member_map_:
            extend_enum(NAT_Traversal, key, default)
        return NAT_Traversal[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 3 <= value <= 65535:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
