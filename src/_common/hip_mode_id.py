# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class ModeID(IntEnum):
    """Enumeration class for ModeID."""
    _ignore_ = 'ModeID _'
    ModeID = vars()

    # HIP NAT Traversal Modes
    ModeID['Reserved'] = 0                                                      # [RFC 5770]
    ModeID['UDP-ENCAPSULATION'] = 1                                             # [RFC 5770]
    ModeID['ICE-STUN-UDP'] = 2                                                  # [RFC 5770]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ModeID(key)
        if key not in ModeID._member_map_:
            extend_enum(ModeID, key, default)
        return ModeID[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 3 <= value <= 65535:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
