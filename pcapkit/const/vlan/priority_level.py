# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Priority levels defined in IEEE 802.1p."""

from aenum import IntEnum, extend_enum

__all__ = ['PriorityLevel']


class PriorityLevel(IntEnum):
    """[PriorityLevel] Priority levels defined in IEEE 802.1p."""

    #: ``0`` - Background (lowest)
    BK = 0b001

    #: ``1`` - Best effort (default)
    BE = 0b000

    #: ``2`` - Excellent effort
    EE = 0b010

    #: ``3`` - Critical applications
    CA = 0b011

    #: ``4`` - Video, < 100 ms latency and jitter
    VI = 0b100

    #: ``5`` - Voice, < 10 ms latency and jitter
    VO = 0b101

    #: ``6`` - Internetwork control
    IC = 0b110

    #: ``7`` - Network control (highest)
    NC = 0b111

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return PriorityLevel(key)
        if key not in PriorityLevel._member_map_:  # pylint: disable=no-member
            extend_enum(PriorityLevel, key, default)
        return PriorityLevel[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0b000 <= value <= 0b111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [0b%s]' % bin(value)[2:].zfill(3), value)
        return cls(value)
