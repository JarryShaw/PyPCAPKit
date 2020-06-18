# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""HIP NAT Traversal Modes"""

from aenum import IntEnum, extend_enum

__all__ = ['NATTraversal']


class NATTraversal(IntEnum):
    """[NATTraversal] HIP NAT Traversal Modes"""

    #: Reserved [:rfc:`5770`]
    Reserved = 0

    #: UDP-ENCAPSULATION [:rfc:`5770`]
    UDP_ENCAPSULATION = 1

    #: ICE-STUN-UDP [:rfc:`5770`]
    ICE_STUN_UDP = 2

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return NATTraversal(key)
        if key not in NATTraversal._member_map_:  # pylint: disable=no-member
            extend_enum(NATTraversal, key, default)
        return NATTraversal[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 3 <= value <= 65535:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        return super()._missing_(value)
