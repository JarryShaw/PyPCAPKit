# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HIP NAT Traversal Modes
=============================

.. module:: pcapkit.const.hip.nat_traversal

This module contains the constant enumeration for **HIP NAT Traversal Modes**,
which is automatically generated from :class:`pcapkit.vendor.hip.nat_traversal.NATTraversal`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['NATTraversal']


class NATTraversal(IntEnum):
    """[NATTraversal] HIP NAT Traversal Modes"""

    #: Reserved [:rfc:`5770`]
    Reserved_0 = 0

    #: UDP-ENCAPSULATION [:rfc:`5770`]
    UDP_ENCAPSULATION = 1

    #: ICE-STUN-UDP [:rfc:`5770`]
    ICE_STUN_UDP = 2

    #: ICE-HIP-UDP [:rfc:`9028`]
    ICE_HIP_UDP = 3

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'NATTraversal':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return NATTraversal(key)
        if key not in NATTraversal._member_map_:  # pylint: disable=no-member
            return extend_enum(NATTraversal, key, default)
        return NATTraversal[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'NATTraversal':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 4 <= value <= 65535:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
