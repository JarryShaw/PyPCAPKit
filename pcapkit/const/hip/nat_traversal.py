# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HIP NAT Traversal Modes
=============================

.. module:: pcapkit.const.hip.nat_traversal

This module contains the constant enumeration for **HIP NAT Traversal Modes**,
which is automatically generated from :class:`pcapkit.vendor.hip.nat_traversal.NATTraversal`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['NATTraversal']


class NATTraversal(EnumRegistry, IntEnum):
    """[NATTraversal] HIP NAT Traversal Modes"""

    #: Reserved [:rfc:`5770`]
    Reserved_0 = 0

    #: UDP-ENCAPSULATION [:rfc:`5770`]
    UDP_ENCAPSULATION = 1

    #: ICE-STUN-UDP [:rfc:`5770`]
    ICE_STUN_UDP = 2

    #: ICE-HIP-UDP [:rfc:`9028`]
    ICE_HIP_UDP = 3

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it passes the range check :meth:`_missing_` makes.

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value`
        with that check and the message it raises, so
        :meth:`~pcapkit.corekit.enum.EnumRegistry.register` refuses exactly the
        values :meth:`~pcapkit.corekit.enum.EnumLookup.get` refuses, in the
        same words (:issue:`1816`).

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` fails that check. A
                :exc:`ValueError`, so an ``except ValueError`` caller is
                unaffected.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

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
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
