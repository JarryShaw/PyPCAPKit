# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""DNS OpCodes
=================

.. module:: pcapkit.const.dns.opcode

This module contains the constant enumeration for **DNS OpCodes**,
which is automatically generated from :class:`pcapkit.vendor.dns.opcode.Opcode`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['Opcode']


class Opcode(EnumRegistry, IntEnum):
    """[Opcode] DNS OpCodes"""

    #: Query [:rfc:`1035`]
    Query = 0

    #: IQuery  (Inverse Query, OBSOLETE) [:rfc:`3425`]
    IQuery = 1

    #: Status [:rfc:`1035`]
    Status = 2

    #: Unassigned
    Unassigned_3 = 3

    #: Notify [:rfc:`1996`]
    Notify = 4

    #: Update [:rfc:`2136`]
    Update = 5

    #: DNS Stateful Operations (DSO) [:rfc:`8490`]
    DSO = 6

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
        if not (isinstance(value, int) and 0 <= value <= 15):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'Opcode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 15):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 7 <= value <= 15:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
