# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Mobile Node Group Identifier Type Registry
================================================

.. module:: pcapkit.const.mh.mn_group_id

This module contains the constant enumeration for **Mobile Node Group Identifier Type Registry**,
which is automatically generated from :class:`pcapkit.vendor.mh.mn_group_id.MNGroupID`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['MNGroupID']


class MNGroupID(EnumRegistry, IntEnum):
    """[MNGroupID] Mobile Node Group Identifier Type Registry"""

    #: Reserved [:rfc:`6602`]
    Reserved_0 = 0

    #: Bulk Binding Update Group [:rfc:`6602`]
    Bulk_Binding_Update_Group = 1

    #: Reserved [:rfc:`6602`]
    Reserved_255 = 255

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
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'MNGroupID':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 2 <= value <= 254:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
