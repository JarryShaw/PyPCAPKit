# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Router Selection Preferences
==================================

.. module:: pcapkit.const.icmpv6.router_preference

This module contains the constant enumeration for **Router Selection Preferences**,
which is automatically generated from :class:`pcapkit.vendor.icmpv6.router_preference.RouterPreference`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['RouterPreference']


class RouterPreference(EnumRegistry, IntEnum):
    """[RouterPreference] Router Selection Preferences [:rfc:`4191`]"""

    #: Medium [:rfc:`4191#section-2.1`]
    Medium = 0

    #: High [:rfc:`4191#section-2.1`]
    High = 1

    #: Reserved [:rfc:`4191#section-2.1`]
    Reserved_2 = 2

    #: Low [:rfc:`4191#section-2.1`]
    Low = 3

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
        if not (isinstance(value, int) and 0 <= value <= 3):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'RouterPreference':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 3):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')
