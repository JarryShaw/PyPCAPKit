# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Classification Level Encodings
====================================

.. module:: pcapkit.const.ipv4.classification_level

This module contains the constant enumeration for **Classification Level Encodings**,
which is automatically generated from :class:`pcapkit.vendor.ipv4.classification_level.ClassificationLevel`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['ClassificationLevel']


class ClassificationLevel(EnumRegistry, IntEnum):
    """[ClassificationLevel] Classification Level Encodings"""

    Reserved_4 = 0b00000001

    Top_Secret = 0b00111101

    Secret = 0b01011010

    Confidential = 0b10010110

    Reserved_3 = 0b01100110

    Reserved_2 = 0b11001100

    Unclassified = 0b10101011

    Reserved_1 = 0b11110001

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
        if not (isinstance(value, int) and 0b00000000 <= value <= 0b11111111):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'ClassificationLevel':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0b00000000 <= value <= 0b11111111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')
