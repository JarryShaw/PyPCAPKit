# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""ICMP Parameter Problem Codes
==================================

.. module:: pcapkit.const.icmp.parameter_problem_code

This module contains the constant enumeration for **ICMP Parameter Problem Codes**,
which is automatically generated from :class:`pcapkit.vendor.icmp.parameter_problem_code.ParameterProblemCode`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['ParameterProblemCode']


class ParameterProblemCode(EnumRegistry, IntEnum):
    """[ParameterProblemCode] ICMP Parameter Problem Codes [:rfc:`792`][:rfc:`1108`]"""

    #: Pointer indicates the error
    Pointer_indicates_the_error = 0

    #: Missing a Required Option [:rfc:`1108`]
    Missing_a_Required_Option = 1

    #: Bad Length
    Bad_Length = 2

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
    def _missing_(cls, value: 'int') -> 'ParameterProblemCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')
