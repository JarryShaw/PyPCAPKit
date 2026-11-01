# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""ICMPv6 Parameter Problem Codes
====================================

.. module:: pcapkit.const.icmpv6.parameter_problem_code

This module contains the constant enumeration for **ICMPv6 Parameter Problem Codes**,
which is automatically generated from :class:`pcapkit.vendor.icmpv6.parameter_problem_code.ParameterProblemCode`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['ParameterProblemCode']


class ParameterProblemCode(EnumRegistry, IntEnum):
    """[ParameterProblemCode] ICMPv6 Parameter Problem Codes [:rfc:`4443`][:rfc:`7112`]"""

    #: erroneous header field encountered
    erroneous_header_field_encountered = 0

    #: unrecognized Next Header type encountered
    unrecognized_Next_Header_type_encountered = 1

    #: unrecognized IPv6 option encountered
    unrecognized_IPv6_option_encountered = 2

    #: IPv6 First Fragment has incomplete IPv6 Header Chain [:rfc:`7112`]
    IPv6_First_Fragment_has_incomplete_IPv6_Header_Chain = 3

    #: SR Upper-layer Header Error [:rfc:`8754`]
    SR_Upper_layer_Header_Error = 4

    #: Unrecognized Next Header type encountered by intermediate node [:rfc:`8883`]
    Unrecognized_Next_Header_type_encountered_by_intermediate_node = 5

    #: Extension header too big [:rfc:`8883`]
    Extension_header_too_big = 6

    #: Extension header chain too long [:rfc:`8883`]
    Extension_header_chain_too_long = 7

    #: Too many extension headers [:rfc:`8883`]
    Too_many_extension_headers = 8

    #: Too many options in extension header [:rfc:`8883`]
    Too_many_options_in_extension_header = 9

    #: Option too big [:rfc:`8883`]
    Option_too_big = 10

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
