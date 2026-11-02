# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""DCCP Option Types
=======================

.. module:: pcapkit.const.dccp.option

This module contains the constant enumeration for **DCCP Option Types**,
which is automatically generated from :class:`pcapkit.vendor.dccp.option.Option`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['Option']


class Option(EnumRegistry, IntEnum):
    """[Option] DCCP Option Types"""

    #: Padding [:rfc:`4340`]
    Padding = 0

    #: Mandatory [:rfc:`4340`]
    Mandatory = 1

    #: Slow Receiver [:rfc:`4340`]
    Slow_Receiver = 2

    #: Reserved for experimental and testing use [:rfc:`4340`]
    Reserved_for_experimental_and_testing_use = 31

    #: Change L [:rfc:`4340`]
    Change_L = 32

    #: Confirm L [:rfc:`4340`]
    Confirm_L = 33

    #: Change R [:rfc:`4340`]
    Change_R = 34

    #: Confirm R [:rfc:`4340`]
    Confirm_R = 35

    #: Init Cookie [:rfc:`4340`]
    Init_Cookie = 36

    #: NDP Count [:rfc:`4340`]
    NDP_Count = 37

    #: Ack Vector [Nonce 0] [:rfc:`4340`]
    Ack_Vector_Nonce_0 = 38

    #: Ack Vector [Nonce 1] [:rfc:`4340`]
    Ack_Vector_Nonce_1 = 39

    #: Data Dropped [:rfc:`4340`]
    Data_Dropped = 40

    #: Timestamp [:rfc:`4340`]
    Timestamp = 41

    #: Timestamp Echo [:rfc:`4340`]
    Timestamp_Echo = 42

    #: Elapsed Time [:rfc:`4340`]
    Elapsed_Time = 43

    #: Data Checksum [:rfc:`4340`]
    Data_Checksum = 44

    #: Quick-Start Response [:rfc:`5634`]
    Quick_Start_Response = 45

    #: Multipath [:rfc:`9897`]
    Multipath = 46

    #: Unassigned [:rfc:`4340`]
    Unassigned_127 = 127

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
    def _missing_(cls, value: 'int') -> 'Option':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 3 <= value <= 30:
            #: Unassigned [:rfc:`4340`]
            return cls._unregistered_member(value, 'Unassigned')
        if 47 <= value <= 119:
            #: Unassigned [:rfc:`4340`]
            return cls._unregistered_member(value, 'Unassigned')
        if 120 <= value <= 126:
            #: Reserved [:rfc:`4340`]
            return cls._unregistered_member(value, 'Reserved')
        if 128 <= value <= 255:
            #: CCID-specific codes [:rfc:`4340`]
            return cls._unregistered_member(value, 'CCID_specific_codes')
        return super()._missing_(value)
