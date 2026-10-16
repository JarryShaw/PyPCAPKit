# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Registration Failure Types
================================

.. module:: pcapkit.const.hip.registration_failure

This module contains the constant enumeration for **Registration Failure Types**,
which is automatically generated from :class:`pcapkit.vendor.hip.registration_failure.RegistrationFailure`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['RegistrationFailure']


class RegistrationFailure(EnumRegistry, IntEnum):
    """[RegistrationFailure] Registration Failure Types"""

    #: Registration requires additional credentials [:rfc:`8003`]
    Registration_requires_additional_credentials = 0

    #: Registration type unavailable [:rfc:`8003`]
    Registration_type_unavailable = 1

    #: Insufficient resources [:rfc:`8003`]
    Insufficient_resources = 2

    #: Invalid certificate [:rfc:`8003`]
    Invalid_certificate = 3

    #: Bad certificate [:rfc:`8003`]
    Bad_certificate = 4

    #: Unsupported certificate [:rfc:`8003`]
    Unsupported_certificate = 5

    #: Certificate expired [:rfc:`8003`]
    Certificate_expired = 6

    #: Certificate other [:rfc:`8003`]
    Certificate_other = 7

    #: Unknown CA [:rfc:`8003`]
    Unknown_CA = 8

    #: Simultaneous Rendezvous and Control Relay Service usage prohibited
    #: [:rfc:`9028`]
    Simultaneous_Rendezvous_and_Control_Relay_Service_usage_prohibited = 9

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
    def _missing_(cls, value: 'int') -> 'RegistrationFailure':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 10 <= value <= 200:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 201 <= value <= 255:
            #: Reserved for Private Use [:rfc:`8003`]
            return cls._unregistered_member(value, 'Reserved_for_Private_Use')
        return super()._missing_(value)
