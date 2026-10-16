# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Registration Types
========================

.. module:: pcapkit.const.hip.registration

This module contains the constant enumeration for **Registration Types**,
which is automatically generated from :class:`pcapkit.vendor.hip.registration.Registration`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['Registration']


class Registration(EnumRegistry, IntEnum):
    """[Registration] Registration Types"""

    #: Unassigned
    Unassigned_0 = 0

    #: RENDEZVOUS [:rfc:`8004`]
    RENDEZVOUS = 1

    #: RELAY_UDP_HIP [:rfc:`5770`]
    RELAY_UDP_HIP = 2

    #: RELAY_UDP_ESP [:rfc:`9028`]
    RELAY_UDP_ESP = 3

    #: CANDIDATE_DISCOVERY [:rfc:`9028`]
    CANDIDATE_DISCOVERY = 4

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
    def _missing_(cls, value: 'int') -> 'Registration':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 5 <= value <= 200:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 201 <= value <= 255:
            #: Reserved for Private Use [:rfc:`8003`]
            return cls._unregistered_member(value, 'Reserved_for_Private_Use')
        return super()._missing_(value)
