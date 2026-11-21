# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""DNS CLASSes
=================

.. module:: pcapkit.const.dns.rr_class

This module contains the constant enumeration for **DNS CLASSes**,
which is automatically generated from :class:`pcapkit.vendor.dns.rr_class.RRClass`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['RRClass']


class RRClass(EnumRegistry, IntEnum):
    """[RRClass] DNS CLASSes"""

    #: Reserved [:rfc:`6895`]
    Reserved_0 = 0

    #: Internet (IN) [:rfc:`1035`]
    IN = 1

    #: Unassigned
    Unassigned_2 = 2

    #: Chaos (CH) [D. Moon, "Chaosnet", A.I. Memo 628, Massachusetts Institute of
    #: Technology Artificial Intelligence Laboratory, June 1981.]
    CH = 3

    #: Hesiod (HS) [Dyer, S., and F. Hsu, "Hesiod", Project Athena Technical Plan -
    #: Name Service, April 1987.]
    HS = 4

    #: QCLASS NONE [:rfc:`2136`]
    NONE = 254

    #: QCLASS * (ANY) [:rfc:`1035`]
    ANY = 255

    #: Reserved [:rfc:`6895`]
    Reserved_65535 = 65535

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
    def _missing_(cls, value: 'int') -> 'RRClass':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 5 <= value <= 253:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 256 <= value <= 65279:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 65280 <= value <= 65534:
            #: Reserved for Private Use [:rfc:`6895`]
            return cls._unregistered_member(value, 'Reserved_for_Private_Use')
        return super()._missing_(value)
