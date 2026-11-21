# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""DNS RCODEs
================

.. module:: pcapkit.const.dns.rcode

This module contains the constant enumeration for **DNS RCODEs**,
which is automatically generated from :class:`pcapkit.vendor.dns.rcode.RCode`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['RCode']


class RCode(EnumRegistry, IntEnum):
    """[RCode] DNS RCODEs"""

    #: NoError -- No Error [:rfc:`1035`]
    NoError = 0

    #: FormErr -- Format Error [:rfc:`1035`]
    FormErr = 1

    #: ServFail -- Server Failure [:rfc:`1035`]
    ServFail = 2

    #: NXDomain -- Non-Existent Domain [:rfc:`1035`]
    NXDomain = 3

    #: NotImp -- Not Implemented [:rfc:`1035`]
    NotImp = 4

    #: Refused -- Query Refused [:rfc:`1035`]
    Refused = 5

    #: YXDomain -- Name Exists when it should not [:rfc:`2136`][:rfc:`6672`]
    YXDomain = 6

    #: YXRRSet -- RR Set Exists when it should not [:rfc:`2136`]
    YXRRSet = 7

    #: NXRRSet -- RR Set that should exist does not [:rfc:`2136`]
    NXRRSet = 8

    #: NotAuth -- Server Not Authoritative for zone [:rfc:`2136`]; Not Authorized
    #: [:rfc:`8945`]
    NotAuth = 9

    #: NotZone -- Name not contained in zone [:rfc:`2136`]
    NotZone = 10

    #: DSOTYPENI -- DSO-TYPE Not Implemented [:rfc:`8490`]
    DSOTYPENI = 11

    #: BADVERS -- Bad OPT Version [:rfc:`6891`]
    BADVERS = 16

    #: BADSIG -- TSIG Signature Failure [:rfc:`8945`]
    BADSIG = 16

    #: BADKEY -- Key not recognized [:rfc:`8945`]
    BADKEY = 17

    #: BADTIME -- Signature out of time window [:rfc:`8945`]
    BADTIME = 18

    #: BADMODE -- Bad TKEY Mode [:rfc:`2930`]
    BADMODE = 19

    #: BADNAME -- Duplicate key name [:rfc:`2930`]
    BADNAME = 20

    #: BADALG -- Algorithm not supported [:rfc:`2930`]
    BADALG = 21

    #: BADTRUNC -- Bad Truncation [:rfc:`8945`]
    BADTRUNC = 22

    #: BADCOOKIE -- Bad/missing Server Cookie [:rfc:`7873`]
    BADCOOKIE = 23

    #: Reserved, can be allocated by Standards Action -- [:rfc:`6895`]
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
    def _missing_(cls, value: 'int') -> 'RCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 12 <= value <= 15:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 24 <= value <= 3840:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 3841 <= value <= 4095:
            #: Reserved for Private Use -- [:rfc:`6895`]
            return cls._unregistered_member(value, 'Reserved_for_Private_Use')
        if 4096 <= value <= 65534:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
