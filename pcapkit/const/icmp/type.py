# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""ICMP Type Numbers
=======================

.. module:: pcapkit.const.icmp.type

This module contains the constant enumeration for **ICMP Type Numbers**,
which is automatically generated from :class:`pcapkit.vendor.icmp.type.Type`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['Type']


class Type(EnumRegistry, IntEnum):
    """[Type] ICMP Type Numbers [:rfc:`792`]"""

    #: Echo Reply [:rfc:`792`]
    Echo_Reply = 0

    #: Unassigned
    Unassigned_1 = 1

    #: Unassigned
    Unassigned_2 = 2

    #: Destination Unreachable [:rfc:`792`]
    Destination_Unreachable = 3

    #: Source Quench (Deprecated) [:rfc:`792`][:rfc:`6633`]
    Source_Quench = 4

    #: Redirect [:rfc:`792`]
    Redirect = 5

    #: Alternate Host Address (Deprecated) [:rfc:`6918`]
    Alternate_Host_Address = 6

    #: Unassigned
    Unassigned_7 = 7

    #: Echo [:rfc:`792`]
    Echo = 8

    #: Router Advertisement [:rfc:`1256`]
    Router_Advertisement = 9

    #: Router Solicitation [:rfc:`1256`]
    Router_Solicitation = 10

    #: Time Exceeded [:rfc:`792`]
    Time_Exceeded = 11

    #: Parameter Problem [:rfc:`792`]
    Parameter_Problem = 12

    #: Timestamp [:rfc:`792`]
    Timestamp = 13

    #: Timestamp Reply [:rfc:`792`]
    Timestamp_Reply = 14

    #: Information Request (Deprecated) [:rfc:`792`][:rfc:`6918`]
    Information_Request = 15

    #: Information Reply (Deprecated) [:rfc:`792`][:rfc:`6918`]
    Information_Reply = 16

    #: Address Mask Request (Deprecated) [:rfc:`950`][:rfc:`6918`]
    Address_Mask_Request = 17

    #: Address Mask Reply (Deprecated) [:rfc:`950`][:rfc:`6918`]
    Address_Mask_Reply = 18

    #: Reserved (for Security) [Solo]
    Reserved_19 = 19

    #: Traceroute (Deprecated) [:rfc:`1393`][:rfc:`6918`]
    Traceroute = 30

    #: Datagram Conversion Error (Deprecated) [:rfc:`1475`][:rfc:`6918`]
    Datagram_Conversion_Error = 31

    #: Mobile Host Redirect (Deprecated) [David Johnson][:rfc:`6918`]
    Mobile_Host_Redirect = 32

    #: IPv6 Where-Are-You (Deprecated) [Simpson][:rfc:`6918`]
    IPv6_Where_Are_You = 33

    #: IPv6 I-Am-Here (Deprecated) [Simpson][:rfc:`6918`]
    IPv6_I_Am_Here = 34

    #: Mobile Registration Request (Deprecated) [Simpson][:rfc:`6918`]
    Mobile_Registration_Request = 35

    #: Mobile Registration Reply (Deprecated) [Simpson][:rfc:`6918`]
    Mobile_Registration_Reply = 36

    #: Domain Name Request (Deprecated) [:rfc:`1788`][:rfc:`6918`]
    Domain_Name_Request = 37

    #: Domain Name Reply (Deprecated) [:rfc:`1788`][:rfc:`6918`]
    Domain_Name_Reply = 38

    #: SKIP (Deprecated) [Markson][:rfc:`6918`]
    SKIP = 39

    #: Photuris [:rfc:`2521`]
    Photuris = 40

    #: ICMP messages utilized by experimental         mobility protocols such as
    #: Seamoby [:rfc:`4065`]
    ICMP_messages_utilized_by_experimental_mobility_protocols_such_as_Seamoby = 41

    #: Extended Echo Request [:rfc:`8335`]
    Extended_Echo_Request = 42

    #: Extended Echo Reply [:rfc:`8335`]
    Extended_Echo_Reply = 43

    #: RFC3692-style Experiment 1 [:rfc:`4727`]
    RFC3692_style_Experiment_1 = 253

    #: RFC3692-style Experiment 2 [:rfc:`4727`]
    RFC3692_style_Experiment_2 = 254

    #: Reserved [JBP]
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
    def _missing_(cls, value: 'int') -> 'Type':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 20 <= value <= 29:
            #: Reserved (for Robustness Experiment) [ZSu]
            return cls._unregistered_member(value, 'Reserved')
        if 44 <= value <= 252:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return cls._unregistered_member(value, 'Unassigned')
