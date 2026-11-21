# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""DNS EDNS0 Option Codes (OPT)
==================================

.. module:: pcapkit.const.dns.option

This module contains the constant enumeration for **DNS EDNS0 Option Codes (OPT)**,
which is automatically generated from :class:`pcapkit.vendor.dns.option.Option`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['Option']


class Option(EnumRegistry, IntEnum):
    """[Option] DNS EDNS0 Option Codes (OPT)"""

    #: Reserved [:rfc:`6891`]
    Reserved_0 = 0

    #: LLQ [:rfc:`8764`]
    LLQ = 1

    #: Update Lease [:rfc:`9664`]
    Update_Lease = 2

    #: NSID [:rfc:`5001`]
    NSID = 3

    #: Reserved [draft-cheshire-edns0-owner-option-00]
    Reserved_4 = 4

    #: DAU [:rfc:`6975`]
    DAU = 5

    #: DHU [:rfc:`6975`]
    DHU = 6

    #: N3U [:rfc:`6975`]
    N3U = 7

    #: edns-client-subnet [:rfc:`7871`]
    edns_client_subnet = 8

    #: EDNS EXPIRE [:rfc:`7314`]
    EDNS_EXPIRE = 9

    #: COOKIE [:rfc:`7873`]
    COOKIE = 10

    #: edns-tcp-keepalive [:rfc:`7828`]
    edns_tcp_keepalive = 11

    #: Padding [:rfc:`7830`]
    Padding = 12

    #: CHAIN [:rfc:`7901`]
    CHAIN = 13

    #: edns-key-tag [:rfc:`8145`]
    edns_key_tag = 14

    #: Extended DNS Error [:rfc:`8914`]
    Extended_DNS_Error = 15

    #: EDNS-Client-Tag [draft-bellis-dnsop-edns-tags-01]
    EDNS_Client_Tag = 16

    #: EDNS-Server-Tag [draft-bellis-dnsop-edns-tags-01]
    EDNS_Server_Tag = 17

    #: Report-Channel [:rfc:`9567`]
    Report_Channel = 18

    #: ZONEVERSION [:rfc:`9660`]
    ZONEVERSION = 19

    #: MQTYPE-Query [:rfc:`10029`]
    MQTYPE_Query = 20

    #: MQTYPE-Response [:rfc:`10029`]
    MQTYPE_Response = 21

    #: EDE-EXTRA-TEXT-LANGUAGE [draft-muks-dns-filtering-05]
    EDE_EXTRA_TEXT_LANGUAGE = 22

    #: FILTERING-CONTACT [draft-muks-dns-filtering-05]
    FILTERING_CONTACT = 23

    #: FILTERING-ORGANIZATION [draft-muks-dns-filtering-05]
    FILTERING_ORGANIZATION = 24

    #: FILTERING-DB [draft-muks-dns-filtering-05]
    FILTERING_DB = 25

    #: Structured DNS Error [RFC-ietf-dnsop-structured-dns-error-27]
    Structured_DNS_Error = 26

    #: Umbrella Ident [https://developer.cisco.com/docs/cloud-security/] [Cisco CIE
    #: DNS team]
    Umbrella_Ident = 20292

    #: DeviceID [https://developer.cisco.com/docs/cloud-security/] [Cisco CIE DNS
    #: team]
    DeviceID = 26946

    #: Reserved for future expansion [:rfc:`6891`]
    Reserved_for_future_expansion = 65535

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
    def _missing_(cls, value: 'int') -> 'Option':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 27 <= value <= 20291:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 20293 <= value <= 26945:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 26947 <= value <= 65000:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 65001 <= value <= 65534:
            #: Reserved for Local/Experimental Use [:rfc:`6891`]
            return cls._unregistered_member(value, 'Reserved_for_Local_Experimental_Use')
        return super()._missing_(value)
