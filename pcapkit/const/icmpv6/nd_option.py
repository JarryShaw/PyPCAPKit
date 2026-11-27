# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""IPv6 Neighbor Discovery Option Formats
============================================

.. module:: pcapkit.const.icmpv6.nd_option

This module contains the constant enumeration for **IPv6 Neighbor Discovery Option Formats**,
which is automatically generated from :class:`pcapkit.vendor.icmpv6.nd_option.NDOption`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['NDOption']


class NDOption(EnumRegistry, IntEnum):
    """[NDOption] IPv6 Neighbor Discovery Option Formats [:rfc:`4861`]"""

    #: Source Link-layer Address [:rfc:`4861`]
    Source_Link_layer_Address = 1

    #: Target Link-layer Address [:rfc:`4861`]
    Target_Link_layer_Address = 2

    #: Prefix Information [:rfc:`4861`]
    Prefix_Information = 3

    #: Redirected Header [:rfc:`4861`]
    Redirected_Header = 4

    #: MTU [:rfc:`4861`]
    MTU = 5

    #: NBMA Shortcut Limit Option [:rfc:`2491`]
    NBMA_Shortcut_Limit_Option = 6

    #: Advertisement Interval Option [:rfc:`6275`]
    Advertisement_Interval_Option = 7

    #: Home Agent Information Option [:rfc:`6275`]
    Home_Agent_Information_Option = 8

    #: Source Address List [:rfc:`3122`]
    Source_Address_List = 9

    #: Target Address List [:rfc:`3122`]
    Target_Address_List = 10

    #: CGA option [:rfc:`3971`]
    CGA_option = 11

    #: RSA Signature option [:rfc:`3971`]
    RSA_Signature_option = 12

    #: Timestamp option [:rfc:`3971`]
    Timestamp_option = 13

    #: Nonce option [:rfc:`3971`]
    Nonce_option = 14

    #: Trust Anchor option [:rfc:`3971`]
    Trust_Anchor_option = 15

    #: Certificate option [:rfc:`3971`]
    Certificate_option = 16

    #: IP Address/Prefix Option [:rfc:`5568`]
    IP_Address_Prefix_Option = 17

    #: New Router Prefix Information Option [:rfc:`4068`]
    New_Router_Prefix_Information_Option = 18

    #: Link-layer Address Option [:rfc:`5568`]
    Link_layer_Address_Option = 19

    #: Neighbor Advertisement Acknowledgment Option [:rfc:`5568`]
    Neighbor_Advertisement_Acknowledgment_Option = 20

    #: PvD ID Router Advertisement Option [:rfc:`8801`]
    PvD_ID_Router_Advertisement_Option = 21

    #: Unassigned
    Unassigned_22 = 22

    #: MAP Option [:rfc:`4140`]
    MAP_Option = 23

    #: Route Information Option [:rfc:`4191`]
    Route_Information_Option = 24

    #: Recursive DNS Server Option [:rfc:`5006`][:rfc:`8106`]
    Recursive_DNS_Server_Option = 25

    #: RA Flags Extension Option [:rfc:`5175`]
    RA_Flags_Extension_Option = 26

    #: Handover Key Request Option [:rfc:`5269`]
    Handover_Key_Request_Option = 27

    #: Handover Key Reply Option [:rfc:`5269`]
    Handover_Key_Reply_Option = 28

    #: Handover Assist Information Option [:rfc:`5271`]
    Handover_Assist_Information_Option = 29

    #: Mobile Node Identifier Option [:rfc:`5271`]
    Mobile_Node_Identifier_Option = 30

    #: DNS Search List Option [:rfc:`8106`]
    DNS_Search_List_Option = 31

    #: Proxy Signature (PS) [:rfc:`6496`]
    Proxy_Signature = 32

    #: Address Registration Option [:rfc:`6775`]
    Address_Registration_Option = 33

    #: 6LoWPAN Context Option [:rfc:`6775`]
    NDOption_6LoWPAN_Context_Option = 34

    #: Authoritative Border Router Option [:rfc:`6775`]
    Authoritative_Border_Router_Option = 35

    #: 6LoWPAN Capability Indication Option (6CIO) [:rfc:`7400`]
    NDOption_6LoWPAN_Capability_Indication_Option = 36

    #: DHCP Captive-Portal [:rfc:`8910`]
    DHCP_Captive_Portal = 37

    #: PREF64 option [:rfc:`8781`]
    PREF64_option = 38

    #: Crypto-ID Parameters Option (CIPO) [:rfc:`8928`]
    Crypto_ID_Parameters_Option = 39

    #: NDP Signature Option (NDPSO) [:rfc:`8928`]
    NDP_Signature_Option = 40

    #: Resource Directory Address Option [:rfc:`9176`]
    Resource_Directory_Address_Option = 41

    #: Consistent Uptime Option [:rfc:`9685`]
    Consistent_Uptime_Option = 42

    #: CARD Request option [:rfc:`4065`]
    CARD_Request_option = 138

    #: CARD Reply option [:rfc:`4065`]
    CARD_Reply_option = 139

    #: Encrypted DNS Option [:rfc:`9463`]
    Encrypted_DNS_Option = 144

    #: RFC3692-style Experiment 1 [:rfc:`4727`]
    RFC3692_style_Experiment_1 = 253

    #: RFC3692-style Experiment 2 [:rfc:`4727`]
    RFC3692_style_Experiment_2 = 254

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
    def _missing_(cls, value: 'int') -> 'NDOption':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 43 <= value <= 137:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 140 <= value <= 143:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 145 <= value <= 252:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return cls._unregistered_member(value, 'Unassigned')
