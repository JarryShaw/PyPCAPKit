# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Mobility Options
======================

.. module:: pcapkit.const.mh.option

This module contains the constant enumeration for **Mobility Options**,
which is automatically generated from :class:`pcapkit.vendor.mh.option.Option`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Option']


class Option(IntEnum):
    """[Option] Mobility Options"""

    #: Pad1 [:rfc:`6275`]
    Pad1 = 0

    #: PadN [:rfc:`6275`]
    PadN = 1

    #: Binding Refresh Advice [:rfc:`6275`]
    Binding_Refresh_Advice = 2

    #: Alternate Care-of Address [:rfc:`6275`]
    Alternate_Care_of_Address = 3

    #: Nonce Indices [:rfc:`6275`]
    Nonce_Indices = 4

    #: Authorization Data [:rfc:`6275`]
    Authorization_Data = 5

    #: Mobile Network Prefix Option [:rfc:`3963`]
    Mobile_Network_Prefix_Option = 6

    #: Mobility Header Link-Layer Address option [:rfc:`5568`]
    Mobility_Header_Link_Layer_Address_option = 7

    #: MN-ID-OPTION-TYPE [:rfc:`4283`]
    MN_ID_OPTION_TYPE = 8

    #: AUTH-OPTION-TYPE [:rfc:`4285`]
    AUTH_OPTION_TYPE = 9

    #: MESG-ID-OPTION-TYPE [:rfc:`4285`]
    MESG_ID_OPTION_TYPE = 10

    #: CGA Parameters Request [:rfc:`4866`]
    CGA_Parameters_Request = 11

    #: CGA Parameters [:rfc:`4866`]
    CGA_Parameters = 12

    #: Signature [:rfc:`4866`]
    Signature = 13

    #: Permanent Home Keygen Token [:rfc:`4866`]
    Permanent_Home_Keygen_Token = 14

    #: Care-of Test Init [:rfc:`4866`]
    Care_of_Test_Init = 15

    #: Care-of Test [:rfc:`4866`]
    Care_of_Test = 16

    #: DNS-UPDATE-TYPE [:rfc:`5026`]
    DNS_UPDATE_TYPE = 17

    #: Experimental Mobility Option [:rfc:`5096`]
    Experimental_Mobility_Option = 18

    #: Vendor Specific Mobility Option [:rfc:`5094`]
    Vendor_Specific_Mobility_Option = 19

    #: Service Selection Mobility Option [:rfc:`5149`]
    Service_Selection_Mobility_Option = 20

    #: Binding Authorization Data for FMIPv6 (BADF) [:rfc:`5568`]
    Binding_Authorization_Data_for_FMIPv6 = 21

    #: Home Network Prefix Option [:rfc:`5213`]
    Home_Network_Prefix_Option = 22

    #: Handoff Indicator Option [:rfc:`5213`]
    Handoff_Indicator_Option = 23

    #: Access Technology Type Option [:rfc:`5213`]
    Access_Technology_Type_Option = 24

    #: Mobile Node Link-layer Identifier Option [:rfc:`5213`]
    Mobile_Node_Link_layer_Identifier_Option = 25

    #: Link-local Address Option [:rfc:`5213`]
    Link_local_Address_Option = 26

    #: Timestamp Option [:rfc:`5213`]
    Timestamp_Option = 27

    #: Restart Counter [:rfc:`5847`]
    Restart_Counter = 28

    #: IPv4 Home Address [:rfc:`5555`]
    IPv4_Home_Address = 29

    #: IPv4 Address Acknowledgement [:rfc:`5555`]
    IPv4_Address_Acknowledgement = 30

    #: NAT Detection [:rfc:`5555`]
    NAT_Detection = 31

    #: IPv4 Care-of Address [:rfc:`5555`]
    IPv4_Care_of_Address = 32

    #: GRE Key Option [:rfc:`5845`]
    GRE_Key_Option = 33

    #: Mobility Header IPv6 Address/Prefix [:rfc:`5568`]
    Mobility_Header_IPv6_Address_Prefix = 34

    #: Binding Identifier [:rfc:`5648`]
    Binding_Identifier = 35

    #: IPv4 Home Address Request [:rfc:`5844`]
    IPv4_Home_Address_Request = 36

    #: IPv4 Home Address Reply [:rfc:`5844`]
    IPv4_Home_Address_Reply = 37

    #: IPv4 Default-Router Address [:rfc:`5844`]
    IPv4_Default_Router_Address = 38

    #: IPv4 DHCP Support Mode [:rfc:`5844`]
    IPv4_DHCP_Support_Mode = 39

    #: Context Request Option [:rfc:`5949`]
    Context_Request_Option = 40

    #: Local Mobility Anchor Address Option [:rfc:`5949`]
    Local_Mobility_Anchor_Address_Option = 41

    #: Mobile Node Link-local Address Interface Identifier Option [:rfc:`5949`]
    Mobile_Node_Link_local_Address_Interface_Identifier_Option = 42

    #: Transient Binding [:rfc:`6058`]
    Transient_Binding = 43

    #: Flow Summary Mobility Option [:rfc:`6089`]
    Flow_Summary_Mobility_Option = 44

    #: Flow Identification Mobility Option [:rfc:`6089`]
    Flow_Identification_Mobility_Option = 45

    #: Redirect-Capability Mobility Option [:rfc:`6463`]
    Redirect_Capability_Mobility_Option = 46

    #: Redirect Mobility Option [:rfc:`6463`]
    Redirect_Mobility_Option = 47

    #: Load Information Mobility Option [:rfc:`6463`]
    Load_Information_Mobility_Option = 48

    #: Alternate IPv4 Care-of Address [:rfc:`6463`]
    Alternate_IPv4_Care_of_Address = 49

    #: Mobile Node Group Identifier [:rfc:`6602`]
    Mobile_Node_Group_Identifier = 50

    #: MAG IPv6 Address [:rfc:`6705`]
    MAG_IPv6_Address = 51

    #: Access Network Identifier [:rfc:`6757`]
    Access_Network_Identifier = 52

    #: IPv4 Traffic Offload Selector [:rfc:`6909`]
    IPv4_Traffic_Offload_Selector = 53

    #: Dynamic IP Multicast Selector [:rfc:`7028`]
    Dynamic_IP_Multicast_Selector = 54

    #: Delegated Mobile Network Prefix [:rfc:`7148`]
    Delegated_Mobile_Network_Prefix = 55

    #: Active Multicast Subscription IPv4 [:rfc:`7161`]
    Active_Multicast_Subscription_IPv4 = 56

    #: Active Multicast Subscription IPv6 [:rfc:`7161`]
    Active_Multicast_Subscription_IPv6 = 57

    #: Quality-of-Service [:rfc:`7222`]
    Quality_of_Service = 58

    #: LMA User-Plane Address [:rfc:`7389`]
    LMA_User_Plane_Address = 59

    #: Multicast Mobility Option [:rfc:`7411`]
    Multicast_Mobility_Option = 60

    #: Multicast Acknowledgement Option [:rfc:`7411`]
    Multicast_Acknowledgement_Option = 61

    #: LMA-Controlled MAG Parameters [:rfc:`8127`]
    LMA_Controlled_MAG_Parameters = 62

    #: MAG Multipath-Binding [:rfc:`8278`]
    MAG_Multipath_Binding = 63

    #: MAG Identifier [:rfc:`8278`]
    MAG_Identifier = 64

    #: Anchored Prefix [:rfc:`8885`]
    Anchored_Prefix = 65

    #: Local Prefix [:rfc:`8885`]
    Local_Prefix = 66

    #: Previous MAAR [:rfc:`8885`]
    Previous_MAAR = 67

    #: Serving MAAR [:rfc:`8885`]
    Serving_MAAR = 68

    #: DLIF Link-Local Address [:rfc:`8885`]
    DLIF_Link_Local_Address = 69

    #: DLIF Link-Layer Address [:rfc:`8885`]
    DLIF_Link_Layer_Address = 70

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Option':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return Option(key)
        if key not in Option._member_map_:  # pylint: disable=no-member
            return extend_enum(Option, key, default)
        return Option[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'Option':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)
