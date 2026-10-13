# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Mobility Options
======================

.. module:: pcapkit.const.mh.option

This module contains the constant enumeration for **Mobility Options**,
which is automatically generated from :class:`pcapkit.vendor.mh.option.Option`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['Option']


class Option(EnumRegistry, IntEnum):
    """[Option] Mobility Options"""

    #: Pad1 [RFC 6275]
    Pad1 = 0

    #: PadN [RFC 6275]
    PadN = 1

    #: Binding Refresh Advice [RFC 6275]
    Binding_Refresh_Advice = 2

    #: Alternate Care-of Address [RFC 6275]
    Alternate_Care_of_Address = 3

    #: Nonce Indices [RFC 6275]
    Nonce_Indices = 4

    #: Authorization Data [RFC 6275]
    Authorization_Data = 5

    #: Mobile Network Prefix Option [RFC 3963]
    Mobile_Network_Prefix_Option = 6

    #: Mobility Header Link-Layer Address option [RFC 5568]
    Mobility_Header_Link_Layer_Address_option = 7

    #: MN-ID-OPTION-TYPE [RFC 4283]
    MN_ID_OPTION_TYPE = 8

    #: AUTH-OPTION-TYPE [RFC 4285]
    AUTH_OPTION_TYPE = 9

    #: MESG-ID-OPTION-TYPE [RFC 4285]
    MESG_ID_OPTION_TYPE = 10

    #: CGA Parameters Request [RFC 4866]
    CGA_Parameters_Request = 11

    #: CGA Parameters [RFC 4866]
    CGA_Parameters = 12

    #: Signature [RFC 4866]
    Signature = 13

    #: Permanent Home Keygen Token [RFC 4866]
    Permanent_Home_Keygen_Token = 14

    #: Care-of Test Init [RFC 4866]
    Care_of_Test_Init = 15

    #: Care-of Test [RFC 4866]
    Care_of_Test = 16

    #: DNS-UPDATE-TYPE [RFC 5026]
    DNS_UPDATE_TYPE = 17

    #: Experimental Mobility Option [RFC 5096]
    Experimental_Mobility_Option = 18

    #: Vendor Specific Mobility Option [RFC 5094]
    Vendor_Specific_Mobility_Option = 19

    #: Service Selection Mobility Option [RFC 5149]
    Service_Selection_Mobility_Option = 20

    #: Binding Authorization Data for FMIPv6 (BADF) [RFC 5568]
    Binding_Authorization_Data_for_FMIPv6 = 21

    #: Home Network Prefix Option [RFC 5213]
    Home_Network_Prefix_Option = 22

    #: Handoff Indicator Option [RFC 5213]
    Handoff_Indicator_Option = 23

    #: Access Technology Type Option [RFC 5213]
    Access_Technology_Type_Option = 24

    #: Mobile Node Link-layer Identifier Option [RFC 5213]
    Mobile_Node_Link_layer_Identifier_Option = 25

    #: Link-local Address Option [RFC 5213]
    Link_local_Address_Option = 26

    #: Timestamp Option [RFC 5213]
    Timestamp_Option = 27

    #: Restart Counter [RFC 5847]
    Restart_Counter = 28

    #: IPv4 Home Address [RFC 5555]
    IPv4_Home_Address = 29

    #: IPv4 Address Acknowledgement [RFC 5555]
    IPv4_Address_Acknowledgement = 30

    #: NAT Detection [RFC 5555]
    NAT_Detection = 31

    #: IPv4 Care-of Address [RFC 5555]
    IPv4_Care_of_Address = 32

    #: GRE Key Option [RFC 5845]
    GRE_Key_Option = 33

    #: Mobility Header IPv6 Address/Prefix [RFC 5568]
    Mobility_Header_IPv6_Address_Prefix = 34

    #: Binding Identifier [RFC 5648]
    Binding_Identifier = 35

    #: IPv4 Home Address Request [RFC 5844]
    IPv4_Home_Address_Request = 36

    #: IPv4 Home Address Reply [RFC 5844]
    IPv4_Home_Address_Reply = 37

    #: IPv4 Default-Router Address [RFC 5844]
    IPv4_Default_Router_Address = 38

    #: IPv4 DHCP Support Mode [RFC 5844]
    IPv4_DHCP_Support_Mode = 39

    #: Context Request Option [RFC 5949]
    Context_Request_Option = 40

    #: Local Mobility Anchor Address Option [RFC 5949]
    Local_Mobility_Anchor_Address_Option = 41

    #: Mobile Node Link-local Address Interface Identifier Option [RFC 5949]
    Mobile_Node_Link_local_Address_Interface_Identifier_Option = 42

    #: Transient Binding [RFC 6058]
    Transient_Binding = 43

    #: Flow Summary Mobility Option [RFC 6089]
    Flow_Summary_Mobility_Option = 44

    #: Flow Identification Mobility Option [RFC 6089]
    Flow_Identification_Mobility_Option = 45

    #: Redirect-Capability Mobility Option [RFC 6463]
    Redirect_Capability_Mobility_Option = 46

    #: Redirect Mobility Option [RFC 6463]
    Redirect_Mobility_Option = 47

    #: Load Information Mobility Option [RFC 6463]
    Load_Information_Mobility_Option = 48

    #: Alternate IPv4 Care-of Address [RFC 6463]
    Alternate_IPv4_Care_of_Address = 49

    #: Mobile Node Group Identifier [RFC 6602]
    Mobile_Node_Group_Identifier = 50

    #: MAG IPv6 Address [RFC 6705]
    MAG_IPv6_Address = 51

    #: Access Network Identifier [RFC 6757]
    Access_Network_Identifier = 52

    #: IPv4 Traffic Offload Selector [RFC 6909]
    IPv4_Traffic_Offload_Selector = 53

    #: Dynamic IP Multicast Selector [RFC 7028]
    Dynamic_IP_Multicast_Selector = 54

    #: Delegated Mobile Network Prefix [RFC 7148]
    Delegated_Mobile_Network_Prefix = 55

    #: Active Multicast Subscription IPv4 [RFC 7161]
    Active_Multicast_Subscription_IPv4 = 56

    #: Active Multicast Subscription IPv6 [RFC 7161]
    Active_Multicast_Subscription_IPv6 = 57

    #: Quality-of-Service [RFC 7222]
    Quality_of_Service = 58

    #: LMA User-Plane Address [RFC 7389]
    LMA_User_Plane_Address = 59

    #: Multicast Mobility Option [RFC 7411]
    Multicast_Mobility_Option = 60

    #: Multicast Acknowledgement Option [RFC 7411]
    Multicast_Acknowledgement_Option = 61

    #: LMA-Controlled MAG Parameters [RFC 8127]
    LMA_Controlled_MAG_Parameters = 62

    #: MAG Multipath-Binding [RFC 8278]
    MAG_Multipath_Binding = 63

    #: MAG Identifier [RFC 8278]
    MAG_Identifier = 64

    #: Anchored Prefix [RFC 8885]
    Anchored_Prefix = 65

    #: Local Prefix [RFC 8885]
    Local_Prefix = 66

    #: Previous MAAR [RFC 8885]
    Previous_MAAR = 67

    #: Serving MAAR [RFC 8885]
    Serving_MAAR = 68

    #: DLIF Link-Local Address [RFC 8885]
    DLIF_Link_Local_Address = 69

    #: DLIF Link-Layer Address [RFC 8885]
    DLIF_Link_Layer_Address = 70

    @classmethod
    def _missing_(cls, value: 'int') -> 'Option':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')
