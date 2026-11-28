# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""BOOTP Vendor Extensions and DHCP Options
==============================================

.. module:: pcapkit.const.dhcp.option

This module contains the constant enumeration for **BOOTP Vendor Extensions and DHCP Options**,
which is automatically generated from :class:`pcapkit.vendor.dhcp.option.Option`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['Option']


class Option(EnumRegistry, IntEnum):
    """[Option] BOOTP Vendor Extensions and DHCP Options"""

    #: Pad [:rfc:`2132`]
    Pad = 0

    #: Subnet Mask -- Subnet Mask Value [:rfc:`2132`]
    Subnet_Mask = 1

    #: Time Offset -- Time Offset in Seconds from UTC (note: deprecated by 100 and
    #: 101) [:rfc:`2132`]
    Time_Offset = 2

    #: Router -- N/4 Router addresses [:rfc:`2132`]
    Router = 3

    #: Time Server -- N/4 Timeserver addresses [:rfc:`2132`]
    Time_Server = 4

    #: Name Server -- N/4 IEN-116 Server addresses [:rfc:`2132`]
    Name_Server = 5

    #: Domain Server -- N/4 DNS Server addresses [:rfc:`2132`]
    Domain_Server = 6

    #: Log Server -- N/4 Logging Server addresses [:rfc:`2132`]
    Log_Server = 7

    #: Quotes Server -- N/4 Quotes Server addresses [:rfc:`2132`]
    Quotes_Server = 8

    #: LPR Server -- N/4 Printer Server addresses [:rfc:`2132`]
    LPR_Server = 9

    #: Impress Server -- N/4 Impress Server addresses [:rfc:`2132`]
    Impress_Server = 10

    #: RLP Server -- N/4 RLP Server addresses [:rfc:`2132`]
    RLP_Server = 11

    #: Hostname -- Hostname string [:rfc:`2132`]
    Hostname = 12

    #: Boot File Size -- Size of boot file in 512 byte chunks [:rfc:`2132`]
    Boot_File_Size = 13

    #: Merit Dump File -- Client to dump and name the file to dump it to
    #: [:rfc:`2132`]
    Merit_Dump_File = 14

    #: Domain Name -- The DNS domain name of the client [:rfc:`2132`]
    Domain_Name = 15

    #: Swap Server -- Swap Server address [:rfc:`2132`]
    Swap_Server = 16

    #: Root Path -- Path name for root disk [:rfc:`2132`]
    Root_Path = 17

    #: Extension File -- Path name for more BOOTP info [:rfc:`2132`]
    Extension_File = 18

    #: Forward On/Off -- Enable/Disable IP Forwarding [:rfc:`2132`]
    Forward_On_Off = 19

    #: SrcRte On/Off -- Enable/Disable Source Routing [:rfc:`2132`]
    SrcRte_On_Off = 20

    #: Policy Filter -- Routing Policy Filters [:rfc:`2132`]
    Policy_Filter = 21

    #: Max DG Assembly -- Max Datagram Reassembly Size [:rfc:`2132`]
    Max_DG_Assembly = 22

    #: Default IP TTL -- Default IP Time to Live [:rfc:`2132`]
    Default_IP_TTL = 23

    #: MTU Timeout -- Path MTU Aging Timeout [:rfc:`2132`]
    MTU_Timeout = 24

    #: MTU Plateau -- Path MTU Plateau Table [:rfc:`2132`]
    MTU_Plateau = 25

    #: MTU Interface -- Interface MTU Size [:rfc:`2132`]
    MTU_Interface = 26

    #: MTU Subnet -- All Subnets are Local [:rfc:`2132`]
    MTU_Subnet = 27

    #: Broadcast Address [:rfc:`2132`]
    Broadcast_Address = 28

    #: Mask Discovery -- Perform Mask Discovery [:rfc:`2132`]
    Mask_Discovery = 29

    #: Mask Supplier -- Provide Mask to Others [:rfc:`2132`]
    Mask_Supplier = 30

    #: Router Discovery -- Perform Router Discovery [:rfc:`2132`]
    Router_Discovery = 31

    #: Router Request -- Router Solicitation Address [:rfc:`2132`]
    Router_Request = 32

    #: Static Route -- Static Routing Table [:rfc:`2132`]
    Static_Route = 33

    #: Trailers -- Trailer Encapsulation [:rfc:`2132`]
    Trailers = 34

    #: ARP Timeout -- ARP Cache Timeout [:rfc:`2132`]
    ARP_Timeout = 35

    #: Ethernet -- Ethernet Encapsulation [:rfc:`2132`]
    Ethernet = 36

    #: Default TCP TTL -- Default TCP Time to Live [:rfc:`2132`]
    Default_TCP_TTL = 37

    #: Keepalive Time -- TCP Keepalive Interval [:rfc:`2132`]
    Keepalive_Time = 38

    #: Keepalive Data -- TCP Keepalive Garbage [:rfc:`2132`]
    Keepalive_Data = 39

    #: NIS Domain -- NIS Domain Name [:rfc:`2132`]
    NIS_Domain = 40

    #: NIS Servers -- NIS Server Addresses [:rfc:`2132`]
    NIS_Servers = 41

    #: NTP Servers -- NTP Server Addresses [:rfc:`2132`]
    NTP_Servers = 42

    #: Vendor Specific -- Vendor Specific Information [:rfc:`2132`]
    Vendor_Specific = 43

    #: NETBIOS Name Srv -- NETBIOS Name Servers [:rfc:`2132`]
    NETBIOS_Name_Srv = 44

    #: NETBIOS Dist Srv -- NETBIOS Datagram Distribution [:rfc:`2132`]
    NETBIOS_Dist_Srv = 45

    #: NETBIOS Node Type [:rfc:`2132`]
    NETBIOS_Node_Type = 46

    #: NETBIOS Scope [:rfc:`2132`]
    NETBIOS_Scope = 47

    #: X Window Font -- X Window Font Server [:rfc:`2132`]
    X_Window_Font = 48

    #: X Window Manager -- X Window Display Manager [:rfc:`2132`]
    X_Window_Manager = 49

    #: Address Request -- Requested IP Address [:rfc:`2132`]
    Address_Request = 50

    #: Address Time -- IP Address Lease Time [:rfc:`2132`]
    Address_Time = 51

    #: Overload -- Overload "sname" or "file" [:rfc:`2132`]
    Overload = 52

    #: DHCP Msg Type -- DHCP Message Type [:rfc:`2132`]
    DHCP_Msg_Type = 53

    #: DHCP Server Id -- DHCP Server Identification [:rfc:`2132`]
    DHCP_Server_Id = 54

    #: Parameter List -- Parameter Request List [:rfc:`2132`]
    Parameter_List = 55

    #: DHCP Message -- DHCP Error Message [:rfc:`2132`]
    DHCP_Message = 56

    #: DHCP Max Msg Size -- DHCP Maximum Message Size [:rfc:`2132`]
    DHCP_Max_Msg_Size = 57

    #: Renewal Time -- DHCP Renewal (T1) Time [:rfc:`2132`]
    Renewal_Time = 58

    #: Rebinding Time -- DHCP Rebinding (T2) Time [:rfc:`2132`]
    Rebinding_Time = 59

    #: Class Id -- Class Identifier [:rfc:`2132`]
    Class_Id = 60

    #: Client Id -- Client Identifier [:rfc:`2132`]
    Client_Id = 61

    #: NetWare/IP Domain -- NetWare/IP Domain Name [:rfc:`2242`]
    NetWare_IP_Domain = 62

    #: NetWare/IP Option -- NetWare/IP sub Options [:rfc:`2242`]
    NetWare_IP_Option = 63

    #: NIS-Domain-Name -- NIS+ v3 Client Domain Name [:rfc:`2132`]
    NIS_Domain_Name = 64

    #: NIS-Server-Addr -- NIS+ v3 Server Addresses [:rfc:`2132`]
    NIS_Server_Addr = 65

    #: Server-Name -- TFTP Server Name [:rfc:`2132`]
    Server_Name = 66

    #: Bootfile-Name -- Boot File Name [:rfc:`2132`]
    Bootfile_Name = 67

    #: Home-Agent-Addrs -- Home Agent Addresses [:rfc:`2132`]
    Home_Agent_Addrs = 68

    #: SMTP-Server -- Simple Mail Server Addresses [:rfc:`2132`]
    SMTP_Server = 69

    #: POP3-Server -- Post Office Server Addresses [:rfc:`2132`]
    POP3_Server = 70

    #: NNTP-Server -- Network News Server Addresses [:rfc:`2132`]
    NNTP_Server = 71

    #: WWW-Server -- WWW Server Addresses [:rfc:`2132`]
    WWW_Server = 72

    #: Finger-Server -- Finger Server Addresses [:rfc:`2132`]
    Finger_Server = 73

    #: IRC-Server -- Chat Server Addresses [:rfc:`2132`]
    IRC_Server = 74

    #: StreetTalk-Server -- StreetTalk Server Addresses [:rfc:`2132`]
    StreetTalk_Server = 75

    #: STDA-Server -- ST Directory Assist. Addresses [:rfc:`2132`]
    STDA_Server = 76

    #: User-Class -- User Class Information [:rfc:`3004`]
    User_Class = 77

    #: Directory Agent -- directory agent information [:rfc:`2610`]
    Directory_Agent = 78

    #: Service Scope -- service location agent scope [:rfc:`2610`]
    Service_Scope = 79

    #: Rapid Commit [:rfc:`4039`]
    Rapid_Commit = 80

    #: Client FQDN -- Fully Qualified Domain Name [:rfc:`4702`]
    Client_FQDN = 81

    #: Relay Agent Information [:rfc:`3046`]
    Relay_Agent_Information = 82

    #: iSNS -- Internet Storage Name Service [:rfc:`4174`]
    iSNS = 83

    #: REMOVED/Unassigned [:rfc:`3679`]
    REMOVED_Unassigned_84 = 84

    #: NDS Servers -- Novell Directory Services [:rfc:`2241`]
    NDS_Servers = 85

    #: NDS Tree Name -- Novell Directory Services [:rfc:`2241`]
    NDS_Tree_Name = 86

    #: NDS Context -- Novell Directory Services [:rfc:`2241`]
    NDS_Context = 87

    #: BCMCS Controller Domain Name list [:rfc:`4280`]
    BCMCS_Controller_Domain_Name_list = 88

    #: BCMCS Controller IPv4 address option [:rfc:`4280`]
    BCMCS_Controller_IPv4_address_option = 89

    #: Authentication [:rfc:`3118`]
    Authentication = 90

    #: client-last-transaction-time option [:rfc:`4388`]
    client_last_transaction_time_option = 91

    #: associated-ip option [:rfc:`4388`]
    associated_ip_option = 92

    #: Client System -- Client System Architecture [:rfc:`4578`]
    Client_System = 93

    #: Client NDI -- Client Network Device Interface [:rfc:`4578`]
    Client_NDI = 94

    #: LDAP -- Lightweight Directory Access Protocol [:rfc:`3679`]
    LDAP = 95

    #: REMOVED/Unassigned [:rfc:`3679`]
    REMOVED_Unassigned_96 = 96

    #: UUID/GUID -- UUID/GUID-based Client Identifier [:rfc:`4578`]
    UUID_GUID = 97

    #: User-Auth -- Open Group's User Authentication [:rfc:`2485`]
    User_Auth = 98

    #: GEOCONF_CIVIC [:rfc:`4776`]
    GEOCONF_CIVIC = 99

    #: PCode -- IEEE 1003.1 TZ String [:rfc:`4833`]
    PCode = 100

    #: TCode -- Reference to the TZ Database [:rfc:`4833`]
    TCode = 101

    #: IPv6-Only Preferred -- Number of seconds that DHCPv4 should be disabled
    #: [:rfc:`8925`]
    IPv6_Only_Preferred = 108

    #: OPTION_DHCP4O6_S46_SADDR -- DHCPv4 over DHCPv6 Softwire Source Address
    #: Option [:rfc:`8539`]
    OPTION_DHCP4O6_S46_SADDR = 109

    #: REMOVED/Unassigned [:rfc:`3679`]
    REMOVED_Unassigned_110 = 110

    #: Unassigned [:rfc:`3679`]
    Unassigned_111 = 111

    #: Netinfo Address -- NetInfo Parent Server Address [:rfc:`3679`]
    Netinfo_Address = 112

    #: Netinfo Tag -- NetInfo Parent Server Tag [:rfc:`3679`]
    Netinfo_Tag = 113

    #: DHCP Captive-Portal [:rfc:`8910`]
    DHCP_Captive_Portal = 114

    #: REMOVED/Unassigned [:rfc:`3679`]
    REMOVED_Unassigned_115 = 115

    #: Auto-Config -- DHCP Auto-Configuration [:rfc:`2563`]
    Auto_Config = 116

    #: Name Service Search [:rfc:`2937`]
    Name_Service_Search = 117

    #: Subnet Selection Option [:rfc:`3011`]
    Subnet_Selection_Option = 118

    #: Domain Search -- DNS domain search list [:rfc:`3397`]
    Domain_Search = 119

    #: SIP Servers DHCP Option [:rfc:`3361`]
    SIP_Servers_DHCP_Option = 120

    #: Classless Static Route Option [:rfc:`3442`]
    Classless_Static_Route_Option = 121

    #: CCC -- CableLabs Client Configuration [:rfc:`3495`]
    CCC = 122

    #: GeoConf Option [:rfc:`6225`]
    GeoConf_Option = 123

    #: V-I Vendor Class -- Vendor-Identifying Vendor Class [:rfc:`3925`]
    V_I_Vendor_Class = 124

    #: V-I Vendor-Specific Information -- Vendor-Identifying Vendor-Specific
    #: Information [:rfc:`3925`]
    V_I_Vendor_Specific_Information = 125

    #: Removed/Unassigned [:rfc:`3679`]
    Removed_Unassigned_126 = 126

    #: Removed/Unassigned [:rfc:`3679`]
    Removed_Unassigned_127 = 127

    #: PXE - undefined (vendor specific) [:rfc:`4578`]; Etherboot signature. 6
    #: bytes: E4:45:74:68:00:00; DOCSIS "full security" server IP address; TFTP
    #: Server IP address (for IP Phone software load)
    PXE_undefined_128 = 128

    #: PXE - undefined (vendor specific) [:rfc:`4578`]; Kernel options. Variable
    #: length string; Call Server IP address
    PXE_undefined_129 = 129

    #: PXE - undefined (vendor specific) [:rfc:`4578`]; Ethernet interface.
    #: Variable length string.; Discrimination string (to identify vendor)
    PXE_undefined_130 = 130

    #: PXE - undefined (vendor specific) [:rfc:`4578`]; Remote statistics server IP
    #: address
    PXE_undefined_131 = 131

    #: PXE - undefined (vendor specific) [:rfc:`4578`]; IEEE 802.1Q VLAN ID
    PXE_undefined_132 = 132

    #: PXE - undefined (vendor specific) [:rfc:`4578`]; IEEE 802.1D/p Layer 2
    #: Priority
    PXE_undefined_133 = 133

    #: PXE - undefined (vendor specific) [:rfc:`4578`]; Diffserv Code Point (DSCP)
    #: for VoIP signalling and media streams
    PXE_undefined_134 = 134

    #: PXE - undefined (vendor specific) [:rfc:`4578`]; HTTP Proxy for
    #: phone-specific applications
    PXE_undefined_135 = 135

    #: OPTION_PANA_AGENT [:rfc:`5192`]
    OPTION_PANA_AGENT = 136

    #: OPTION_V4_LOST [:rfc:`5223`]
    OPTION_V4_LOST = 137

    #: OPTION_CAPWAP_AC_V4 -- CAPWAP Access Controller addresses [:rfc:`5417`]
    OPTION_CAPWAP_AC_V4 = 138

    #: OPTION-IPv4_Address-MoS -- a series of suboptions [:rfc:`5678`]
    OPTION_IPv4_Address_MoS = 139

    #: OPTION-IPv4_FQDN-MoS -- a series of suboptions [:rfc:`5678`]
    OPTION_IPv4_FQDN_MoS = 140

    #: SIP UA Configuration Service Domains -- List of domain names to search for
    #: SIP User Agent Configuration [:rfc:`6011`]
    SIP_UA_Configuration_Service_Domains = 141

    #: OPTION-IPv4_Address-ANDSF -- ANDSF IPv4 Address Option for DHCPv4
    #: [:rfc:`6153`]
    OPTION_IPv4_Address_ANDSF = 142

    #: OPTION_V4_SZTP_REDIRECT -- This option provides a list of URIs for SZTP
    #: bootstrap servers [:rfc:`8572`]
    OPTION_V4_SZTP_REDIRECT = 143

    #: GeoLoc -- Geospatial Location with Uncertainty [:rfc:`6225`]
    GeoLoc = 144

    #: FORCERENEW_NONCE_CAPABLE -- Forcerenew Nonce Capable [:rfc:`6704`]
    FORCERENEW_NONCE_CAPABLE = 145

    #: RDNSS Selection -- Information for selecting RDNSS [:rfc:`6731`]
    RDNSS_Selection = 146

    #: OPTION_V4_DOTS_RI -- The name of the peer DOTS agent. [:rfc:`8973`]
    OPTION_V4_DOTS_RI = 147

    #: OPTION_V4_DOTS_ADDRESS -- N/4 IPv4 addresses of peer DOTS agent(s).
    #: [:rfc:`8973`]
    OPTION_V4_DOTS_ADDRESS = 148

    #: Unassigned [:rfc:`3942`]
    Unassigned_149 = 149

    #: TFTP server address [:rfc:`5859`]; Etherboot; GRUB configuration path name
    TFTP_server_address = 150

    #: status-code -- Status code and optional N byte text message describing
    #: status. [:rfc:`6926`]
    status_code = 151

    #: base-time -- Absolute time (seconds since Jan 1, 1970) message was sent.
    #: [:rfc:`6926`]
    base_time = 152

    #: start-time-of-state -- Number of seconds in the past when client entered
    #: current state. [:rfc:`6926`]
    start_time_of_state = 153

    #: query-start-time -- Absolute time (seconds since Jan 1, 1970) for beginning
    #: of query. [:rfc:`6926`]
    query_start_time = 154

    #: query-end-time -- Absolute time (seconds since Jan 1, 1970) for end of
    #: query. [:rfc:`6926`]
    query_end_time = 155

    #: dhcp-state -- State of IP address. [:rfc:`6926`]
    dhcp_state = 156

    #: data-source -- Indicates information came from local or remote server.
    #: [:rfc:`6926`]
    data_source = 157

    #: OPTION_V4_PCP_SERVER -- Includes one or multiple lists of PCP server IP
    #: addresses; each list is treated as a separate PCP server. [:rfc:`7291`]
    OPTION_V4_PCP_SERVER = 158

    #: OPTION_V4_PORTPARAMS -- This option is used to configure a set of ports
    #: bound to a shared IPv4 address. [:rfc:`7618`]
    OPTION_V4_PORTPARAMS = 159

    #: Unassigned -- Previously assigned by [RFC 7710]; known to also be used by
    #: Polycom. [:rfc:`7710`][:rfc:`8910`]
    Unassigned_160 = 160

    #: OPTION_MUD_URL_V4 -- Manufacturer Usage Descriptions [:rfc:`8520`]
    OPTION_MUD_URL_V4 = 161

    #: OPTION_V4_DNR -- Encrypted DNS Server [:rfc:`9463`]
    OPTION_V4_DNR = 162

    #: Etherboot (Tentatively Assigned - 2005-06-23)
    Etherboot_175 = 175

    #: IP Telephone (Tentatively Assigned - 2005-06-23)
    IP_Telephone = 176

    #: Etherboot (Tentatively Assigned - 2005-06-23); PacketCable and CableHome
    #: (replaced by 122)
    Etherboot_177 = 177

    #: PXELINUX Magic -- magic string = F1:00:74:7E [:rfc:`5071`][Deprecated]
    PXELINUX_Magic = 208

    #: Configuration File -- Configuration file [:rfc:`5071`]
    Configuration_File = 209

    #: Path Prefix -- Path Prefix Option [:rfc:`5071`]
    Path_Prefix = 210

    #: Reboot Time [:rfc:`5071`]
    Reboot_Time = 211

    #: OPTION_6RD -- OPTION_6RD with N/4 6rd BR addresses [:rfc:`5969`]
    OPTION_6RD = 212

    #: OPTION_V4_ACCESS_DOMAIN -- Access Network Domain Name [:rfc:`5986`]
    OPTION_V4_ACCESS_DOMAIN = 213

    #: Subnet Allocation Option [:rfc:`6656`]
    Subnet_Allocation_Option = 220

    #: Virtual Subnet Selection (VSS) Option [:rfc:`6607`]
    Virtual_Subnet_Selection_Option = 221

    #: End [:rfc:`2132`]
    End = 255

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
        if 102 <= value <= 107:
            #: REMOVED/Unassigned [:rfc:`3679`]
            return cls._unregistered_member(value, 'REMOVED_Unassigned')
        if 163 <= value <= 174:
            #: Unassigned [:rfc:`3942`]
            return cls._unregistered_member(value, 'Unassigned')
        if 178 <= value <= 207:
            #: Unassigned [:rfc:`3942`]
            return cls._unregistered_member(value, 'Unassigned')
        if 214 <= value <= 219:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 222 <= value <= 223:
            #: Unassigned [:rfc:`3942`]
            return cls._unregistered_member(value, 'Unassigned')
        if 224 <= value <= 254:
            #: Reserved (Private Use)
            return cls._unregistered_member(value, 'Reserved')
        return super()._missing_(value)
