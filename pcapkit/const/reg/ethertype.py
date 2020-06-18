# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Ethertype IEEE 802 Numbers"""

from aenum import IntEnum, extend_enum

__all__ = ['EtherType']


class EtherType(IntEnum):
    """[EtherType] Ethertype IEEE 802 Numbers"""

    #: XEROX PUP (see 0A00) [Boggs, D., J. Shoch, E. Taft, and R. Metcalfe, "PUP:
    #: An Internetwork Architecture", XEROX Palo Alto Research Center, CSL-79-10,
    #: July 1979; also in IEEE Transactions on Communication, Volume COM-28, Number
    #: 4, April 1980.][Neil Sembower]
    XEROX_PUP = 0x0200

    #: PUP Addr Trans (see 0A01) [Neil Sembower]
    PUP_Addr_Trans_0x0201 = 0x0201

    #: Nixdorf [Neil Sembower]
    Nixdorf = 0x0400

    #: XEROX NS IDP ["The Ethernet, A Local Area Network: Data Link Layer and
    #: Physical Layer Specification", AA-K759B-TK, Digital Equipment Corporation,
    #: Maynard, MA. Also as: "The Ethernet - A Local Area Network", Version 1.0,
    #: Digital Equipment Corporation, Intel Corporation, Xerox Corporation,
    #: September 1980. And: "The Ethernet, A Local Area Network: Data Link Layer
    #: and Physical Layer Specifications", Digital, Intel and Xerox, November 1982.
    #: And: XEROX, "The Ethernet, A Local Area Network: Data Link Layer and
    #: Physical Layer Specification", X3T51/80-50, Xerox Corporation, Stamford,
    #: CT., October 1980.][Neil Sembower]
    XEROX_NS_IDP = 0x0600

    #: DLOG [Neil Sembower]
    DLOG_0x0660 = 0x0660

    #: DLOG [Neil Sembower]
    DLOG_0x0661 = 0x0661

    #: Internet Protocol version 4 (IPv4) [:rfc:`7042`]
    Internet_Protocol_version_4 = 0x0800

    #: X.75 Internet [Neil Sembower]
    X_75_Internet = 0x0801

    #: NBS Internet [Neil Sembower]
    NBS_Internet = 0x0802

    #: ECMA Internet [Neil Sembower]
    ECMA_Internet = 0x0803

    #: Chaosnet [Neil Sembower]
    Chaosnet = 0x0804

    #: X.25 Level 3 [Neil Sembower]
    X_25_Level_3 = 0x0805

    #: Address Resolution Protocol (ARP) [:rfc:`7042`]
    Address_Resolution_Protocol = 0x0806

    #: XNS Compatability [Neil Sembower]
    XNS_Compatability = 0x0807

    #: Frame Relay ARP [:rfc:`1701`]
    Frame_Relay_ARP = 0x0808

    #: Symbolics Private [David Plummer]
    Symbolics_Private = 0x081C

    #: Ungermann-Bass net debugr [Neil Sembower]
    Ungermann_Bass_net_debugr = 0x0900

    #: Xerox IEEE802.3 PUP [Neil Sembower]
    Xerox_IEEE802_3_PUP = 0x0A00

    #: PUP Addr Trans [Neil Sembower]
    PUP_Addr_Trans_0x0A01 = 0x0A01

    #: Banyan VINES [Neil Sembower]
    Banyan_VINES = 0x0BAD

    #: VINES Loopback [:rfc:`1701`]
    VINES_Loopback = 0x0BAE

    #: VINES Echo [:rfc:`1701`]
    VINES_Echo = 0x0BAF

    #: Berkeley Trailer nego [Neil Sembower]
    Berkeley_Trailer_nego = 0x1000

    #: Valid Systems [Neil Sembower]
    Valid_Systems = 0x1600

    #: TRILL [:rfc:`6325`]
    TRILL = 0x22F3

    #: L2-IS-IS [:rfc:`6325`]
    L2_IS_IS = 0x22F4

    #: PCS Basic Block Protocol [Neil Sembower]
    PCS_Basic_Block_Protocol = 0x4242

    #: BBN Simnet [Neil Sembower]
    BBN_Simnet = 0x5208

    #: DEC Unassigned (Exp.) [Neil Sembower]
    DEC_Unassigned_0x6000 = 0x6000

    #: DEC MOP Dump/Load [Neil Sembower]
    DEC_MOP_Dump_Load = 0x6001

    #: DEC MOP Remote Console [Neil Sembower]
    DEC_MOP_Remote_Console = 0x6002

    #: DEC DECNET Phase IV Route [Neil Sembower]
    DEC_DECNET_Phase_IV_Route = 0x6003

    #: DEC LAT [Neil Sembower]
    DEC_LAT = 0x6004

    #: DEC Diagnostic Protocol [Neil Sembower]
    DEC_Diagnostic_Protocol = 0x6005

    #: DEC Customer Protocol [Neil Sembower]
    DEC_Customer_Protocol = 0x6006

    #: DEC LAVC, SCA [Neil Sembower]
    DEC_LAVC_SCA = 0x6007

    #: Trans Ether Bridging [:rfc:`1701`]
    Trans_Ether_Bridging = 0x6558

    #: Raw Frame Relay [:rfc:`1701`]
    Raw_Frame_Relay = 0x6559

    #: Ungermann-Bass download [Neil Sembower]
    Ungermann_Bass_download = 0x7000

    #: Ungermann-Bass dia/loop [Neil Sembower]
    Ungermann_Bass_dia_loop = 0x7002

    #: Proteon [Neil Sembower]
    Proteon = 0x7030

    #: Cabletron [Neil Sembower]
    Cabletron = 0x7034

    #: Cronus VLN [:rfc:`824`][Daniel Tappan]
    Cronus_VLN = 0x8003

    #: Cronus Direct [:rfc:`824`][Daniel Tappan]
    Cronus_Direct = 0x8004

    #: HP Probe [Neil Sembower]
    HP_Probe = 0x8005

    #: Nestar [Neil Sembower]
    Nestar = 0x8006

    #: AT&T [Neil Sembower]
    AT_T_0x8008 = 0x8008

    #: Excelan [Neil Sembower]
    Excelan = 0x8010

    #: SGI diagnostics [Andrew Cherenson]
    SGI_diagnostics = 0x8013

    #: SGI network games [Andrew Cherenson]
    SGI_network_games = 0x8014

    #: SGI reserved [Andrew Cherenson]
    SGI_reserved = 0x8015

    #: SGI bounce server [Andrew Cherenson]
    SGI_bounce_server = 0x8016

    #: Apollo Domain [Neil Sembower]
    Apollo_Domain = 0x8019

    #: Tymshare [Neil Sembower]
    Tymshare = 0x802E

    #: Tigan, Inc. [Neil Sembower]
    Tigan_Inc = 0x802F

    #: Reverse Address Resolution Protocol (RARP) [:rfc:`903`][Joseph Murdock]
    Reverse_Address_Resolution_Protocol = 0x8035

    #: Aeonic Systems [Neil Sembower]
    Aeonic_Systems = 0x8036

    #: DEC LANBridge [Neil Sembower]
    DEC_LANBridge = 0x8038

    #: DEC Ethernet Encryption [Neil Sembower]
    DEC_Ethernet_Encryption = 0x803D

    #: DEC Unassigned [Neil Sembower]
    DEC_Unassigned_0x803E = 0x803E

    #: DEC LAN Traffic Monitor [Neil Sembower]
    DEC_LAN_Traffic_Monitor = 0x803F

    #: Planning Research Corp. [Neil Sembower]
    Planning_Research_Corp = 0x8044

    #: AT&T [Neil Sembower]
    AT_T_0x8046 = 0x8046

    #: AT&T [Neil Sembower]
    AT_T_0x8047 = 0x8047

    #: ExperData [Neil Sembower]
    ExperData = 0x8049

    #: Stanford V Kernel exp. [Neil Sembower]
    Stanford_V_Kernel_exp = 0x805B

    #: Stanford V Kernel prod. [Neil Sembower]
    Stanford_V_Kernel_prod = 0x805C

    #: Evans & Sutherland [Neil Sembower]
    Evans_Sutherland = 0x805D

    #: Little Machines [Neil Sembower]
    Little_Machines = 0x8060

    #: Counterpoint Computers [Neil Sembower]
    Counterpoint_Computers = 0x8062

    #: Univ. of Mass. @ Amherst [Neil Sembower]
    Univ_of_Mass_Amherst_0x8065 = 0x8065

    #: Univ. of Mass. @ Amherst [Neil Sembower]
    Univ_of_Mass_Amherst_0x8066 = 0x8066

    #: Veeco Integrated Auto. [Neil Sembower]
    Veeco_Integrated_Auto = 0x8067

    #: General Dynamics [Neil Sembower]
    General_Dynamics = 0x8068

    #: AT&T [Neil Sembower]
    AT_T_0x8069 = 0x8069

    #: Autophon [Neil Sembower]
    Autophon = 0x806A

    #: ComDesign [Neil Sembower]
    ComDesign = 0x806C

    #: Computgraphic Corp. [Neil Sembower]
    Computgraphic_Corp = 0x806D

    #: Matra [Neil Sembower]
    Matra = 0x807A

    #: Dansk Data Elektronik [Neil Sembower]
    Dansk_Data_Elektronik = 0x807B

    #: Merit Internodal [Hans Werner Braun]
    Merit_Internodal = 0x807C

    #: Vitalink TransLAN III [Neil Sembower]
    Vitalink_TransLAN_III = 0x8080

    #: Appletalk [Neil Sembower]
    Appletalk = 0x809B

    #: Spider Systems Ltd. [Neil Sembower]
    Spider_Systems_Ltd = 0x809F

    #: Nixdorf Computers [Neil Sembower]
    Nixdorf_Computers = 0x80A3

    #: Banyan Systems [Neil Sembower]
    Banyan_Systems_0x80C4 = 0x80C4

    #: Banyan Systems [Neil Sembower]
    Banyan_Systems_0x80C5 = 0x80C5

    #: Pacer Software [Neil Sembower]
    Pacer_Software = 0x80C6

    #: Applitek Corporation [Neil Sembower]
    Applitek_Corporation = 0x80C7

    #: IBM SNA Service on Ether [Neil Sembower]
    IBM_SNA_Service_on_Ether = 0x80D5

    #: Varian Associates [Neil Sembower]
    Varian_Associates = 0x80DD

    #: Retix [Neil Sembower]
    Retix = 0x80F2

    #: AppleTalk AARP (Kinetics) [Neil Sembower]
    AppleTalk_AARP = 0x80F3

    #: Apollo Computer [Neil Sembower]
    Apollo_Computer = 0x80F7

    #: Wellfleet Communications [Neil Sembower]
    Wellfleet_Communications = 0x80FF

    #: Customer VLAN Tag Type (C-Tag, formerly called the Q-Tag) (initially
    #: Wellfleet) [:rfc:`7042`]
    Customer_VLAN_Tag_Type = 0x8100

    #: Hayes Microcomputers [Neil Sembower]
    Hayes_Microcomputers = 0x8130

    #: VG Laboratory Systems [Neil Sembower]
    VG_Laboratory_Systems = 0x8131

    #: Logicraft [Neil Sembower]
    Logicraft = 0x8148

    #: Network Computing Devices [Neil Sembower]
    Network_Computing_Devices = 0x8149

    #: Alpha Micro [Neil Sembower]
    Alpha_Micro = 0x814A

    #: SNMP [Joyce K Reynolds]
    SNMP = 0x814C

    #: BIIN [Neil Sembower]
    BIIN_0x814D = 0x814D

    #: BIIN [Neil Sembower]
    BIIN_0x814E = 0x814E

    #: Technically Elite Concept [Neil Sembower]
    Technically_Elite_Concept = 0x814F

    #: Rational Corp [Neil Sembower]
    Rational_Corp = 0x8150

    #: XTP [Neil Sembower]
    XTP = 0x817D

    #: SGI/Time Warner prop. [Neil Sembower]
    SGI_Time_Warner_prop = 0x817E

    #: HIPPI-FP encapsulation [Neil Sembower]
    HIPPI_FP_encapsulation = 0x8180

    #: STP, HIPPI-ST [Neil Sembower]
    STP_HIPPI_ST = 0x8181

    #: Reserved for HIPPI-6400 [Neil Sembower]
    Reserved_for_HIPPI_6400_0x8182 = 0x8182

    #: Reserved for HIPPI-6400 [Neil Sembower]
    Reserved_for_HIPPI_6400_0x8183 = 0x8183

    #: Motorola Computer [Neil Sembower]
    Motorola_Computer = 0x818D

    #: ARAI Bunkichi [Neil Sembower]
    ARAI_Bunkichi = 0x81A4

    #: SECTRA [Neil Sembower]
    SECTRA = 0x86DB

    #: Delta Controls [Neil Sembower]
    Delta_Controls = 0x86DE

    #: Internet Protocol version 6 (IPv6) [:rfc:`7042`]
    Internet_Protocol_version_6 = 0x86DD

    #: ATOMIC [Joe Touch]
    ATOMIC = 0x86DF

    #: TCP/IP Compression [:rfc:`1144`][:rfc:`1701`]
    TCP_IP_Compression = 0x876B

    #: IP Autonomous Systems [:rfc:`1701`]
    IP_Autonomous_Systems = 0x876C

    #: Secure Data [:rfc:`1701`]
    Secure_Data = 0x876D

    #: IEEE Std 802.3 - Ethernet Passive Optical Network (EPON) [EPON][:rfc:`7042`]
    IEEE_Std_802_3_Ethernet_Passive_Optical_Network = 0x8808

    #: Point-to-Point Protocol (PPP) [:rfc:`7042`]
    Point_to_Point_Protocol = 0x880B

    #: General Switch Management Protocol (GSMP) [:rfc:`7042`]
    General_Switch_Management_Protocol = 0x880C

    #: MPLS [:rfc:`5332`]
    MPLS = 0x8847

    #: MPLS with upstream-assigned label [:rfc:`5332`]
    MPLS_with_upstream_assigned_label = 0x8848

    #: Multicast Channel Allocation Protocol (MCAP) [:rfc:`7042`]
    Multicast_Channel_Allocation_Protocol = 0x8861

    #: PPP over Ethernet (PPPoE) Discovery Stage [:rfc:`2516`]
    PPP_over_Ethernet_Discovery_Stage = 0x8863

    #: PPP over Ethernet (PPPoE) Session Stage [:rfc:`2516`]
    PPP_over_Ethernet_Session_Stage = 0x8864

    #: IEEE Std 802.1X - Port-based network access control [IEEE]
    IEEE_Std_802_1X_Port_based_network_access_control = 0x888E

    #: IEEE Std 802.1Q - Service VLAN tag identifier (S-Tag) [IEEE]
    IEEE_Std_802_1Q_Service_VLAN_tag_identifier = 0x88A8

    #: IEEE Std 802 - Local Experimental Ethertype [IEEE]
    IEEE_Std_802_Local_Experimental_Ethertype_0x88B5 = 0x88B5

    #: IEEE Std 802 - Local Experimental Ethertype [IEEE]
    IEEE_Std_802_Local_Experimental_Ethertype_0x88B6 = 0x88B6

    #: IEEE Std 802 - OUI Extended Ethertype [IEEE]
    IEEE_Std_802_OUI_Extended_Ethertype = 0x88B7

    #: IEEE Std 802.11 - Pre-Authentication (802.11i) [IEEE]
    IEEE_Std_802_11_Pre_Authentication = 0x88C7

    #: IEEE Std 802.1AB - Link Layer Discovery Protocol (LLDP) [IEEE]
    IEEE_Std_802_1AB_Link_Layer_Discovery_Protocol = 0x88CC

    #: IEEE Std 802.1AE - Media Access Control Security [IEEE]
    IEEE_Std_802_1AE_Media_Access_Control_Security = 0x88E5

    #: Provider Backbone Bridging Instance tag [IEEE Std 802.1Q-2014]
    Provider_Backbone_Bridging_Instance_tag = 0x88E7

    #: IEEE Std 802.1Q  - Multiple VLAN Registration Protocol (MVRP) [IEEE]
    IEEE_Std_802_1Q_Multiple_VLAN_Registration_Protocol = 0x88F5

    #: IEEE Std 802.1Q - Multiple Multicast Registration Protocol (MMRP) [IEEE]
    IEEE_Std_802_1Q_Multiple_Multicast_Registration_Protocol = 0x88F6

    #: IEEE Std 802.11 - Fast Roaming Remote Request (802.11r) [IEEE]
    IEEE_Std_802_11_Fast_Roaming_Remote_Request = 0x890D

    #: IEEE Std 802.21 - Media Independent Handover Protocol [IEEE]
    IEEE_Std_802_21_Media_Independent_Handover_Protocol = 0x8917

    #: IEEE Std 802.1Qbe - Multiple I-SID Registration Protocol [IEEE]
    IEEE_Std_802_1Qbe_Multiple_I_SID_Registration_Protocol = 0x8929

    #: TRILL Fine Grained Labeling (FGL) [:rfc:`7172`]
    TRILL_Fine_Grained_Labeling = 0x893B

    #: IEEE Std 802.1Qbg - ECP Protocol (also used in 802.1BR) [IEEE]
    IEEE_Std_802_1Qbg_ECP_Protocol = 0x8940

    #: TRILL RBridge Channel [:rfc:`7178`]
    TRILL_RBridge_Channel = 0x8946

    #: GeoNetworking as defined in ETSI EN 302 636-4-1 [IEEE]
    GeoNetworking_as_defined_in_ETSI_EN_302_636_4_1 = 0x8947

    #: NSH (Network Service Header) [:rfc:`8300`]
    NSH = 0x894F

    #: Loopback [Neil Sembower]
    Loopback = 0x9000

    #: 3Com(Bridge) XNS Sys Mgmt [Neil Sembower]
    EtherType_3Com_XNS_Sys_Mgmt = 0x9001

    #: 3Com(Bridge) TCP-IP Sys [Neil Sembower]
    EtherType_3Com_TCP_IP_Sys = 0x9002

    #: 3Com(Bridge) loop detect [Neil Sembower]
    EtherType_3Com_loop_detect = 0x9003

    #: Multi-Topology [:rfc:`8377`]
    Multi_Topology = 0x9A22

    #: LoWPAN encapsulation [:rfc:`7973`]
    LoWPAN_encapsulation = 0xA0ED

    #: The Ethertype will be used to identify a "Channel"          in which control
    #: messages are encapsulated as payload of GRE packets.          When a GRE
    #: packet tagged with the Ethertype is received, the payload          will be
    #: handed to the network processor for processing. [:rfc:`8157`]
    The_Ethertype_will_be_used_to_identify_a_Channel_in_which_control_messages_are_encapsulated_as_payload_of_GRE_packets_When_a_GRE_packet_tagged_with_the_Ethertype_is_received_the_payload_will_be_handed_to_the_network_processor_for_processing = 0xB7EA

    #: BBN VITAL-LanBridge cache [Neil Sembower]
    BBN_VITAL_LanBridge_cache = 0xFF00

    #: Reserved [:rfc:`1701`]
    Reserved = 0xFFFF

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return EtherType(key)
        if key not in EtherType._member_map_:  # pylint: disable=no-member
            extend_enum(EtherType, key, default)
        return EtherType[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0x0000 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0000 <= value <= 0x05DC:
            #: IEEE802.3 Length Field [Neil Sembower]
            extend_enum(cls, 'IEEE802_3_Length_Field_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x0101 <= value <= 0x01FF:
            #: Experimental [Neil Sembower]
            extend_enum(cls, 'Experimental_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x0888 <= value <= 0x088A:
            #: Xyplex [Neil Sembower]
            extend_enum(cls, 'Xyplex_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x1001 <= value <= 0x100F:
            #: Berkeley Trailer encap/IP [Neil Sembower]
            extend_enum(cls, 'Berkeley_Trailer_encap_IP_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x6008 <= value <= 0x6009:
            #: DEC Unassigned [Neil Sembower]
            extend_enum(cls, 'DEC_Unassigned_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x6010 <= value <= 0x6014:
            #: 3Com Corporation [Neil Sembower]
            extend_enum(cls, 'EtherType_3Com_Corporation_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x7020 <= value <= 0x7029:
            #: LRT [Neil Sembower]
            extend_enum(cls, 'LRT_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8039 <= value <= 0x803C:
            #: DEC Unassigned [Neil Sembower]
            extend_enum(cls, 'DEC_Unassigned_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8040 <= value <= 0x8042:
            #: DEC Unassigned [Neil Sembower]
            extend_enum(cls, 'DEC_Unassigned_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x806E <= value <= 0x8077:
            #: Landmark Graphics Corp. [Neil Sembower]
            extend_enum(cls, 'Landmark_Graphics_Corp_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x807D <= value <= 0x807F:
            #: Vitalink Communications [Neil Sembower]
            extend_enum(cls, 'Vitalink_Communications_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8081 <= value <= 0x8083:
            #: Counterpoint Computers [Neil Sembower]
            extend_enum(cls, 'Counterpoint_Computers_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x809C <= value <= 0x809E:
            #: Datability [Neil Sembower]
            extend_enum(cls, 'Datability_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80A4 <= value <= 0x80B3:
            #: Siemens Gammasonics Inc. [Neil Sembower]
            extend_enum(cls, 'Siemens_Gammasonics_Inc_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80C0 <= value <= 0x80C3:
            #: DCA Data Exchange Cluster [Neil Sembower]
            extend_enum(cls, 'DCA_Data_Exchange_Cluster_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80C8 <= value <= 0x80CC:
            #: Intergraph Corporation [Neil Sembower]
            extend_enum(cls, 'Intergraph_Corporation_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80CD <= value <= 0x80CE:
            #: Harris Corporation [Neil Sembower]
            extend_enum(cls, 'Harris_Corporation_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80CF <= value <= 0x80D2:
            #: Taylor Instrument [Neil Sembower]
            extend_enum(cls, 'Taylor_Instrument_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80D3 <= value <= 0x80D4:
            #: Rosemount Corporation [Neil Sembower]
            extend_enum(cls, 'Rosemount_Corporation_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80DE <= value <= 0x80DF:
            #: Integrated Solutions TRFS [Neil Sembower]
            extend_enum(cls, 'Integrated_Solutions_TRFS_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80E0 <= value <= 0x80E3:
            #: Allen-Bradley [Neil Sembower]
            extend_enum(cls, 'Allen_Bradley_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80E4 <= value <= 0x80F0:
            #: Datability [Neil Sembower]
            extend_enum(cls, 'Datability_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80F4 <= value <= 0x80F5:
            #: Kinetics [Neil Sembower]
            extend_enum(cls, 'Kinetics_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8101 <= value <= 0x8103:
            #: Wellfleet Communications [Neil Sembower]
            extend_enum(cls, 'Wellfleet_Communications_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8107 <= value <= 0x8109:
            #: Symbolics Private [Neil Sembower]
            extend_enum(cls, 'Symbolics_Private_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8132 <= value <= 0x8136:
            #: Bridge Communications [Neil Sembower]
            extend_enum(cls, 'Bridge_Communications_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8137 <= value <= 0x8138:
            #: Novell, Inc. [Neil Sembower]
            extend_enum(cls, 'Novell_Inc_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8139 <= value <= 0x813D:
            #: KTI [Neil Sembower]
            extend_enum(cls, 'KTI_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8151 <= value <= 0x8153:
            #: Qualcomm [Neil Sembower]
            extend_enum(cls, 'Qualcomm_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x815C <= value <= 0x815E:
            #: Computer Protocol Pty Ltd [Neil Sembower]
            extend_enum(cls, 'Computer_Protocol_Pty_Ltd_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8164 <= value <= 0x8166:
            #: Charles River Data System [Neil Sembower]
            extend_enum(cls, 'Charles_River_Data_System_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8184 <= value <= 0x818C:
            #: Silicon Graphics prop. [Neil Sembower]
            extend_enum(cls, 'Silicon_Graphics_prop_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x819A <= value <= 0x81A3:
            #: Qualcomm [Neil Sembower]
            extend_enum(cls, 'Qualcomm_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81A5 <= value <= 0x81AE:
            #: RAD Network Devices [Neil Sembower]
            extend_enum(cls, 'RAD_Network_Devices_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81B7 <= value <= 0x81B9:
            #: Xyplex [Neil Sembower]
            extend_enum(cls, 'Xyplex_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81CC <= value <= 0x81D5:
            #: Apricot Computers [Neil Sembower]
            extend_enum(cls, 'Apricot_Computers_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81D6 <= value <= 0x81DD:
            #: Artisoft [Neil Sembower]
            extend_enum(cls, 'Artisoft_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81E6 <= value <= 0x81EF:
            #: Polygon [Neil Sembower]
            extend_enum(cls, 'Polygon_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81F0 <= value <= 0x81F2:
            #: Comsat Labs [Neil Sembower]
            extend_enum(cls, 'Comsat_Labs_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81F3 <= value <= 0x81F5:
            #: SAIC [Neil Sembower]
            extend_enum(cls, 'SAIC_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81F6 <= value <= 0x81F8:
            #: VG Analytical [Neil Sembower]
            extend_enum(cls, 'VG_Analytical_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8203 <= value <= 0x8205:
            #: Quantum Software [Neil Sembower]
            extend_enum(cls, 'Quantum_Software_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8221 <= value <= 0x8222:
            #: Ascom Banking Systems [Neil Sembower]
            extend_enum(cls, 'Ascom_Banking_Systems_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x823E <= value <= 0x8240:
            #: Advanced Encryption Syste [Neil Sembower]
            extend_enum(cls, 'Advanced_Encryption_Syste_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x827F <= value <= 0x8282:
            #: Athena Programming [Neil Sembower]
            extend_enum(cls, 'Athena_Programming_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8263 <= value <= 0x826A:
            #: Charles River Data System [Neil Sembower]
            extend_enum(cls, 'Charles_River_Data_System_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x829A <= value <= 0x829B:
            #: Inst Ind Info Tech [Neil Sembower]
            extend_enum(cls, 'Inst_Ind_Info_Tech_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x829C <= value <= 0x82AB:
            #: Taurus Controls [Neil Sembower]
            extend_enum(cls, 'Taurus_Controls_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x82AC <= value <= 0x8693:
            #: Walker Richer & Quinn [Neil Sembower]
            extend_enum(cls, 'Walker_Richer_Quinn_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8694 <= value <= 0x869D:
            #: Idea Courier [Neil Sembower]
            extend_enum(cls, 'Idea_Courier_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x869E <= value <= 0x86A1:
            #: Computer Network Tech [Neil Sembower]
            extend_enum(cls, 'Computer_Network_Tech_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x86A3 <= value <= 0x86AC:
            #: Gateway Communications [Neil Sembower]
            extend_enum(cls, 'Gateway_Communications_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x86E0 <= value <= 0x86EF:
            #: Landis & Gyr Powers [Neil Sembower]
            extend_enum(cls, 'Landis_Gyr_Powers_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8700 <= value <= 0x8710:
            #: Motorola [Neil Sembower]
            extend_enum(cls, 'Motorola_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8A96 <= value <= 0x8A97:
            #: Invisible Software [Neil Sembower]
            extend_enum(cls, 'Invisible_Software_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0xFF00 <= value <= 0xFF0F:
            #: ISC Bunker Ramo [Neil Sembower]
            extend_enum(cls, 'ISC_Bunker_Ramo_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        return super()._missing_(value)
