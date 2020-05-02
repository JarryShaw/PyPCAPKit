# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Ethertype IEEE 802 Numbers"""

from aenum import IntEnum, extend_enum

__all__ = ['EtherType']


class EtherType(IntEnum):
    """[EtherType] Ethertype IEEE 802 Numbers"""

    _ignore_ = 'EtherType _'
    EtherType = vars()

    #: [Boggs, D., J. Shoch, E. Taft, and R. Metcalfe, "PUP: An Internetwork Architecture", XEROX Palo Alto Research Center, CSL-79-10, July 1979; also in IEEE Transactions on Communication, Volume COM-28, Number 4, April 1980.][Neil Sembower]
    EtherType['XEROX_PUP'] = 0x0200

    #: [Neil Sembower]
    EtherType['PUP_Addr_Trans_0x0201'] = 0x0201

    #: [Neil Sembower]
    EtherType['Nixdorf'] = 0x0400

    #: ["The Ethernet, A Local Area Network: Data Link Layer and Physical Layer Specification", AA-K759B-TK, Digital Equipment Corporation, Maynard, MA. Also as: "The Ethernet - A Local Area Network", Version 1.0, Digital Equipment Corporation, Intel Corporation, Xerox Corporation, September 1980. And: "The Ethernet, A Local Area Network: Data Link Layer and Physical Layer Specifications", Digital, Intel and Xerox, November 1982. And: XEROX, "The Ethernet, A Local Area Network: Data Link Layer and Physical Layer Specification", X3T51/80-50, Xerox Corporation, Stamford, CT., October 1980.][Neil Sembower]
    EtherType['XEROX_NS_IDP'] = 0x0600

    #: [Neil Sembower]
    EtherType['DLOG_0x0660'] = 0x0660

    #: [Neil Sembower]
    EtherType['DLOG_0x0661'] = 0x0661

    #: [:rfc:`7042`]
    EtherType['Internet_Protocol_Version_4'] = 0x0800

    #: [Neil Sembower]
    EtherType['X_75_Internet'] = 0x0801

    #: [Neil Sembower]
    EtherType['NBS_Internet'] = 0x0802

    #: [Neil Sembower]
    EtherType['ECMA_Internet'] = 0x0803

    #: [Neil Sembower]
    EtherType['Chaosnet'] = 0x0804

    #: [Neil Sembower]
    EtherType['X_25_Level_3'] = 0x0805

    #: [:rfc:`7042`]
    EtherType['Address_Resolution_Protocol'] = 0x0806

    #: [Neil Sembower]
    EtherType['XNS_Compatability'] = 0x0807

    #: [:rfc:`1701`]
    EtherType['Frame_Relay_ARP'] = 0x0808

    #: [David Plummer]
    EtherType['Symbolics_Private'] = 0x081C

    #: [Neil Sembower]
    EtherType['Ungermann_Bass_Net_Debugr'] = 0x0900

    #: [Neil Sembower]
    EtherType['Xerox_IEEE802_3_PUP'] = 0x0A00

    #: [Neil Sembower]
    EtherType['PUP_Addr_Trans_0x0A01'] = 0x0A01

    #: [Neil Sembower]
    EtherType['Banyan_VINES'] = 0x0BAD

    #: [:rfc:`1701`]
    EtherType['VINES_Loopback'] = 0x0BAE

    #: [:rfc:`1701`]
    EtherType['VINES_Echo'] = 0x0BAF

    #: [Neil Sembower]
    EtherType['Berkeley_Trailer_Nego'] = 0x1000

    #: [Neil Sembower]
    EtherType['Valid_Systems'] = 0x1600

    #: [:rfc:`6325`]
    EtherType['TRILL'] = 0x22F3

    #: [:rfc:`6325`]
    EtherType['L2_IS_IS'] = 0x22F4

    #: [Neil Sembower]
    EtherType['PCS_Basic_Block_Protocol'] = 0x4242

    #: [Neil Sembower]
    EtherType['BBN_Simnet'] = 0x5208

    #: [Neil Sembower]
    EtherType['DEC_Unassigned_0x6000'] = 0x6000

    #: [Neil Sembower]
    EtherType['DEC_MOP_Dump_Load'] = 0x6001

    #: [Neil Sembower]
    EtherType['DEC_MOP_Remote_Console'] = 0x6002

    #: [Neil Sembower]
    EtherType['DEC_DECNET_Phase_IV_Route'] = 0x6003

    #: [Neil Sembower]
    EtherType['DEC_LAT'] = 0x6004

    #: [Neil Sembower]
    EtherType['DEC_Diagnostic_Protocol'] = 0x6005

    #: [Neil Sembower]
    EtherType['DEC_Customer_Protocol'] = 0x6006

    #: [Neil Sembower]
    EtherType['DEC_LAVC_SCA'] = 0x6007

    #: [:rfc:`1701`]
    EtherType['Trans_Ether_Bridging'] = 0x6558

    #: [:rfc:`1701`]
    EtherType['Raw_Frame_Relay'] = 0x6559

    #: [Neil Sembower]
    EtherType['Ungermann_Bass_Download'] = 0x7000

    #: [Neil Sembower]
    EtherType['Ungermann_Bass_Dia_loop'] = 0x7002

    #: [Neil Sembower]
    EtherType['Proteon'] = 0x7030

    #: [Neil Sembower]
    EtherType['Cabletron'] = 0x7034

    #: [:rfc:`824`][Daniel Tappan]
    EtherType['Cronus_VLN'] = 0x8003

    #: [:rfc:`824`][Daniel Tappan]
    EtherType['Cronus_Direct'] = 0x8004

    #: [Neil Sembower]
    EtherType['HP_Probe'] = 0x8005

    #: [Neil Sembower]
    EtherType['Nestar'] = 0x8006

    #: [Neil Sembower]
    EtherType['AT_T_0x8008'] = 0x8008

    #: [Neil Sembower]
    EtherType['Excelan'] = 0x8010

    #: [Andrew Cherenson]
    EtherType['SGI_Diagnostics'] = 0x8013

    #: [Andrew Cherenson]
    EtherType['SGI_Network_Games'] = 0x8014

    #: [Andrew Cherenson]
    EtherType['SGI_Reserved'] = 0x8015

    #: [Andrew Cherenson]
    EtherType['SGI_Bounce_Server'] = 0x8016

    #: [Neil Sembower]
    EtherType['Apollo_Domain'] = 0x8019

    #: [Neil Sembower]
    EtherType['Tymshare'] = 0x802E

    #: [Neil Sembower]
    EtherType['Tigan_Inc'] = 0x802F

    #: [:rfc:`903`][Joseph Murdock]
    EtherType['Reverse_Address_Resolution_Protocol'] = 0x8035

    #: [Neil Sembower]
    EtherType['Aeonic_Systems'] = 0x8036

    #: [Neil Sembower]
    EtherType['DEC_LANBridge'] = 0x8038

    #: [Neil Sembower]
    EtherType['DEC_Ethernet_Encryption'] = 0x803D

    #: [Neil Sembower]
    EtherType['DEC_Unassigned_0x803E'] = 0x803E

    #: [Neil Sembower]
    EtherType['DEC_LAN_Traffic_Monitor'] = 0x803F

    #: [Neil Sembower]
    EtherType['Planning_Research_Corp'] = 0x8044

    #: [Neil Sembower]
    EtherType['AT_T_0x8046'] = 0x8046

    #: [Neil Sembower]
    EtherType['AT_T_0x8047'] = 0x8047

    #: [Neil Sembower]
    EtherType['ExperData'] = 0x8049

    #: [Neil Sembower]
    EtherType['Stanford_V_Kernel_Exp'] = 0x805B

    #: [Neil Sembower]
    EtherType['Stanford_V_Kernel_Prod'] = 0x805C

    #: [Neil Sembower]
    EtherType['Evans_Sutherland'] = 0x805D

    #: [Neil Sembower]
    EtherType['Little_Machines'] = 0x8060

    #: [Neil Sembower]
    EtherType['Counterpoint_Computers'] = 0x8062

    #: [Neil Sembower]
    EtherType['Univ_Of_Mass_Amherst_0x8065'] = 0x8065

    #: [Neil Sembower]
    EtherType['Univ_Of_Mass_Amherst_0x8066'] = 0x8066

    #: [Neil Sembower]
    EtherType['Veeco_Integrated_Auto'] = 0x8067

    #: [Neil Sembower]
    EtherType['General_Dynamics'] = 0x8068

    #: [Neil Sembower]
    EtherType['AT_T_0x8069'] = 0x8069

    #: [Neil Sembower]
    EtherType['Autophon'] = 0x806A

    #: [Neil Sembower]
    EtherType['ComDesign'] = 0x806C

    #: [Neil Sembower]
    EtherType['Computgraphic_Corp'] = 0x806D

    #: [Neil Sembower]
    EtherType['Matra'] = 0x807A

    #: [Neil Sembower]
    EtherType['Dansk_Data_Elektronik'] = 0x807B

    #: [Hans Werner Braun]
    EtherType['Merit_Internodal'] = 0x807C

    #: [Neil Sembower]
    EtherType['Vitalink_TransLAN_III'] = 0x8080

    #: [Neil Sembower]
    EtherType['Appletalk'] = 0x809B

    #: [Neil Sembower]
    EtherType['Spider_Systems_Ltd'] = 0x809F

    #: [Neil Sembower]
    EtherType['Nixdorf_Computers'] = 0x80A3

    #: [Neil Sembower]
    EtherType['Banyan_Systems_0x80C4'] = 0x80C4

    #: [Neil Sembower]
    EtherType['Banyan_Systems_0x80C5'] = 0x80C5

    #: [Neil Sembower]
    EtherType['Pacer_Software'] = 0x80C6

    #: [Neil Sembower]
    EtherType['Applitek_Corporation'] = 0x80C7

    #: [Neil Sembower]
    EtherType['IBM_SNA_Service_On_Ether'] = 0x80D5

    #: [Neil Sembower]
    EtherType['Varian_Associates'] = 0x80DD

    #: [Neil Sembower]
    EtherType['Retix'] = 0x80F2

    #: [Neil Sembower]
    EtherType['AppleTalk_AARP'] = 0x80F3

    #: [Neil Sembower]
    EtherType['Apollo_Computer'] = 0x80F7

    #: [Neil Sembower]
    EtherType['Wellfleet_Communications'] = 0x80FF

    #: [:rfc:`7042`]
    EtherType['Customer_VLAN_Tag_Type'] = 0x8100

    #: [Neil Sembower]
    EtherType['Hayes_Microcomputers'] = 0x8130

    #: [Neil Sembower]
    EtherType['VG_Laboratory_Systems'] = 0x8131

    #: [Neil Sembower]
    EtherType['Logicraft'] = 0x8148

    #: [Neil Sembower]
    EtherType['Network_Computing_Devices'] = 0x8149

    #: [Neil Sembower]
    EtherType['Alpha_Micro'] = 0x814A

    #: [Joyce K Reynolds]
    EtherType['SNMP'] = 0x814C

    #: [Neil Sembower]
    EtherType['BIIN_0x814D'] = 0x814D

    #: [Neil Sembower]
    EtherType['BIIN_0x814E'] = 0x814E

    #: [Neil Sembower]
    EtherType['Technically_Elite_Concept'] = 0x814F

    #: [Neil Sembower]
    EtherType['Rational_Corp'] = 0x8150

    #: [Neil Sembower]
    EtherType['XTP'] = 0x817D

    #: [Neil Sembower]
    EtherType['SGI_Time_Warner_Prop'] = 0x817E

    #: [Neil Sembower]
    EtherType['HIPPI_FP_Encapsulation'] = 0x8180

    #: [Neil Sembower]
    EtherType['STP_HIPPI_ST'] = 0x8181

    #: [Neil Sembower]
    EtherType['Reserved_For_HIPPI_6400_0x8182'] = 0x8182

    #: [Neil Sembower]
    EtherType['Reserved_For_HIPPI_6400_0x8183'] = 0x8183

    #: [Neil Sembower]
    EtherType['Motorola_Computer'] = 0x818D

    #: [Neil Sembower]
    EtherType['ARAI_Bunkichi'] = 0x81A4

    #: [Neil Sembower]
    EtherType['SECTRA'] = 0x86DB

    #: [Neil Sembower]
    EtherType['Delta_Controls'] = 0x86DE

    #: [:rfc:`7042`]
    EtherType['Internet_Protocol_Version_6'] = 0x86DD

    #: [Joe Touch]
    EtherType['ATOMIC'] = 0x86DF

    #: [:rfc:`1144`][:rfc:`1701`]
    EtherType['TCP_IP_Compression'] = 0x876B

    #: [:rfc:`1701`]
    EtherType['IP_Autonomous_Systems'] = 0x876C

    #: [:rfc:`1701`]
    EtherType['Secure_Data'] = 0x876D

    #: [EPON][:rfc:`7042`]
    EtherType['IEEE_Std_802_3_Ethernet_Passive_Optical_Network'] = 0x8808

    #: [:rfc:`7042`]
    EtherType['Point_to_Point_Protocol'] = 0x880B

    #: [:rfc:`7042`]
    EtherType['General_Switch_Management_Protocol'] = 0x880C

    #: [:rfc:`5332`]
    EtherType['MPLS'] = 0x8847

    #: [:rfc:`5332`]
    EtherType['MPLS_With_Upstream_assigned_Label'] = 0x8848

    #: [:rfc:`7042`]
    EtherType['Multicast_Channel_Allocation_Protocol'] = 0x8861

    #: [:rfc:`2516`]
    EtherType['PPP_Over_Ethernet_Discovery_Stage'] = 0x8863

    #: [:rfc:`2516`]
    EtherType['PPP_Over_Ethernet_Session_Stage'] = 0x8864

    #: [IEEE]
    EtherType['IEEE_Std_802_1X_Port_based_Network_Access_Control'] = 0x888E

    #: [IEEE]
    EtherType['IEEE_Std_802_1Q_Service_VLAN_Tag_Identifier'] = 0x88A8

    #: [IEEE]
    EtherType['IEEE_Std_802_Local_Experimental_Ethertype_0x88B5'] = 0x88B5

    #: [IEEE]
    EtherType['IEEE_Std_802_Local_Experimental_Ethertype_0x88B6'] = 0x88B6

    #: [IEEE]
    EtherType['IEEE_Std_802_OUI_Extended_Ethertype'] = 0x88B7

    #: [IEEE]
    EtherType['IEEE_Std_802_11_Pre_Authentication'] = 0x88C7

    #: [IEEE]
    EtherType['IEEE_Std_802_1AB_Link_Layer_Discovery_Protocol'] = 0x88CC

    #: [IEEE]
    EtherType['IEEE_Std_802_1AE_Media_Access_Control_Security'] = 0x88E5

    #: [IEEE Std 802.1Q-2014]
    EtherType['Provider_Backbone_Bridging_Instance_Tag'] = 0x88E7

    #: [IEEE]
    EtherType['IEEE_Std_802_1Q_Multiple_VLAN_Registration_Protocol'] = 0x88F5

    #: [IEEE]
    EtherType['IEEE_Std_802_1Q_Multiple_Multicast_Registration_Protocol'] = 0x88F6

    #: [IEEE]
    EtherType['IEEE_Std_802_11_Fast_Roaming_Remote_Request'] = 0x890D

    #: [IEEE]
    EtherType['IEEE_Std_802_21_Media_Independent_Handover_Protocol'] = 0x8917

    #: [IEEE]
    EtherType['IEEE_Std_802_1Qbe_Multiple_I_SID_Registration_Protocol'] = 0x8929

    #: [:rfc:`7172`]
    EtherType['TRILL_Fine_Grained_Labeling'] = 0x893B

    #: [IEEE]
    EtherType['IEEE_Std_802_1Qbg_ECP_Protocol'] = 0x8940

    #: [:rfc:`7178`]
    EtherType['TRILL_RBridge_Channel'] = 0x8946

    #: [IEEE]
    EtherType['GeoNetworking_As_Defined_In_ETSI_EN_302_636_4_1'] = 0x8947

    #: [:rfc:`8300`]
    EtherType['NSH'] = 0x894F

    #: [Neil Sembower]
    EtherType['Loopback'] = 0x9000

    #: [Neil Sembower]
    EtherType['3Com_XNS_Sys_Mgmt'] = 0x9001

    #: [Neil Sembower]
    EtherType['3Com_TCP_IP_Sys'] = 0x9002

    #: [Neil Sembower]
    EtherType['3Com_Loop_Detect'] = 0x9003

    #: [:rfc:`8377`]
    EtherType['Multi_Topology'] = 0x9A22

    #: [:rfc:`7973`]
    EtherType['LoWPAN_Encapsulation'] = 0xA0ED

    #: [:rfc:`8157`]
    EtherType['The_Ethertype_Will_Be_Used_To_Identify_A_Channel_In_Which_Control_Messages_Are_Encapsulated_As_Payload_Of_GRE_Packets_When_A_GRE_Packet_Tagged_With_The_Ethertype_Is_Received_The_Payload_Will_Be_Handed_To_The_Network_Processor_For_Processing'] = 0xB7EA

    #: [Neil Sembower]
    EtherType['BBN_VITAL_LanBridge_Cache'] = 0xFF00

    #: [:rfc:`1701`]
    EtherType['Reserved'] = 0xFFFF

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
            #: [Neil Sembower]
            extend_enum(cls, 'IEEE802.3 Length Field [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x0101 <= value <= 0x01FF:
            #: [Neil Sembower]
            extend_enum(cls, 'Experimental [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x0888 <= value <= 0x088A:
            #: [Neil Sembower]
            extend_enum(cls, 'Xyplex [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x1001 <= value <= 0x100F:
            #: [Neil Sembower]
            extend_enum(cls, 'Berkeley Trailer encap/IP [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x6008 <= value <= 0x6009:
            #: [Neil Sembower]
            extend_enum(cls, 'DEC Unassigned [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x6010 <= value <= 0x6014:
            #: [Neil Sembower]
            extend_enum(cls, '3Com Corporation [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x7020 <= value <= 0x7029:
            #: [Neil Sembower]
            extend_enum(cls, 'LRT [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8039 <= value <= 0x803C:
            #: [Neil Sembower]
            extend_enum(cls, 'DEC Unassigned [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8040 <= value <= 0x8042:
            #: [Neil Sembower]
            extend_enum(cls, 'DEC Unassigned [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x806E <= value <= 0x8077:
            #: [Neil Sembower]
            extend_enum(cls, 'Landmark Graphics Corp. [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x807D <= value <= 0x807F:
            #: [Neil Sembower]
            extend_enum(cls, 'Vitalink Communications [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8081 <= value <= 0x8083:
            #: [Neil Sembower]
            extend_enum(cls, 'Counterpoint Computers [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x809C <= value <= 0x809E:
            #: [Neil Sembower]
            extend_enum(cls, 'Datability [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80A4 <= value <= 0x80B3:
            #: [Neil Sembower]
            extend_enum(cls, 'Siemens Gammasonics Inc. [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80C0 <= value <= 0x80C3:
            #: [Neil Sembower]
            extend_enum(cls, 'DCA Data Exchange Cluster [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80C8 <= value <= 0x80CC:
            #: [Neil Sembower]
            extend_enum(cls, 'Intergraph Corporation [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80CD <= value <= 0x80CE:
            #: [Neil Sembower]
            extend_enum(cls, 'Harris Corporation [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80CF <= value <= 0x80D2:
            #: [Neil Sembower]
            extend_enum(cls, 'Taylor Instrument [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80D3 <= value <= 0x80D4:
            #: [Neil Sembower]
            extend_enum(cls, 'Rosemount Corporation [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80DE <= value <= 0x80DF:
            #: [Neil Sembower]
            extend_enum(cls, 'Integrated Solutions TRFS [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80E0 <= value <= 0x80E3:
            #: [Neil Sembower]
            extend_enum(cls, 'Allen-Bradley [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80E4 <= value <= 0x80F0:
            #: [Neil Sembower]
            extend_enum(cls, 'Datability [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x80F4 <= value <= 0x80F5:
            #: [Neil Sembower]
            extend_enum(cls, 'Kinetics [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8101 <= value <= 0x8103:
            #: [Neil Sembower]
            extend_enum(cls, 'Wellfleet Communications [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8107 <= value <= 0x8109:
            #: [Neil Sembower]
            extend_enum(cls, 'Symbolics Private [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8132 <= value <= 0x8136:
            #: [Neil Sembower]
            extend_enum(cls, 'Bridge Communications [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8137 <= value <= 0x8138:
            #: [Neil Sembower]
            extend_enum(cls, 'Novell, Inc. [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8139 <= value <= 0x813D:
            #: [Neil Sembower]
            extend_enum(cls, 'KTI [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8151 <= value <= 0x8153:
            #: [Neil Sembower]
            extend_enum(cls, 'Qualcomm [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x815C <= value <= 0x815E:
            #: [Neil Sembower]
            extend_enum(cls, 'Computer Protocol Pty Ltd [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8164 <= value <= 0x8166:
            #: [Neil Sembower]
            extend_enum(cls, 'Charles River Data System [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8184 <= value <= 0x818C:
            #: [Neil Sembower]
            extend_enum(cls, 'Silicon Graphics prop. [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x819A <= value <= 0x81A3:
            #: [Neil Sembower]
            extend_enum(cls, 'Qualcomm [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81A5 <= value <= 0x81AE:
            #: [Neil Sembower]
            extend_enum(cls, 'RAD Network Devices [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81B7 <= value <= 0x81B9:
            #: [Neil Sembower]
            extend_enum(cls, 'Xyplex [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81CC <= value <= 0x81D5:
            #: [Neil Sembower]
            extend_enum(cls, 'Apricot Computers [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81D6 <= value <= 0x81DD:
            #: [Neil Sembower]
            extend_enum(cls, 'Artisoft [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81E6 <= value <= 0x81EF:
            #: [Neil Sembower]
            extend_enum(cls, 'Polygon [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81F0 <= value <= 0x81F2:
            #: [Neil Sembower]
            extend_enum(cls, 'Comsat Labs [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81F3 <= value <= 0x81F5:
            #: [Neil Sembower]
            extend_enum(cls, 'SAIC [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x81F6 <= value <= 0x81F8:
            #: [Neil Sembower]
            extend_enum(cls, 'VG Analytical [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8203 <= value <= 0x8205:
            #: [Neil Sembower]
            extend_enum(cls, 'Quantum Software [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8221 <= value <= 0x8222:
            #: [Neil Sembower]
            extend_enum(cls, 'Ascom Banking Systems [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x823E <= value <= 0x8240:
            #: [Neil Sembower]
            extend_enum(cls, 'Advanced Encryption Syste [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x827F <= value <= 0x8282:
            #: [Neil Sembower]
            extend_enum(cls, 'Athena Programming [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8263 <= value <= 0x826A:
            #: [Neil Sembower]
            extend_enum(cls, 'Charles River Data System [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x829A <= value <= 0x829B:
            #: [Neil Sembower]
            extend_enum(cls, 'Inst Ind Info Tech [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x829C <= value <= 0x82AB:
            #: [Neil Sembower]
            extend_enum(cls, 'Taurus Controls [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x82AC <= value <= 0x8693:
            #: [Neil Sembower]
            extend_enum(cls, 'Walker Richer & Quinn [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8694 <= value <= 0x869D:
            #: [Neil Sembower]
            extend_enum(cls, 'Idea Courier [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x869E <= value <= 0x86A1:
            #: [Neil Sembower]
            extend_enum(cls, 'Computer Network Tech [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x86A3 <= value <= 0x86AC:
            #: [Neil Sembower]
            extend_enum(cls, 'Gateway Communications [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x86E0 <= value <= 0x86EF:
            #: [Neil Sembower]
            extend_enum(cls, 'Landis & Gyr Powers [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8700 <= value <= 0x8710:
            #: [Neil Sembower]
            extend_enum(cls, 'Motorola [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x8A96 <= value <= 0x8A97:
            #: [Neil Sembower]
            extend_enum(cls, 'Invisible Software [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0xFF00 <= value <= 0xFF0F:
            #: [Neil Sembower]
            extend_enum(cls, 'ISC Bunker Ramo [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        return super()._missing_(value)
