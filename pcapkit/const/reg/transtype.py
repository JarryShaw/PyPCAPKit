# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Transport Layer Protocol Numbers
======================================

.. module:: pcapkit.const.reg.transtype

This module contains the constant enumeration for **Transport Layer Protocol Numbers**,
which is automatically generated from :class:`pcapkit.vendor.reg.transtype.TransType`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['TransType']


class TransType(IntEnum):
    """[TransType] Transport Layer Protocol Numbers"""

    #: IPv6 Hop-by-Hop Option [:rfc:`8200`]
    HOPOPT = 0

    #: Internet Control Message [:rfc:`792`]
    ICMP = 1

    #: Internet Group Management [:rfc:`1112`]
    IGMP = 2

    #: Gateway-to-Gateway [:rfc:`823`]
    GGP = 3

    #: IPv4 encapsulation [:rfc:`2003`]
    IPv4 = 4

    #: Stream [:rfc:`1190`][:rfc:`1819`]
    ST = 5

    #: Transmission Control [:rfc:`9293`]
    TCP = 6

    #: CBT [Tony Ballardie]
    CBT = 7

    #: Exterior Gateway Protocol [:rfc:`888`][David Mills]
    EGP = 8

    #: any private interior gateway (used by Cisco for their IGRP) [Internet
    #: Assigned Numbers Authority]
    IGP = 9

    #: BBN RCC Monitoring [Steve Chipman]
    BBN_RCC_MON = 10

    #: Network Voice Protocol [:rfc:`741`][Steve Casner]
    NVP_II = 11

    #: PUP [Boggs, D., J. Shoch, E. Taft, and R. Metcalfe, "PUP: An Internetwork
    #: Architecture", XEROX Palo Alto Research Center, CSL-79-10, July 1979; also
    #: in IEEE Transactions on Communication, Volume COM-28, Number 4, April
    #: 1980.][XEROX]
    PUP = 12

    #: ARGUS (deprecated)) [Robert W Scheifler]
    ARGUS = 13

    #: EMCON [Bich Nguyen]
    EMCON = 14

    #: Cross Net Debugger [Haverty, J., "XNET Formats for Internet Protocol Version
    #: 4", IEN 158, October 1980.][Jack Haverty]
    XNET = 15

    #: Chaos [J Noel Chiappa]
    CHAOS = 16

    #: User Datagram [:rfc:`768`][Jon Postel]
    UDP = 17

    #: Multiplexing [Cohen, D. and J. Postel, "Multiplexing Protocol", IEN 90,
    #: USC/Information Sciences Institute, May 1979.][Jon Postel]
    MUX = 18

    #: DCN Measurement Subsystems [David Mills]
    DCN_MEAS = 19

    #: Host Monitoring [:rfc:`869`][Bob Hinden]
    HMP = 20

    #: Packet Radio Measurement [Zaw Sing Su]
    PRM = 21

    #: XEROX NS IDP ["The Ethernet, A Local Area Network: Data Link Layer and
    #: Physical Layer Specification", AA-K759B-TK, Digital Equipment Corporation,
    #: Maynard, MA. Also as: "The Ethernet - A Local Area Network", Version 1.0,
    #: Digital Equipment Corporation, Intel Corporation, Xerox Corporation,
    #: September 1980. And: "The Ethernet, A Local Area Network: Data Link Layer
    #: and Physical Layer Specifications", Digital, Intel and Xerox, November 1982.
    #: And: XEROX, "The Ethernet, A Local Area Network: Data Link Layer and
    #: Physical Layer Specification", X3T51/80-50, Xerox Corporation, Stamford,
    #: CT., October 1980.][XEROX]
    XNS_IDP = 22

    #: Trunk-1 [Barry Boehm]
    TRUNK_1 = 23

    #: Trunk-2 [Barry Boehm]
    TRUNK_2 = 24

    #: Leaf-1 [Barry Boehm]
    LEAF_1 = 25

    #: Leaf-2 [Barry Boehm]
    LEAF_2 = 26

    #: Reliable Data Protocol [:rfc:`908`][Bob Hinden]
    RDP = 27

    #: Internet Reliable Transaction [:rfc:`938`][Trudy Miller]
    IRTP = 28

    #: ISO Transport Protocol Class 4 [:rfc:`905`][Robert Cole]
    ISO_TP4 = 29

    #: Bulk Data Transfer Protocol [:rfc:`969`][David Clark]
    NETBLT = 30

    #: MFE Network Services Protocol [Shuttleworth, B., "A Documentary of MFENet, a
    #: National Computer Network", UCRL-52317, Lawrence Livermore Labs, Livermore,
    #: California, June 1977.][Barry Howard]
    MFE_NSP = 31

    #: MERIT Internodal Protocol [Hans Werner Braun]
    MERIT_INP = 32

    #: Datagram Congestion Control Protocol [:rfc:`4340`]
    DCCP = 33

    #: Third Party Connect Protocol [Stuart A Friedberg]
    TransType_3PC = 34

    #: Inter-Domain Policy Routing Protocol [Martha Steenstrup]
    IDPR = 35

    #: XTP [Greg Chesson]
    XTP = 36

    #: Datagram Delivery Protocol [Wesley Craig]
    DDP = 37

    #: IDPR Control Message Transport Proto [Martha Steenstrup]
    IDPR_CMTP = 38

    #: TP++ Transport Protocol [Dirk Fromhein]
    TP = 39

    #: IL Transport Protocol [Dave Presotto]
    IL = 40

    #: IPv6 encapsulation [:rfc:`2473`]
    IPv6 = 41

    #: Source Demand Routing Protocol [Deborah Estrin]
    SDRP = 42

    #: Routing Header for IPv6 [Steve Deering]
    IPv6_Route = 43

    #: Fragment Header for IPv6 [Steve Deering]
    IPv6_Frag = 44

    #: Inter-Domain Routing Protocol [Sue Hares]
    IDRP = 45

    #: Reservation Protocol [:rfc:`2205`][:rfc:`3209`][Bob Braden]
    RSVP = 46

    #: Generic Routing Encapsulation [:rfc:`2784`][Tony Li]
    GRE = 47

    #: Dynamic Source Routing Protocol [:rfc:`4728`]
    DSR = 48

    #: BNA [Gary Salamon]
    BNA = 49

    #: Encap Security Payload [:rfc:`4303`]
    ESP = 50

    #: Authentication Header [:rfc:`4302`]
    AH = 51

    #: Integrated Net Layer Security TUBA [K Robert Glenn]
    I_NLSP = 52

    #: IP with Encryption (deprecated)) [John Ioannidis]
    SWIPE = 53

    #: NBMA Address Resolution Protocol [:rfc:`1735`]
    NARP = 54

    #: Minimal IPv4 Encapsulation [:rfc:`2004`][Charlie Perkins]
    Min_IPv4 = 55

    #: Transport Layer Security Protocol using Kryptonet key management [Christer
    #: Oberg]
    TLSP = 56

    #: SKIP [Tom Markson]
    SKIP = 57

    #: ICMP for IPv6 [:rfc:`8200`]
    IPv6_ICMP = 58

    #: No Next Header for IPv6 [:rfc:`8200`]
    IPv6_NoNxt = 59

    #: Destination Options for IPv6 [:rfc:`8200`]
    IPv6_Opts = 60

    #: any host internal protocol [Internet Assigned Numbers Authority]
    any_host_internal_protocol = 61

    #: CFTP [Forsdick, H., "CFTP", Network Message, Bolt Beranek and Newman,
    #: January 1982.][Harry Forsdick]
    CFTP = 62

    #: any local network [Internet Assigned Numbers Authority]
    any_local_network = 63

    #: SATNET and Backroom EXPAK [Steven Blumenthal]
    SAT_EXPAK = 64

    #: Kryptolan [Paul Liu]
    KRYPTOLAN = 65

    #: MIT Remote Virtual Disk Protocol [Michael Greenwald]
    RVD = 66

    #: Internet Pluribus Packet Core [Steven Blumenthal]
    IPPC = 67

    #: any distributed file system [Internet Assigned Numbers Authority]
    any_distributed_file_system = 68

    #: SATNET Monitoring [Steven Blumenthal]
    SAT_MON = 69

    #: VISA Protocol [Gene Tsudik]
    VISA = 70

    #: Internet Packet Core Utility [Steven Blumenthal]
    IPCV = 71

    #: Computer Protocol Network Executive [David Mittnacht]
    CPNX = 72

    #: Computer Protocol Heart Beat [David Mittnacht]
    CPHB = 73

    #: Wang Span Network [Victor Dafoulas]
    WSN = 74

    #: Packet Video Protocol [Steve Casner]
    PVP = 75

    #: Backroom SATNET Monitoring [Steven Blumenthal]
    BR_SAT_MON = 76

    #: SUN ND PROTOCOL-Temporary [William Melohn]
    SUN_ND = 77

    #: WIDEBAND Monitoring [Steven Blumenthal]
    WB_MON = 78

    #: WIDEBAND EXPAK [Steven Blumenthal]
    WB_EXPAK = 79

    #: ISO Internet Protocol [Marshall T Rose]
    ISO_IP = 80

    #: VMTP [Dave Cheriton]
    VMTP = 81

    #: SECURE-VMTP [Dave Cheriton]
    SECURE_VMTP = 82

    #: VINES [Brian Horn]
    VINES = 83

    #: Internet Protocol Traffic Manager [Jim Stevens][1]
    IPTM = 84

    #: NSFNET-IGP [Hans Werner Braun]
    NSFNET_IGP = 85

    #: Dissimilar Gateway Protocol [M/A-COM Government Systems, "Dissimilar Gateway
    #: Protocol Specification, Draft Version", Contract no. CS901145, November 16,
    #: 1987.][Mike Little]
    DGP = 86

    #: TCF [Guillermo A Loyola]
    TCF = 87

    #: EIGRP [:rfc:`7868`]
    EIGRP = 88

    #: OSPFIGP [:rfc:`1583`][:rfc:`2328`][:rfc:`5340`][John Moy]
    OSPFIGP = 89

    #: Sprite RPC Protocol [Welch, B., "The Sprite Remote Procedure Call System",
    #: Technical Report, UCB/Computer Science Dept., 86/302, University of
    #: California at Berkeley, June 1986.][Bruce Willins]
    Sprite_RPC = 90

    #: Locus Address Resolution Protocol [Brian Horn]
    LARP = 91

    #: Multicast Transport Protocol [Susie Armstrong]
    MTP = 92

    #: AX.25 Frames [Brian Kantor]
    AX_25 = 93

    #: IP-within-IP Encapsulation Protocol [John Ioannidis]
    IPIP = 94

    #: Mobile Internetworking Control Pro. (deprecated)) [John Ioannidis]
    MICP = 95

    #: Semaphore Communications Sec. Pro. [Howard Hart]
    SCC_SP = 96

    #: Ethernet-within-IP Encapsulation [:rfc:`3378`]
    ETHERIP = 97

    #: Encapsulation Header [:rfc:`1241`][Robert Woodburn]
    ENCAP = 98

    #: any private encryption scheme [Internet Assigned Numbers Authority]
    any_private_encryption_scheme = 99

    #: GMTP [RXB5]
    GMTP = 100

    #: Ipsilon Flow Management Protocol [Bob Hinden][November 1995, 1997.]
    IFMP = 101

    #: PNNI over IP [Ross Callon]
    PNNI = 102

    #: Protocol Independent Multicast [:rfc:`7761`][Dino Farinacci]
    PIM = 103

    #: ARIS [Nancy Feldman]
    ARIS = 104

    #: SCPS [Robert Durst]
    SCPS = 105

    #: QNX [Michael Hunter]
    QNX = 106

    #: Active Networks [Bob Braden]
    A_N = 107

    #: IP Payload Compression Protocol [:rfc:`2393`]
    IPComp = 108

    #: Sitara Networks Protocol [Manickam R Sridhar]
    SNP = 109

    #: Compaq Peer Protocol [Victor Volpe]
    Compaq_Peer = 110

    #: IPX in IP [CJ Lee]
    IPX_in_IP = 111

    #: Virtual Router Redundancy Protocol [:rfc:`9568`]
    VRRP = 112

    #: PGM Reliable Transport Protocol [Tony Speakman]
    PGM = 113

    #: any 0-hop protocol [Internet Assigned Numbers Authority]
    any_0_hop_protocol = 114

    #: Layer Two Tunneling Protocol [:rfc:`3931`][Bernard Aboba]
    L2TP = 115

    #: D-II Data Exchange (DDX) [John Worley]
    DDX = 116

    #: Interactive Agent Transfer Protocol [John Murphy]
    IATP = 117

    #: Schedule Transfer Protocol [Jean Michel Pittet]
    STP = 118

    #: SpectraLink Radio Protocol [Mark Hamilton]
    SRP = 119

    #: UTI [Peter Lothberg]
    UTI = 120

    #: Simple Message Protocol [Leif Ekblad]
    SMP = 121

    #: Simple Multicast Protocol (deprecated)) [Jon Crowcroft][draft-perlman-
    #: simple-multicast]
    SM = 122

    #: Performance Transparency Protocol [Michael Welzl]
    PTP = 123

    #: [Tony Przygienda]
    ISIS_over_IPv4 = 124

    #: [Criag Partridge]
    FIRE = 125

    #: Combat Radio Transport Protocol [Robert Sautter]
    CRTP = 126

    #: Combat Radio User Datagram [Robert Sautter]
    CRUDP = 127

    #: [Kurt Waber]
    SSCOPMCE = 128

    #: [Hollbach]
    IPLT = 129

    #: Secure Packet Shield [Bill McIntosh]
    SPS = 130

    #: Private IP Encapsulation within IP [Bernhard Petri]
    PIPE = 131

    #: Stream Control Transmission Protocol [Randall R Stewart]
    SCTP = 132

    #: Fibre Channel [Murali Rajagopal][:rfc:`6172`]
    FC = 133

    #: [:rfc:`3175`]
    RSVP_E2E_IGNORE = 134

    #: [:rfc:`6275`]
    Mobility_Header = 135

    #: [:rfc:`3828`]
    UDPLite = 136

    #: [:rfc:`4023`]
    MPLS_in_IP = 137

    #: MANET Protocols [:rfc:`5498`]
    manet = 138

    #: Host Identity Protocol [:rfc:`7401`]
    HIP = 139

    #: Shim6 Protocol [:rfc:`5533`]
    Shim6 = 140

    #: Wrapped Encapsulating Security Payload [:rfc:`5840`]
    WESP = 141

    #: Robust Header Compression [:rfc:`5858`]
    ROHC = 142

    #: Ethernet [:rfc:`8986`]
    Ethernet = 143

    #: AGGFRAG encapsulation payload for ESP [:rfc:`9347`]
    AGGFRAG = 144

    #: Network Service Header [:rfc:`9491`]
    NSH = 145

    #: Homa [HomaModule][John Ousterhout]
    Homa = 146

    #: Use for experimentation and testing [:rfc:`3692`]
    Use_for_experimentation_and_testing_253 = 253

    #: Use for experimentation and testing [:rfc:`3692`]
    Use_for_experimentation_and_testing_254 = 254

    #: [Internet Assigned Numbers Authority]
    Reserved_255 = 255

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'TransType':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return TransType(key)
        if key not in TransType._member_map_:  # pylint: disable=no-member
            return extend_enum(TransType, key, default)
        return TransType[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'TransType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 147 <= value <= 252:
            #: Unassigned [Internet Assigned Numbers Authority]
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)
