# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Transport Layer Protocol Numbers"""

from aenum import IntEnum, extend_enum

__all__ = ['TransType']


class TransType(IntEnum):
    """[TransType] Transport Layer Protocol Numbers"""

    #: [:rfc:`8200`] IPv6 Hop-by-Hop Option
    HOPOPT = 0

    #: [:rfc:`792`] Internet Control Message
    ICMP = 1

    #: [:rfc:`1112`] Internet Group Management
    IGMP = 2

    #: [:rfc:`823`] Gateway-to-Gateway
    GGP = 3

    #: [:rfc:`2003`] IPv4 encapsulation
    IPv4 = 4

    #: [:rfc:`1190`][:rfc:`1819`] Stream
    ST = 5

    #: [:rfc:`793`] Transmission Control
    TCP = 6

    #: [Tony Ballardie] CBT
    CBT = 7

    #: [:rfc:`888`][David Mills] Exterior Gateway Protocol
    EGP = 8

    #: [Internet Assigned Numbers Authority] any private interior gateway (used by
    #: Cisco for their IGRP)
    IGP = 9

    #: [Steve Chipman] BBN RCC Monitoring
    BBN_RCC_MON = 10

    #: [:rfc:`741`][Steve Casner] Network Voice Protocol
    NVP_II = 11

    #: [Boggs, D., J. Shoch, E. Taft, and R. Metcalfe, "PUP: An Internetwork
    #: Architecture", XEROX Palo Alto Research Center, CSL-79-10, July 1979; also
    #: in IEEE Transactions on Communication, Volume COM-28, Number 4, April
    #: 1980.][XEROX] PUP
    PUP = 12

    #: [Robert W Scheifler] ARGUS (deprecated))
    ARGUS = 13

    #: [<mystery contact>] EMCON
    EMCON = 14

    #: [Haverty, J., "XNET Formats for Internet Protocol Version 4", IEN 158,
    #: October 1980.][Jack Haverty] Cross Net Debugger
    XNET = 15

    #: [J Noel Chiappa] Chaos
    CHAOS = 16

    #: [:rfc:`768`][Jon Postel] User Datagram
    UDP = 17

    #: [Cohen, D. and J. Postel, "Multiplexing Protocol", IEN 90, USC/Information
    #: Sciences Institute, May 1979.][Jon Postel] Multiplexing
    MUX = 18

    #: [David Mills] DCN Measurement Subsystems
    DCN_MEAS = 19

    #: [:rfc:`869`][Bob Hinden] Host Monitoring
    HMP = 20

    #: [Zaw Sing Su] Packet Radio Measurement
    PRM = 21

    #: ["The Ethernet, A Local Area Network: Data Link Layer and Physical Layer
    #: Specification", AA-K759B-TK, Digital Equipment Corporation, Maynard, MA.
    #: Also as: "The Ethernet - A Local Area Network", Version 1.0, Digital
    #: Equipment Corporation, Intel Corporation, Xerox Corporation, September 1980.
    #: And: "The Ethernet, A Local Area Network: Data Link Layer and Physical Layer
    #: Specifications", Digital, Intel and Xerox, November 1982. And: XEROX, "The
    #: Ethernet, A Local Area Network: Data Link Layer and Physical Layer
    #: Specification", X3T51/80-50, Xerox Corporation, Stamford, CT., October
    #: 1980.][XEROX] XEROX NS IDP
    XNS_IDP = 22

    #: [Barry Boehm] Trunk-1
    TRUNK_1 = 23

    #: [Barry Boehm] Trunk-2
    TRUNK_2 = 24

    #: [Barry Boehm] Leaf-1
    LEAF_1 = 25

    #: [Barry Boehm] Leaf-2
    LEAF_2 = 26

    #: [:rfc:`908`][Bob Hinden] Reliable Data Protocol
    RDP = 27

    #: [:rfc:`938`][Trudy Miller] Internet Reliable Transaction
    IRTP = 28

    #: [:rfc:`905`][<mystery contact>] ISO Transport Protocol Class 4
    ISO_TP4 = 29

    #: [:rfc:`969`][David Clark] Bulk Data Transfer Protocol
    NETBLT = 30

    #: [Shuttleworth, B., "A Documentary of MFENet, a National Computer Network",
    #: UCRL-52317, Lawrence Livermore Labs, Livermore, California, June
    #: 1977.][Barry Howard] MFE Network Services Protocol
    MFE_NSP = 31

    #: [Hans Werner Braun] MERIT Internodal Protocol
    MERIT_INP = 32

    #: [:rfc:`4340`] Datagram Congestion Control Protocol
    DCCP = 33

    #: [Stuart A Friedberg] Third Party Connect Protocol
    TransType_3PC = 34

    #: [Martha Steenstrup] Inter-Domain Policy Routing Protocol
    IDPR = 35

    #: [Greg Chesson] XTP
    XTP = 36

    #: [Wesley Craig] Datagram Delivery Protocol
    DDP = 37

    #: [Martha Steenstrup] IDPR Control Message Transport Proto
    IDPR_CMTP = 38

    #: [Dirk Fromhein] TP++ Transport Protocol
    TP = 39

    #: [Dave Presotto] IL Transport Protocol
    IL = 40

    #: [:rfc:`2473`] IPv6 encapsulation
    IPv6 = 41

    #: [Deborah Estrin] Source Demand Routing Protocol
    SDRP = 42

    #: [Steve Deering] Routing Header for IPv6
    IPv6_Route = 43

    #: [Steve Deering] Fragment Header for IPv6
    IPv6_Frag = 44

    #: [Sue Hares] Inter-Domain Routing Protocol
    IDRP = 45

    #: [:rfc:`2205`][:rfc:`3209`][Bob Braden] Reservation Protocol
    RSVP = 46

    #: [:rfc:`2784`][Tony Li] Generic Routing Encapsulation
    GRE = 47

    #: [:rfc:`4728`] Dynamic Source Routing Protocol
    DSR = 48

    #: [Gary Salamon] BNA
    BNA = 49

    #: [:rfc:`4303`] Encap Security Payload
    ESP = 50

    #: [:rfc:`4302`] Authentication Header
    AH = 51

    #: [K Robert Glenn] Integrated Net Layer Security TUBA
    I_NLSP = 52

    #: [John Ioannidis] IP with Encryption (deprecated))
    SWIPE = 53

    #: [:rfc:`1735`] NBMA Address Resolution Protocol
    NARP = 54

    #: [Charlie Perkins] IP Mobility
    MOBILE = 55

    #: [Christer Oberg] Transport Layer Security Protocol using Kryptonet key
    #: management
    TLSP = 56

    #: [Tom Markson] SKIP
    SKIP = 57

    #: [:rfc:`8200`] ICMP for IPv6
    IPv6_ICMP = 58

    #: [:rfc:`8200`] No Next Header for IPv6
    IPv6_NoNxt = 59

    #: [:rfc:`8200`] Destination Options for IPv6
    IPv6_Opts = 60

    #: [Internet Assigned Numbers Authority] any host internal protocol
    any_host_internal_protocol = 61

    #: [Forsdick, H., "CFTP", Network Message, Bolt Beranek and Newman, January
    #: 1982.][Harry Forsdick] CFTP
    CFTP = 62

    #: [Internet Assigned Numbers Authority] any local network
    any_local_network = 63

    #: [Steven Blumenthal] SATNET and Backroom EXPAK
    SAT_EXPAK = 64

    #: [Paul Liu] Kryptolan
    KRYPTOLAN = 65

    #: [Michael Greenwald] MIT Remote Virtual Disk Protocol
    RVD = 66

    #: [Steven Blumenthal] Internet Pluribus Packet Core
    IPPC = 67

    #: [Internet Assigned Numbers Authority] any distributed file system
    any_distributed_file_system = 68

    #: [Steven Blumenthal] SATNET Monitoring
    SAT_MON = 69

    #: [Gene Tsudik] VISA Protocol
    VISA = 70

    #: [Steven Blumenthal] Internet Packet Core Utility
    IPCV = 71

    #: [David Mittnacht] Computer Protocol Network Executive
    CPNX = 72

    #: [David Mittnacht] Computer Protocol Heart Beat
    CPHB = 73

    #: [Victor Dafoulas] Wang Span Network
    WSN = 74

    #: [Steve Casner] Packet Video Protocol
    PVP = 75

    #: [Steven Blumenthal] Backroom SATNET Monitoring
    BR_SAT_MON = 76

    #: [William Melohn] SUN ND PROTOCOL-Temporary
    SUN_ND = 77

    #: [Steven Blumenthal] WIDEBAND Monitoring
    WB_MON = 78

    #: [Steven Blumenthal] WIDEBAND EXPAK
    WB_EXPAK = 79

    #: [Marshall T Rose] ISO Internet Protocol
    ISO_IP = 80

    #: [Dave Cheriton] VMTP
    VMTP = 81

    #: [Dave Cheriton] SECURE-VMTP
    SECURE_VMTP = 82

    #: [Brian Horn] VINES
    VINES = 83

    #: [Jim Stevens] Transaction Transport Protocol
    TTP = 84

    #: [Jim Stevens] Internet Protocol Traffic Manager
    IPTM = 84

    #: [Hans Werner Braun] NSFNET-IGP
    NSFNET_IGP = 85

    #: [M/A-COM Government Systems, "Dissimilar Gateway Protocol Specification,
    #: Draft Version", Contract no. CS901145, November 16, 1987.][Mike Little]
    #: Dissimilar Gateway Protocol
    DGP = 86

    #: [Guillermo A Loyola] TCF
    TCF = 87

    #: [:rfc:`7868`] EIGRP
    EIGRP = 88

    #: [:rfc:`1583`][:rfc:`2328`][:rfc:`5340`][John Moy] OSPFIGP
    OSPFIGP = 89

    #: [Welch, B., "The Sprite Remote Procedure Call System", Technical Report,
    #: UCB/Computer Science Dept., 86/302, University of California at Berkeley,
    #: June 1986.][Bruce Willins] Sprite RPC Protocol
    Sprite_RPC = 90

    #: [Brian Horn] Locus Address Resolution Protocol
    LARP = 91

    #: [Susie Armstrong] Multicast Transport Protocol
    MTP = 92

    #: [Brian Kantor] AX.25 Frames
    AX_25 = 93

    #: [John Ioannidis] IP-within-IP Encapsulation Protocol
    IPIP = 94

    #: [John Ioannidis] Mobile Internetworking Control Pro. (deprecated))
    MICP = 95

    #: [Howard Hart] Semaphore Communications Sec. Pro.
    SCC_SP = 96

    #: [:rfc:`3378`] Ethernet-within-IP Encapsulation
    ETHERIP = 97

    #: [:rfc:`1241`][Robert Woodburn] Encapsulation Header
    ENCAP = 98

    #: [Internet Assigned Numbers Authority] any private encryption scheme
    any_private_encryption_scheme = 99

    #: [RXB5] GMTP
    GMTP = 100

    #: [Bob Hinden][November 1995, 1997.] Ipsilon Flow Management Protocol
    IFMP = 101

    #: [Ross Callon] PNNI over IP
    PNNI = 102

    #: [:rfc:`7761`][Dino Farinacci] Protocol Independent Multicast
    PIM = 103

    #: [Nancy Feldman] ARIS
    ARIS = 104

    #: [Robert Durst] SCPS
    SCPS = 105

    #: [Michael Hunter] QNX
    QNX = 106

    #: [Bob Braden] Active Networks
    A_N = 107

    #: [:rfc:`2393`] IP Payload Compression Protocol
    IPComp = 108

    #: [Manickam R Sridhar] Sitara Networks Protocol
    SNP = 109

    #: [Victor Volpe] Compaq Peer Protocol
    Compaq_Peer = 110

    #: [CJ Lee] IPX in IP
    IPX_in_IP = 111

    #: [:rfc:`5798`] Virtual Router Redundancy Protocol
    VRRP = 112

    #: [Tony Speakman] PGM Reliable Transport Protocol
    PGM = 113

    #: [Internet Assigned Numbers Authority] any 0-hop protocol
    any_0_hop_protocol = 114

    #: [:rfc:`3931`][Bernard Aboba] Layer Two Tunneling Protocol
    L2TP = 115

    #: [John Worley] D-II Data Exchange (DDX)
    DDX = 116

    #: [John Murphy] Interactive Agent Transfer Protocol
    IATP = 117

    #: [Jean Michel Pittet] Schedule Transfer Protocol
    STP = 118

    #: [Mark Hamilton] SpectraLink Radio Protocol
    SRP = 119

    #: [Peter Lothberg] UTI
    UTI = 120

    #: [Leif Ekblad] Simple Message Protocol
    SMP = 121

    #: [Jon Crowcroft][draft-perlman-simple-multicast] Simple Multicast Protocol
    #: (deprecated))
    SM = 122

    #: [Michael Welzl] Performance Transparency Protocol
    PTP = 123

    #: [Tony Przygienda]
    ISIS_over_IPv4 = 124

    #: [Criag Partridge]
    FIRE = 125

    #: [Robert Sautter] Combat Radio Transport Protocol
    CRTP = 126

    #: [Robert Sautter] Combat Radio User Datagram
    CRUDP = 127

    #: [Kurt Waber]
    SSCOPMCE = 128

    #: [Hollbach]
    IPLT = 129

    #: [Bill McIntosh] Secure Packet Shield
    SPS = 130

    #: [Bernhard Petri] Private IP Encapsulation within IP
    PIPE = 131

    #: [Randall R Stewart] Stream Control Transmission Protocol
    SCTP = 132

    #: [Murali Rajagopal][:rfc:`6172`] Fibre Channel
    FC = 133

    #: [:rfc:`3175`]
    RSVP_E2E_IGNORE = 134

    #: [:rfc:`6275`]
    Mobility_Header = 135

    #: [:rfc:`3828`]
    UDPLite = 136

    #: [:rfc:`4023`]
    MPLS_in_IP = 137

    #: [:rfc:`5498`] MANET Protocols
    manet = 138

    #: [:rfc:`7401`] Host Identity Protocol
    HIP = 139

    #: [:rfc:`5533`] Shim6 Protocol
    Shim6 = 140

    #: [:rfc:`5840`] Wrapped Encapsulating Security Payload
    WESP = 141

    #: [:rfc:`5858`] Robust Header Compression
    ROHC = 142

    #: [draft-ietf-spring-srv6-network-programming] Ethernet (TEMPORARY -
    #: registered 2020-01-31, expires 2021-01-31)
    Ethernet = 143

    #: [:rfc:`3692`] Use for experimentation and testing
    Use_for_experimentation_and_testing_253 = 253

    #: [:rfc:`3692`] Use for experimentation and testing
    Use_for_experimentation_and_testing_254 = 254

    #: [Internet Assigned Numbers Authority]
    Reserved = 255

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return TransType(key)
        if key not in TransType._member_map_:  # pylint: disable=no-member
            extend_enum(TransType, key, default)
        return TransType[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 144 <= value <= 252:
            #: [Internet Assigned Numbers Authority] Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        return super()._missing_(value)
