# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Transport Layer Protocol Numbers"""

from aenum import IntEnum, extend_enum

__all__ = ['TransType']


class TransType(IntEnum):
    """[TransType] Transport Layer Protocol Numbers"""

    _ignore_ = 'TransType _'
    TransType = vars()

    #: [:rfc:`8200`] IPv6 Hop-by-Hop Option
    TransType['HOPOPT'] = 0

    #: [:rfc:`792`] Internet Control Message
    TransType['ICMP'] = 1

    #: [:rfc:`1112`] Internet Group Management
    TransType['IGMP'] = 2

    #: [:rfc:`823`] Gateway-to-Gateway
    TransType['GGP'] = 3

    #: [:rfc:`2003`] IPv4 encapsulation
    TransType['IPv4'] = 4

    #: [:rfc:`1190`][:rfc:`1819`] Stream
    TransType['ST'] = 5

    #: [:rfc:`793`] Transmission Control
    TransType['TCP'] = 6

    #: [Tony Ballardie] CBT
    TransType['CBT'] = 7

    #: [:rfc:`888`][David Mills] Exterior Gateway Protocol
    TransType['EGP'] = 8

    #: [Internet Assigned Numbers Authority] any private interior gateway (used by Cisco for their IGRP)
    TransType['IGP'] = 9

    #: [Steve Chipman] BBN RCC Monitoring
    TransType['BBN_RCC_MON'] = 10

    #: [:rfc:`741`][Steve Casner] Network Voice Protocol
    TransType['NVP_II'] = 11

    #: [Boggs, D., J. Shoch, E. Taft, and R. Metcalfe, "PUP: An Internetwork Architecture", XEROX Palo Alto Research Center, CSL-79-10, July 1979; also in IEEE Transactions on Communication, Volume COM-28, Number 4, April 1980.][XEROX] PUP
    TransType['PUP'] = 12

    #: [Robert W Scheifler] ARGUS (deprecated)
    TransType['ARGUS'] = 13

    #: [<mystery contact>] EMCON
    TransType['EMCON'] = 14

    #: [Haverty, J., "XNET Formats for Internet Protocol Version 4", IEN 158, October 1980.][Jack Haverty] Cross Net Debugger
    TransType['XNET'] = 15

    #: [J Noel Chiappa] Chaos
    TransType['CHAOS'] = 16

    #: [:rfc:`768`][Jon Postel] User Datagram
    TransType['UDP'] = 17

    #: [Cohen, D. and J. Postel, "Multiplexing Protocol", IEN 90, USC/Information Sciences Institute, May 1979.][Jon Postel] Multiplexing
    TransType['MUX'] = 18

    #: [David Mills] DCN Measurement Subsystems
    TransType['DCN_MEAS'] = 19

    #: [:rfc:`869`][Bob Hinden] Host Monitoring
    TransType['HMP'] = 20

    #: [Zaw Sing Su] Packet Radio Measurement
    TransType['PRM'] = 21

    #: ["The Ethernet, A Local Area Network: Data Link Layer and Physical Layer Specification", AA-K759B-TK, Digital Equipment Corporation, Maynard, MA. Also as: "The Ethernet - A Local Area Network", Version 1.0, Digital Equipment Corporation, Intel Corporation, Xerox Corporation, September 1980. And: "The Ethernet, A Local Area Network: Data Link Layer and Physical Layer Specifications", Digital, Intel and Xerox, November 1982. And: XEROX, "The Ethernet, A Local Area Network: Data Link Layer and Physical Layer Specification", X3T51/80-50, Xerox Corporation, Stamford, CT., October 1980.][XEROX] XEROX NS IDP
    TransType['XNS_IDP'] = 22

    #: [Barry Boehm] Trunk-1
    TransType['TRUNK_1'] = 23

    #: [Barry Boehm] Trunk-2
    TransType['TRUNK_2'] = 24

    #: [Barry Boehm] Leaf-1
    TransType['LEAF_1'] = 25

    #: [Barry Boehm] Leaf-2
    TransType['LEAF_2'] = 26

    #: [:rfc:`908`][Bob Hinden] Reliable Data Protocol
    TransType['RDP'] = 27

    #: [:rfc:`938`][Trudy Miller] Internet Reliable Transaction
    TransType['IRTP'] = 28

    #: [:rfc:`905`][<mystery contact>] ISO Transport Protocol Class 4
    TransType['ISO_TP4'] = 29

    #: [:rfc:`969`][David Clark] Bulk Data Transfer Protocol
    TransType['NETBLT'] = 30

    #: [Shuttleworth, B., "A Documentary of MFENet, a National Computer Network", UCRL-52317, Lawrence Livermore Labs, Livermore, California, June 1977.][Barry Howard] MFE Network Services Protocol
    TransType['MFE_NSP'] = 31

    #: [Hans Werner Braun] MERIT Internodal Protocol
    TransType['MERIT_INP'] = 32

    #: [:rfc:`4340`] Datagram Congestion Control Protocol
    TransType['DCCP'] = 33

    #: [Stuart A Friedberg] Third Party Connect Protocol
    TransType['3PC'] = 34

    #: [Martha Steenstrup] Inter-Domain Policy Routing Protocol
    TransType['IDPR'] = 35

    #: [Greg Chesson] XTP
    TransType['XTP'] = 36

    #: [Wesley Craig] Datagram Delivery Protocol
    TransType['DDP'] = 37

    #: [Martha Steenstrup] IDPR Control Message Transport Proto
    TransType['IDPR_CMTP'] = 38

    #: [Dirk Fromhein] TP++ Transport Protocol
    TransType['TP'] = 39

    #: [Dave Presotto] IL Transport Protocol
    TransType['IL'] = 40

    #: [:rfc:`2473`] IPv6 encapsulation
    TransType['IPv6'] = 41

    #: [Deborah Estrin] Source Demand Routing Protocol
    TransType['SDRP'] = 42

    #: [Steve Deering] Routing Header for IPv6
    TransType['IPv6_Route'] = 43

    #: [Steve Deering] Fragment Header for IPv6
    TransType['IPv6_Frag'] = 44

    #: [Sue Hares] Inter-Domain Routing Protocol
    TransType['IDRP'] = 45

    #: [:rfc:`2205`][:rfc:`3209`][Bob Braden] Reservation Protocol
    TransType['RSVP'] = 46

    #: [:rfc:`2784`][Tony Li] Generic Routing Encapsulation
    TransType['GRE'] = 47

    #: [:rfc:`4728`] Dynamic Source Routing Protocol
    TransType['DSR'] = 48

    #: [Gary Salamon] BNA
    TransType['BNA'] = 49

    #: [:rfc:`4303`] Encap Security Payload
    TransType['ESP'] = 50

    #: [:rfc:`4302`] Authentication Header
    TransType['AH'] = 51

    #: [K Robert Glenn] Integrated Net Layer Security TUBA
    TransType['I_NLSP'] = 52

    #: [John Ioannidis] IP with Encryption (deprecated)
    TransType['SWIPE'] = 53

    #: [:rfc:`1735`] NBMA Address Resolution Protocol
    TransType['NARP'] = 54

    #: [Charlie Perkins] IP Mobility
    TransType['MOBILE'] = 55

    #: [Christer Oberg] Transport Layer Security Protocol using Kryptonet key management
    TransType['TLSP'] = 56

    #: [Tom Markson] SKIP
    TransType['SKIP'] = 57

    #: [:rfc:`8200`] ICMP for IPv6
    TransType['IPv6_ICMP'] = 58

    #: [:rfc:`8200`] No Next Header for IPv6
    TransType['IPv6_NoNxt'] = 59

    #: [:rfc:`8200`] Destination Options for IPv6
    TransType['IPv6_Opts'] = 60

    #: [Internet Assigned Numbers Authority]
    TransType['Any_Host_Internal_Protocol'] = 61

    #: [Forsdick, H., "CFTP", Network Message, Bolt Beranek and Newman, January 1982.][Harry Forsdick] CFTP
    TransType['CFTP'] = 62

    #: [Internet Assigned Numbers Authority]
    TransType['Any_Local_Network'] = 63

    #: [Steven Blumenthal] SATNET and Backroom EXPAK
    TransType['SAT_EXPAK'] = 64

    #: [Paul Liu] Kryptolan
    TransType['KRYPTOLAN'] = 65

    #: [Michael Greenwald] MIT Remote Virtual Disk Protocol
    TransType['RVD'] = 66

    #: [Steven Blumenthal] Internet Pluribus Packet Core
    TransType['IPPC'] = 67

    #: [Internet Assigned Numbers Authority]
    TransType['Any_Distributed_File_System'] = 68

    #: [Steven Blumenthal] SATNET Monitoring
    TransType['SAT_MON'] = 69

    #: [Gene Tsudik] VISA Protocol
    TransType['VISA'] = 70

    #: [Steven Blumenthal] Internet Packet Core Utility
    TransType['IPCV'] = 71

    #: [David Mittnacht] Computer Protocol Network Executive
    TransType['CPNX'] = 72

    #: [David Mittnacht] Computer Protocol Heart Beat
    TransType['CPHB'] = 73

    #: [Victor Dafoulas] Wang Span Network
    TransType['WSN'] = 74

    #: [Steve Casner] Packet Video Protocol
    TransType['PVP'] = 75

    #: [Steven Blumenthal] Backroom SATNET Monitoring
    TransType['BR_SAT_MON'] = 76

    #: [William Melohn] SUN ND PROTOCOL-Temporary
    TransType['SUN_ND'] = 77

    #: [Steven Blumenthal] WIDEBAND Monitoring
    TransType['WB_MON'] = 78

    #: [Steven Blumenthal] WIDEBAND EXPAK
    TransType['WB_EXPAK'] = 79

    #: [Marshall T Rose] ISO Internet Protocol
    TransType['ISO_IP'] = 80

    #: [Dave Cheriton] VMTP
    TransType['VMTP'] = 81

    #: [Dave Cheriton] SECURE-VMTP
    TransType['SECURE_VMTP'] = 82

    #: [Brian Horn] VINES
    TransType['VINES'] = 83

    #: [Jim Stevens] Transaction Transport Protocol
    TransType['TTP'] = 84

    #: [Jim Stevens] Internet Protocol Traffic Manager
    TransType['IPTM'] = 84

    #: [Hans Werner Braun] NSFNET-IGP
    TransType['NSFNET_IGP'] = 85

    #: [M/A-COM Government Systems, "Dissimilar Gateway Protocol Specification, Draft Version", Contract no. CS901145, November 16, 1987.][Mike Little] Dissimilar Gateway Protocol
    TransType['DGP'] = 86

    #: [Guillermo A Loyola] TCF
    TransType['TCF'] = 87

    #: [:rfc:`7868`] EIGRP
    TransType['EIGRP'] = 88

    #: [:rfc:`1583`][:rfc:`2328`][:rfc:`5340`][John Moy] OSPFIGP
    TransType['OSPFIGP'] = 89

    #: [Welch, B., "The Sprite Remote Procedure Call System", Technical Report, UCB/Computer Science Dept., 86/302, University of California at Berkeley, June 1986.][Bruce Willins] Sprite RPC Protocol
    TransType['Sprite_RPC'] = 90

    #: [Brian Horn] Locus Address Resolution Protocol
    TransType['LARP'] = 91

    #: [Susie Armstrong] Multicast Transport Protocol
    TransType['MTP'] = 92

    #: [Brian Kantor] AX.25 Frames
    TransType['AX_25'] = 93

    #: [John Ioannidis] IP-within-IP Encapsulation Protocol
    TransType['IPIP'] = 94

    #: [John Ioannidis] Mobile Internetworking Control Pro. (deprecated)
    TransType['MICP'] = 95

    #: [Howard Hart] Semaphore Communications Sec. Pro.
    TransType['SCC_SP'] = 96

    #: [:rfc:`3378`] Ethernet-within-IP Encapsulation
    TransType['ETHERIP'] = 97

    #: [:rfc:`1241`][Robert Woodburn] Encapsulation Header
    TransType['ENCAP'] = 98

    #: [Internet Assigned Numbers Authority]
    TransType['Any_Private_Encryption_Scheme'] = 99

    #: [RXB5] GMTP
    TransType['GMTP'] = 100

    #: [Bob Hinden][November 1995, 1997.] Ipsilon Flow Management Protocol
    TransType['IFMP'] = 101

    #: [Ross Callon] PNNI over IP
    TransType['PNNI'] = 102

    #: [:rfc:`7761`][Dino Farinacci] Protocol Independent Multicast
    TransType['PIM'] = 103

    #: [Nancy Feldman] ARIS
    TransType['ARIS'] = 104

    #: [Robert Durst] SCPS
    TransType['SCPS'] = 105

    #: [Michael Hunter] QNX
    TransType['QNX'] = 106

    #: [Bob Braden] Active Networks
    TransType['A_N'] = 107

    #: [:rfc:`2393`] IP Payload Compression Protocol
    TransType['IPComp'] = 108

    #: [Manickam R Sridhar] Sitara Networks Protocol
    TransType['SNP'] = 109

    #: [Victor Volpe] Compaq Peer Protocol
    TransType['Compaq_Peer'] = 110

    #: [CJ Lee] IPX in IP
    TransType['IPX_in_IP'] = 111

    #: [:rfc:`5798`] Virtual Router Redundancy Protocol
    TransType['VRRP'] = 112

    #: [Tony Speakman] PGM Reliable Transport Protocol
    TransType['PGM'] = 113

    #: [Internet Assigned Numbers Authority]
    TransType['Any_0_hop_Protocol'] = 114

    #: [:rfc:`3931`][Bernard Aboba] Layer Two Tunneling Protocol
    TransType['L2TP'] = 115

    #: [John Worley] D-II Data Exchange (DDX)
    TransType['DDX'] = 116

    #: [John Murphy] Interactive Agent Transfer Protocol
    TransType['IATP'] = 117

    #: [Jean Michel Pittet] Schedule Transfer Protocol
    TransType['STP'] = 118

    #: [Mark Hamilton] SpectraLink Radio Protocol
    TransType['SRP'] = 119

    #: [Peter Lothberg] UTI
    TransType['UTI'] = 120

    #: [Leif Ekblad] Simple Message Protocol
    TransType['SMP'] = 121

    #: [Jon Crowcroft][draft-perlman-simple-multicast] Simple Multicast Protocol (deprecated)
    TransType['SM'] = 122

    #: [Michael Welzl] Performance Transparency Protocol
    TransType['PTP'] = 123

    #: [Tony Przygienda]
    TransType['ISIS_Over_IPv4'] = 124

    #: [Criag Partridge]
    TransType['FIRE'] = 125

    #: [Robert Sautter] Combat Radio Transport Protocol
    TransType['CRTP'] = 126

    #: [Robert Sautter] Combat Radio User Datagram
    TransType['CRUDP'] = 127

    #: [Kurt Waber]
    TransType['SSCOPMCE'] = 128

    #: [Hollbach]
    TransType['IPLT'] = 129

    #: [Bill McIntosh] Secure Packet Shield
    TransType['SPS'] = 130

    #: [Bernhard Petri] Private IP Encapsulation within IP
    TransType['PIPE'] = 131

    #: [Randall R Stewart] Stream Control Transmission Protocol
    TransType['SCTP'] = 132

    #: [Murali Rajagopal][:rfc:`6172`] Fibre Channel
    TransType['FC'] = 133

    #: [:rfc:`3175`]
    TransType['RSVP_E2E_IGNORE'] = 134

    #: [:rfc:`6275`]
    TransType['Mobility_Header'] = 135

    #: [:rfc:`3828`]
    TransType['UDPLite'] = 136

    #: [:rfc:`4023`]
    TransType['MPLS_in_IP'] = 137

    #: [:rfc:`5498`] MANET Protocols
    TransType['Manet'] = 138

    #: [:rfc:`7401`] Host Identity Protocol
    TransType['HIP'] = 139

    #: [:rfc:`5533`] Shim6 Protocol
    TransType['Shim6'] = 140

    #: [:rfc:`5840`] Wrapped Encapsulating Security Payload
    TransType['WESP'] = 141

    #: [:rfc:`5858`] Robust Header Compression
    TransType['ROHC'] = 142

    #: [draft-ietf-spring-srv6-network-programming] Ethernet (TEMPORARY - registered 2020-01-31, expires 2021-01-31)
    TransType['Ethernet'] = 143

    #: [:rfc:`3692`]
    TransType['Use_For_Experimentation_And_Testing_253'] = 253

    #: [:rfc:`3692`]
    TransType['Use_For_Experimentation_And_Testing_254'] = 254

    #: [Internet Assigned Numbers Authority]
    TransType['Reserved'] = 255

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
            # [Internet Assigned Numbers Authority]
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        return super()._missing_(value)
