# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class TransType(IntEnum):
    """Enumeration class for TransType."""
    _ignore_ = 'TransType _'
    TransType = vars()

    # Transport Layer Protocol Numbers
    TransType['HOPOPT'] = 0                                                     # [RFC 8200] IPv6 Hop-by-Hop Option
    TransType['ICMP'] = 1                                                       # [RFC 792] Internet Control Message
    TransType['IGMP'] = 2                                                       # [RFC 1112] Internet Group Management
    TransType['GGP'] = 3                                                        # [RFC 823] Gateway-to-Gateway
    TransType['IPv4'] = 4                                                       # [RFC 2003] IPv4 encapsulation
    TransType['ST'] = 5                                                         # [RFC 1190][RFC 1819] Stream
    TransType['TCP'] = 6                                                        # [RFC 793] Transmission Control
    TransType['CBT'] = 7                                                        # [Tony_Ballardie] CBT
    TransType['EGP'] = 8                                                        # [RFC 888][David_Mills] Exterior Gateway Protocol
    TransType['IGP'] = 9                                                        # [Internet_Assigned_Numbers_Authority] any private interior gateway (used by Cisco for their IGRP)
    TransType['BBN-RCC-MON'] = 10                                               # [Steve_Chipman] BBN RCC Monitoring
    TransType['NVP-II'] = 11                                                    # [RFC 741][Steve_Casner] Network Voice Protocol
    TransType['PUP'] = 12                                                       # [Boggs, D., J. Shoch, E. Taft, and R. Metcalfe, "PUP: An Internetwork Architecture", XEROX Palo Alto Research Center, CSL-79-10, July 1979; also in IEEE Transactions on Communication, Volume COM-28, Number 4, April 1980.][XEROX] PUP
    TransType['ARGUS'] = 13                                                     # [Robert_W_Scheifler] ARGUS (deprecated)
    TransType['EMCON'] = 14                                                     # [<mystery contact>] EMCON
    TransType['XNET'] = 15                                                      # [Haverty, J., "XNET Formats for Internet Protocol Version 4", IEN 158, October 1980.][Jack_Haverty] Cross Net Debugger
    TransType['CHAOS'] = 16                                                     # [J_Noel_Chiappa] Chaos
    TransType['UDP'] = 17                                                       # [RFC 768][Jon_Postel] User Datagram
    TransType['MUX'] = 18                                                       # [Cohen, D. and J. Postel, "Multiplexing Protocol", IEN 90, USC/Information Sciences Institute, May 1979.][Jon_Postel] Multiplexing
    TransType['DCN-MEAS'] = 19                                                  # [David_Mills] DCN Measurement Subsystems
    TransType['HMP'] = 20                                                       # [RFC 869][Bob_Hinden] Host Monitoring
    TransType['PRM'] = 21                                                       # [Zaw_Sing_Su] Packet Radio Measurement
    TransType['XNS-IDP'] = 22                                                   # ["The Ethernet, A Local Area Network: Data Link Layer and Physical Layer Specification", AA-K759B-TK, Digital Equipment Corporation, Maynard, MA. Also as: "The Ethernet - A Local Area Network", Version 1.0, Digital Equipment Corporation, Intel Corporation, Xerox Corporation, September 1980. And: "The Ethernet, A Local Area Network: Data Link Layer and Physical Layer Specifications", Digital, Intel and Xerox, November 1982. And: XEROX, "The Ethernet, A Local Area Network: Data Link Layer and Physical Layer Specification", X3T51/80-50, Xerox Corporation, Stamford, CT., October 1980.][XEROX] XEROX NS IDP
    TransType['TRUNK-1'] = 23                                                   # [Barry_Boehm] Trunk-1
    TransType['TRUNK-2'] = 24                                                   # [Barry_Boehm] Trunk-2
    TransType['LEAF-1'] = 25                                                    # [Barry_Boehm] Leaf-1
    TransType['LEAF-2'] = 26                                                    # [Barry_Boehm] Leaf-2
    TransType['RDP'] = 27                                                       # [RFC 908][Bob_Hinden] Reliable Data Protocol
    TransType['IRTP'] = 28                                                      # [RFC 938][Trudy_Miller] Internet Reliable Transaction
    TransType['ISO-TP4'] = 29                                                   # [RFC 905][<mystery contact>] ISO Transport Protocol Class 4
    TransType['NETBLT'] = 30                                                    # [RFC 969][David_Clark] Bulk Data Transfer Protocol
    TransType['MFE-NSP'] = 31                                                   # [Shuttleworth, B., "A Documentary of MFENet, a National Computer Network", UCRL-52317, Lawrence Livermore Labs, Livermore, California, June 1977.][Barry_Howard] MFE Network Services Protocol
    TransType['MERIT-INP'] = 32                                                 # [Hans_Werner_Braun] MERIT Internodal Protocol
    TransType['DCCP'] = 33                                                      # [RFC 4340] Datagram Congestion Control Protocol
    TransType['3PC'] = 34                                                       # [Stuart_A_Friedberg] Third Party Connect Protocol
    TransType['IDPR'] = 35                                                      # [Martha_Steenstrup] Inter-Domain Policy Routing Protocol
    TransType['XTP'] = 36                                                       # [Greg_Chesson] XTP
    TransType['DDP'] = 37                                                       # [Wesley_Craig] Datagram Delivery Protocol
    TransType['IDPR-CMTP'] = 38                                                 # [Martha_Steenstrup] IDPR Control Message Transport Proto
    TransType['TP++'] = 39                                                      # [Dirk_Fromhein] TP++ Transport Protocol
    TransType['IL'] = 40                                                        # [Dave_Presotto] IL Transport Protocol
    TransType['IPv6'] = 41                                                      # [RFC 2473] IPv6 encapsulation
    TransType['SDRP'] = 42                                                      # [Deborah_Estrin] Source Demand Routing Protocol
    TransType['IPv6-Route'] = 43                                                # [Steve_Deering] Routing Header for IPv6
    TransType['IPv6-Frag'] = 44                                                 # [Steve_Deering] Fragment Header for IPv6
    TransType['IDRP'] = 45                                                      # [Sue_Hares] Inter-Domain Routing Protocol
    TransType['RSVP'] = 46                                                      # [RFC 2205][RFC 3209][Bob_Braden] Reservation Protocol
    TransType['GRE'] = 47                                                       # [RFC 2784][Tony_Li] Generic Routing Encapsulation
    TransType['DSR'] = 48                                                       # [RFC 4728] Dynamic Source Routing Protocol
    TransType['BNA'] = 49                                                       # [Gary Salamon] BNA
    TransType['ESP'] = 50                                                       # [RFC 4303] Encap Security Payload
    TransType['AH'] = 51                                                        # [RFC 4302] Authentication Header
    TransType['I-NLSP'] = 52                                                    # [K_Robert_Glenn] Integrated Net Layer Security TUBA
    TransType['SWIPE'] = 53                                                     # [John_Ioannidis] IP with Encryption (deprecated)
    TransType['NARP'] = 54                                                      # [RFC 1735] NBMA Address Resolution Protocol
    TransType['MOBILE'] = 55                                                    # [Charlie_Perkins] IP Mobility
    TransType['TLSP'] = 56                                                      # [Christer_Oberg] Transport Layer Security Protocol using Kryptonet key management
    TransType['SKIP'] = 57                                                      # [Tom_Markson] SKIP
    TransType['IPv6-ICMP'] = 58                                                 # [RFC 8200] ICMP for IPv6
    TransType['IPv6-NoNxt'] = 59                                                # [RFC 8200] No Next Header for IPv6
    TransType['IPv6-Opts'] = 60                                                 # [RFC 8200] Destination Options for IPv6
    TransType['any host internal protocol [61]'] = 61                           # [Internet_Assigned_Numbers_Authority]
    TransType['CFTP'] = 62                                                      # [Forsdick, H., "CFTP", Network Message, Bolt Beranek and Newman, January 1982.][Harry_Forsdick] CFTP
    TransType['any local network [63]'] = 63                                    # [Internet_Assigned_Numbers_Authority]
    TransType['SAT-EXPAK'] = 64                                                 # [Steven_Blumenthal] SATNET and Backroom EXPAK
    TransType['KRYPTOLAN'] = 65                                                 # [Paul Liu] Kryptolan
    TransType['RVD'] = 66                                                       # [Michael_Greenwald] MIT Remote Virtual Disk Protocol
    TransType['IPPC'] = 67                                                      # [Steven_Blumenthal] Internet Pluribus Packet Core
    TransType['any distributed file system [68]'] = 68                          # [Internet_Assigned_Numbers_Authority]
    TransType['SAT-MON'] = 69                                                   # [Steven_Blumenthal] SATNET Monitoring
    TransType['VISA'] = 70                                                      # [Gene_Tsudik] VISA Protocol
    TransType['IPCV'] = 71                                                      # [Steven_Blumenthal] Internet Packet Core Utility
    TransType['CPNX'] = 72                                                      # [David Mittnacht] Computer Protocol Network Executive
    TransType['CPHB'] = 73                                                      # [David Mittnacht] Computer Protocol Heart Beat
    TransType['WSN'] = 74                                                       # [Victor Dafoulas] Wang Span Network
    TransType['PVP'] = 75                                                       # [Steve_Casner] Packet Video Protocol
    TransType['BR-SAT-MON'] = 76                                                # [Steven_Blumenthal] Backroom SATNET Monitoring
    TransType['SUN-ND'] = 77                                                    # [William_Melohn] SUN ND PROTOCOL-Temporary
    TransType['WB-MON'] = 78                                                    # [Steven_Blumenthal] WIDEBAND Monitoring
    TransType['WB-EXPAK'] = 79                                                  # [Steven_Blumenthal] WIDEBAND EXPAK
    TransType['ISO-IP'] = 80                                                    # [Marshall_T_Rose] ISO Internet Protocol
    TransType['VMTP'] = 81                                                      # [Dave_Cheriton] VMTP
    TransType['SECURE-VMTP'] = 82                                               # [Dave_Cheriton] SECURE-VMTP
    TransType['VINES'] = 83                                                     # [Brian Horn] VINES
    TransType['TTP'] = 84                                                       # [Jim_Stevens] Transaction Transport Protocol
    TransType['IPTM'] = 84                                                      # [Jim_Stevens] Internet Protocol Traffic Manager
    TransType['NSFNET-IGP'] = 85                                                # [Hans_Werner_Braun] NSFNET-IGP
    TransType['DGP'] = 86                                                       # [M/A-COM Government Systems, "Dissimilar Gateway Protocol Specification, Draft Version", Contract no. CS901145, November 16, 1987.][Mike_Little] Dissimilar Gateway Protocol
    TransType['TCF'] = 87                                                       # [Guillermo_A_Loyola] TCF
    TransType['EIGRP'] = 88                                                     # [RFC 7868] EIGRP
    TransType['OSPFIGP'] = 89                                                   # [RFC 1583][RFC 2328][RFC 5340][John_Moy] OSPFIGP
    TransType['Sprite-RPC'] = 90                                                # [Welch, B., "The Sprite Remote Procedure Call System", Technical Report, UCB/Computer Science Dept., 86/302, University of California at Berkeley, June 1986.][Bruce Willins] Sprite RPC Protocol
    TransType['LARP'] = 91                                                      # [Brian Horn] Locus Address Resolution Protocol
    TransType['MTP'] = 92                                                       # [Susie_Armstrong] Multicast Transport Protocol
    TransType['AX.25'] = 93                                                     # [Brian_Kantor] AX.25 Frames
    TransType['IPIP'] = 94                                                      # [John_Ioannidis] IP-within-IP Encapsulation Protocol
    TransType['MICP'] = 95                                                      # [John_Ioannidis] Mobile Internetworking Control Pro. (deprecated)
    TransType['SCC-SP'] = 96                                                    # [Howard_Hart] Semaphore Communications Sec. Pro.
    TransType['ETHERIP'] = 97                                                   # [RFC 3378] Ethernet-within-IP Encapsulation
    TransType['ENCAP'] = 98                                                     # [RFC 1241][Robert_Woodburn] Encapsulation Header
    TransType['any private encryption scheme [99]'] = 99                        # [Internet_Assigned_Numbers_Authority]
    TransType['GMTP'] = 100                                                     # [RXB5] GMTP
    TransType['IFMP'] = 101                                                     # [Bob_Hinden][November 1995, 1997.] Ipsilon Flow Management Protocol
    TransType['PNNI'] = 102                                                     # [Ross_Callon] PNNI over IP
    TransType['PIM'] = 103                                                      # [RFC 7761][Dino_Farinacci] Protocol Independent Multicast
    TransType['ARIS'] = 104                                                     # [Nancy_Feldman] ARIS
    TransType['SCPS'] = 105                                                     # [Robert_Durst] SCPS
    TransType['QNX'] = 106                                                      # [Michael_Hunter] QNX
    TransType['A/N'] = 107                                                      # [Bob_Braden] Active Networks
    TransType['IPComp'] = 108                                                   # [RFC 2393] IP Payload Compression Protocol
    TransType['SNP'] = 109                                                      # [Manickam_R_Sridhar] Sitara Networks Protocol
    TransType['Compaq-Peer'] = 110                                              # [Victor_Volpe] Compaq Peer Protocol
    TransType['IPX-in-IP'] = 111                                                # [CJ_Lee] IPX in IP
    TransType['VRRP'] = 112                                                     # [RFC 5798] Virtual Router Redundancy Protocol
    TransType['PGM'] = 113                                                      # [Tony_Speakman] PGM Reliable Transport Protocol
    TransType['any 0-hop protocol [114]'] = 114                                 # [Internet_Assigned_Numbers_Authority]
    TransType['L2TP'] = 115                                                     # [RFC 3931][Bernard_Aboba] Layer Two Tunneling Protocol
    TransType['DDX'] = 116                                                      # [John_Worley] D-II Data Exchange (DDX)
    TransType['IATP'] = 117                                                     # [John_Murphy] Interactive Agent Transfer Protocol
    TransType['STP'] = 118                                                      # [Jean_Michel_Pittet] Schedule Transfer Protocol
    TransType['SRP'] = 119                                                      # [Mark_Hamilton] SpectraLink Radio Protocol
    TransType['UTI'] = 120                                                      # [Peter_Lothberg] UTI
    TransType['SMP'] = 121                                                      # [Leif_Ekblad] Simple Message Protocol
    TransType['SM'] = 122                                                       # [Jon_Crowcroft][draft-perlman-simple-multicast] Simple Multicast Protocol (deprecated)
    TransType['PTP'] = 123                                                      # [Michael_Welzl] Performance Transparency Protocol
    TransType['ISIS over IPv4'] = 124                                           # [Tony_Przygienda]
    TransType['FIRE'] = 125                                                     # [Criag_Partridge]
    TransType['CRTP'] = 126                                                     # [Robert_Sautter] Combat Radio Transport Protocol
    TransType['CRUDP'] = 127                                                    # [Robert_Sautter] Combat Radio User Datagram
    TransType['SSCOPMCE'] = 128                                                 # [Kurt_Waber]
    TransType['IPLT'] = 129                                                     # [Hollbach]
    TransType['SPS'] = 130                                                      # [Bill_McIntosh] Secure Packet Shield
    TransType['PIPE'] = 131                                                     # [Bernhard_Petri] Private IP Encapsulation within IP
    TransType['SCTP'] = 132                                                     # [Randall_R_Stewart] Stream Control Transmission Protocol
    TransType['FC'] = 133                                                       # [Murali_Rajagopal][RFC 6172] Fibre Channel
    TransType['RSVP-E2E-IGNORE'] = 134                                          # [RFC 3175]
    TransType['Mobility Header'] = 135                                          # [RFC 6275]
    TransType['UDPLite'] = 136                                                  # [RFC 3828]
    TransType['MPLS-in-IP'] = 137                                               # [RFC 4023]
    TransType['manet'] = 138                                                    # [RFC 5498] MANET Protocols
    TransType['HIP'] = 139                                                      # [RFC 7401] Host Identity Protocol
    TransType['Shim6'] = 140                                                    # [RFC 5533] Shim6 Protocol
    TransType['WESP'] = 141                                                     # [RFC 5840] Wrapped Encapsulating Security Payload
    TransType['ROHC'] = 142                                                     # [RFC 5858] Robust Header Compression
    TransType['Use for experimentation and testing [253]'] = 253                # [RFC 3692]
    TransType['Use for experimentation and testing [254]'] = 254                # [RFC 3692]
    TransType['Reserved'] = 255                                                 # [Internet_Assigned_Numbers_Authority]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return TransType(key)
        if key not in TransType._member_map_:
            extend_enum(TransType, key, default)
        return TransType[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 143 <= value <= 252:
            # [Internet_Assigned_Numbers_Authority]
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)
