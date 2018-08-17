# -*- coding: utf-8 -*-


# Transport Layer Protocol Numbers
TP_PROTO = {
    0 : 'HOPOPT',                                                               # [RFC 8200] IPv6 Hop-by-Hop Option
    1 : 'ICMP',                                                                 # [RFC 792] Internet Control Message
    2 : 'IGMP',                                                                 # [RFC 1112] Internet Group Management
    3 : 'GGP',                                                                  # [RFC 823] Gateway-to-Gateway
    4 : 'IPv4',                                                                 # [RFC 2003] IPv4 encapsulation
    5 : 'ST',                                                                   # [RFC 1190][RFC 1819] Stream
    6 : 'TCP',                                                                  # [RFC 793] Transmission Control
    7 : 'CBT',                                                                  # [Tony_Ballardie] CBT
    8 : 'EGP',                                                                  # [RFC 888][David_Mills] Exterior Gateway Protocol
    9 : 'IGP',                                                                  # [Internet_Assigned_Numbers_Authority] any private interior gateway (used by Cisco for their IGRP)
   10 : 'BBN-RCC-MON',                                                          # [Steve_Chipman] BBN RCC Monitoring
   11 : 'NVP-II',                                                               # [RFC 741][Steve_Casner] Network Voice Protocol
   12 : 'PUP',                                                                  # [Boggs, D., J. Shoch, E. Taft, and R. Metcalfe, "PUP: An Internetwork Architecture", XEROX Palo Alto Research Center, CSL-79-10, July 1979; also in IEEE Transactions on Communication, Volume COM-28, Number 4, April 1980.][XEROX] PUP
   13 : 'ARGUS',                                                                # [Robert_W_Scheifler] ARGUS (deprecated)
   14 : 'EMCON',                                                                # [<mystery contact>] EMCON
   15 : 'XNET',                                                                 # [Haverty, J., "XNET Formats for Internet Protocol Version 4", IEN 158, October 1980.][Jack_Haverty] Cross Net Debugger
   16 : 'CHAOS',                                                                # [J_Noel_Chiappa] Chaos
   17 : 'UDP',                                                                  # [RFC 768][Jon_Postel] User Datagram
   18 : 'MUX',                                                                  # [Cohen, D. and J. Postel, "Multiplexing Protocol", IEN 90, USC/Information Sciences Institute, May 1979.][Jon_Postel] Multiplexing
   19 : 'DCN-MEAS',                                                             # [David_Mills] DCN Measurement Subsystems
   20 : 'HMP',                                                                  # [RFC 869][Bob_Hinden] Host Monitoring
   21 : 'PRM',                                                                  # [Zaw_Sing_Su] Packet Radio Measurement
   22 : 'XNS-IDP',                                                              # ["The Ethernet, A Local Area Network: Data Link Layer and Physical Layer Specification", AA-K759B-TK, Digital Equipment Corporation, Maynard, MA. Also as: "The Ethernet - A Local Area Network", Version 1.0, Digital Equipment Corporation, Intel Corporation, Xerox Corporation, September 1980. And: "The Ethernet, A Local Area Network: Data Link Layer and Physical Layer Specifications", Digital, Intel and Xerox, November 1982. And: XEROX, "The Ethernet, A Local Area Network: Data Link Layer and Physical Layer Specification", X3T51/80-50, Xerox Corporation, Stamford, CT., October 1980.][XEROX] XEROX NS IDP
   23 : 'TRUNK-1',                                                              # [Barry_Boehm] Trunk-1
   24 : 'TRUNK-2',                                                              # [Barry_Boehm] Trunk-2
   25 : 'LEAF-1',                                                               # [Barry_Boehm] Leaf-1
   26 : 'LEAF-2',                                                               # [Barry_Boehm] Leaf-2
   27 : 'RDP',                                                                  # [RFC 908][Bob_Hinden] Reliable Data Protocol
   28 : 'IRTP',                                                                 # [RFC 938][Trudy_Miller] Internet Reliable Transaction
   29 : 'ISO-TP4',                                                              # [RFC 905][<mystery contact>] ISO Transport Protocol Class 4
   30 : 'NETBLT',                                                               # [RFC 969][David_Clark] Bulk Data Transfer Protocol
   31 : 'MFE-NSP',                                                              # [Shuttleworth, B., "A Documentary of MFENet, a National Computer Network", UCRL-52317, Lawrence Livermore Labs, Livermore, California, June 1977.][Barry_Howard] MFE Network Services Protocol
   32 : 'MERIT-INP',                                                            # [Hans_Werner_Braun] MERIT Internodal Protocol
   33 : 'DCCP',                                                                 # [RFC 4340] Datagram Congestion Control Protocol
   34 : '3PC',                                                                  # [Stuart_A_Friedberg] Third Party Connect Protocol
   35 : 'IDPR',                                                                 # [Martha_Steenstrup] Inter-Domain Policy Routing Protocol
   36 : 'XTP',                                                                  # [Greg_Chesson] XTP
   37 : 'DDP',                                                                  # [Wesley_Craig] Datagram Delivery Protocol
   38 : 'IDPR-CMTP',                                                            # [Martha_Steenstrup] IDPR Control Message Transport Proto
   39 : 'TP++',                                                                 # [Dirk_Fromhein] TP++ Transport Protocol
   40 : 'IL',                                                                   # [Dave_Presotto] IL Transport Protocol
   41 : 'IPv6',                                                                 # [RFC 2473] IPv6 encapsulation
   42 : 'SDRP',                                                                 # [Deborah_Estrin] Source Demand Routing Protocol
   43 : 'IPv6-Route',                                                           # [Steve_Deering] Routing Header for IPv6
   44 : 'IPv6-Frag',                                                            # [Steve_Deering] Fragment Header for IPv6
   45 : 'IDRP',                                                                 # [Sue_Hares] Inter-Domain Routing Protocol
   46 : 'RSVP',                                                                 # [RFC 2205][RFC 3209][Bob_Braden] Reservation Protocol
   47 : 'GRE',                                                                  # [RFC 2784][Tony_Li] Generic Routing Encapsulation
   48 : 'DSR',                                                                  # [RFC 4728] Dynamic Source Routing Protocol
   49 : 'BNA',                                                                  # [Gary Salamon] BNA
   50 : 'ESP',                                                                  # [RFC 4303] Encap Security Payload
   51 : 'AH',                                                                   # [RFC 4302] Authentication Header
   52 : 'I-NLSP',                                                               # [K_Robert_Glenn] Integrated Net Layer Security TUBA
   53 : 'SWIPE',                                                                # [John_Ioannidis] IP with Encryption (deprecated)
   54 : 'NARP',                                                                 # [RFC 1735] NBMA Address Resolution Protocol
   55 : 'MOBILE',                                                               # [Charlie_Perkins] IP Mobility
   56 : 'TLSP',                                                                 # [Christer_Oberg] Transport Layer Security Protocol using Kryptonet key management
   57 : 'SKIP',                                                                 # [Tom_Markson] SKIP
   58 : 'IPv6-ICMP',                                                            # [RFC 8200] ICMP for IPv6
   59 : 'IPv6-NoNxt',                                                           # [RFC 8200] No Next Header for IPv6
   60 : 'IPv6-Opts',                                                            # [RFC 8200] Destination Options for IPv6
   61 : 'any host internal protocol [61]',                                      # [Internet_Assigned_Numbers_Authority]
   62 : 'CFTP',                                                                 # [Forsdick, H., "CFTP", Network Message, Bolt Beranek and Newman, January 1982.][Harry_Forsdick] CFTP
   63 : 'any local network [63]',                                               # [Internet_Assigned_Numbers_Authority]
   64 : 'SAT-EXPAK',                                                            # [Steven_Blumenthal] SATNET and Backroom EXPAK
   65 : 'KRYPTOLAN',                                                            # [Paul Liu] Kryptolan
   66 : 'RVD',                                                                  # [Michael_Greenwald] MIT Remote Virtual Disk Protocol
   67 : 'IPPC',                                                                 # [Steven_Blumenthal] Internet Pluribus Packet Core
   68 : 'any distributed file system [68]',                                     # [Internet_Assigned_Numbers_Authority]
   69 : 'SAT-MON',                                                              # [Steven_Blumenthal] SATNET Monitoring
   70 : 'VISA',                                                                 # [Gene_Tsudik] VISA Protocol
   71 : 'IPCV',                                                                 # [Steven_Blumenthal] Internet Packet Core Utility
   72 : 'CPNX',                                                                 # [David Mittnacht] Computer Protocol Network Executive
   73 : 'CPHB',                                                                 # [David Mittnacht] Computer Protocol Heart Beat
   74 : 'WSN',                                                                  # [Victor Dafoulas] Wang Span Network
   75 : 'PVP',                                                                  # [Steve_Casner] Packet Video Protocol
   76 : 'BR-SAT-MON',                                                           # [Steven_Blumenthal] Backroom SATNET Monitoring
   77 : 'SUN-ND',                                                               # [William_Melohn] SUN ND PROTOCOL-Temporary
   78 : 'WB-MON',                                                               # [Steven_Blumenthal] WIDEBAND Monitoring
   79 : 'WB-EXPAK',                                                             # [Steven_Blumenthal] WIDEBAND EXPAK
   80 : 'ISO-IP',                                                               # [Marshall_T_Rose] ISO Internet Protocol
   81 : 'VMTP',                                                                 # [Dave_Cheriton] VMTP
   82 : 'SECURE-VMTP',                                                          # [Dave_Cheriton] SECURE-VMTP
   83 : 'VINES',                                                                # [Brian Horn] VINES
   84 : 'TTP',                                                                  # [Jim_Stevens] Transaction Transport Protocol
   84 : 'IPTM',                                                                 # [Jim_Stevens] Internet Protocol Traffic Manager
   85 : 'NSFNET-IGP',                                                           # [Hans_Werner_Braun] NSFNET-IGP
   86 : 'DGP',                                                                  # [M/A-COM Government Systems, "Dissimilar Gateway Protocol Specification, Draft Version", Contract no. CS901145, November 16, 1987.][Mike_Little] Dissimilar Gateway Protocol
   87 : 'TCF',                                                                  # [Guillermo_A_Loyola] TCF
   88 : 'EIGRP',                                                                # [RFC 7868] EIGRP
   89 : 'OSPFIGP',                                                              # [RFC 1583][RFC 2328][RFC 5340][John_Moy] OSPFIGP
   90 : 'Sprite-RPC',                                                           # [Welch, B., "The Sprite Remote Procedure Call System", Technical Report, UCB/Computer Science Dept., 86/302, University of California at Berkeley, June 1986.][Bruce Willins] Sprite RPC Protocol
   91 : 'LARP',                                                                 # [Brian Horn] Locus Address Resolution Protocol
   92 : 'MTP',                                                                  # [Susie_Armstrong] Multicast Transport Protocol
   93 : 'AX.25',                                                                # [Brian_Kantor] AX.25 Frames
   94 : 'IPIP',                                                                 # [John_Ioannidis] IP-within-IP Encapsulation Protocol
   95 : 'MICP',                                                                 # [John_Ioannidis] Mobile Internetworking Control Pro. (deprecated)
   96 : 'SCC-SP',                                                               # [Howard_Hart] Semaphore Communications Sec. Pro.
   97 : 'ETHERIP',                                                              # [RFC 3378] Ethernet-within-IP Encapsulation
   98 : 'ENCAP',                                                                # [RFC 1241][Robert_Woodburn] Encapsulation Header
   99 : 'any private encryption scheme [99]',                                   # [Internet_Assigned_Numbers_Authority]
  100 : 'GMTP',                                                                 # [RXB5] GMTP
  101 : 'IFMP',                                                                 # [Bob_Hinden][November 1995, 1997.] Ipsilon Flow Management Protocol
  102 : 'PNNI',                                                                 # [Ross_Callon] PNNI over IP
  103 : 'PIM',                                                                  # [RFC 7761][Dino_Farinacci] Protocol Independent Multicast
  104 : 'ARIS',                                                                 # [Nancy_Feldman] ARIS
  105 : 'SCPS',                                                                 # [Robert_Durst] SCPS
  106 : 'QNX',                                                                  # [Michael_Hunter] QNX
  107 : 'A/N',                                                                  # [Bob_Braden] Active Networks
  108 : 'IPComp',                                                               # [RFC 2393] IP Payload Compression Protocol
  109 : 'SNP',                                                                  # [Manickam_R_Sridhar] Sitara Networks Protocol
  110 : 'Compaq-Peer',                                                          # [Victor_Volpe] Compaq Peer Protocol
  111 : 'IPX-in-IP',                                                            # [CJ_Lee] IPX in IP
  112 : 'VRRP',                                                                 # [RFC 5798] Virtual Router Redundancy Protocol
  113 : 'PGM',                                                                  # [Tony_Speakman] PGM Reliable Transport Protocol
  114 : 'any 0-hop protocol [114]',                                             # [Internet_Assigned_Numbers_Authority]
  115 : 'L2TP',                                                                 # [RFC 3931][Bernard_Aboba] Layer Two Tunneling Protocol
  116 : 'DDX',                                                                  # [John_Worley] D-II Data Exchange (DDX)
  117 : 'IATP',                                                                 # [John_Murphy] Interactive Agent Transfer Protocol
  118 : 'STP',                                                                  # [Jean_Michel_Pittet] Schedule Transfer Protocol
  119 : 'SRP',                                                                  # [Mark_Hamilton] SpectraLink Radio Protocol
  120 : 'UTI',                                                                  # [Peter_Lothberg] UTI
  121 : 'SMP',                                                                  # [Leif_Ekblad] Simple Message Protocol
  122 : 'SM',                                                                   # [Jon_Crowcroft][draft-perlman-simple-multicast] Simple Multicast Protocol (deprecated)
  123 : 'PTP',                                                                  # [Michael_Welzl] Performance Transparency Protocol
  124 : 'ISIS over IPv4',                                                       # [Tony_Przygienda]
  125 : 'FIRE',                                                                 # [Criag_Partridge]
  126 : 'CRTP',                                                                 # [Robert_Sautter] Combat Radio Transport Protocol
  127 : 'CRUDP',                                                                # [Robert_Sautter] Combat Radio User Datagram
  128 : 'SSCOPMCE',                                                             # [Kurt_Waber]
  129 : 'IPLT',                                                                 # [Hollbach]
  130 : 'SPS',                                                                  # [Bill_McIntosh] Secure Packet Shield
  131 : 'PIPE',                                                                 # [Bernhard_Petri] Private IP Encapsulation within IP
  132 : 'SCTP',                                                                 # [Randall_R_Stewart] Stream Control Transmission Protocol
  133 : 'FC',                                                                   # [Murali_Rajagopal][RFC 6172] Fibre Channel
  134 : 'RSVP-E2E-IGNORE',                                                      # [RFC 3175]
  135 : 'Mobility Header',                                                      # [RFC 6275]
  136 : 'UDPLite',                                                              # [RFC 3828]
  137 : 'MPLS-in-IP',                                                           # [RFC 4023]
  138 : 'manet',                                                                # [RFC 5498] MANET Protocols
  139 : 'HIP',                                                                  # [RFC 7401] Host Identity Protocol
  140 : 'Shim6',                                                                # [RFC 5533] Shim6 Protocol
  141 : 'WESP',                                                                 # [RFC 5840] Wrapped Encapsulating Security Payload
  142 : 'ROHC',                                                                 # [RFC 5858] Robust Header Compression
  143 : 'Unassigned [143]',                                                     # [Internet_Assigned_Numbers_Authority]
  144 : 'Unassigned [144]',                                                     # [Internet_Assigned_Numbers_Authority]
  145 : 'Unassigned [145]',                                                     # [Internet_Assigned_Numbers_Authority]
  146 : 'Unassigned [146]',                                                     # [Internet_Assigned_Numbers_Authority]
  147 : 'Unassigned [147]',                                                     # [Internet_Assigned_Numbers_Authority]
  148 : 'Unassigned [148]',                                                     # [Internet_Assigned_Numbers_Authority]
  149 : 'Unassigned [149]',                                                     # [Internet_Assigned_Numbers_Authority]
  150 : 'Unassigned [150]',                                                     # [Internet_Assigned_Numbers_Authority]
  151 : 'Unassigned [151]',                                                     # [Internet_Assigned_Numbers_Authority]
  152 : 'Unassigned [152]',                                                     # [Internet_Assigned_Numbers_Authority]
  153 : 'Unassigned [153]',                                                     # [Internet_Assigned_Numbers_Authority]
  154 : 'Unassigned [154]',                                                     # [Internet_Assigned_Numbers_Authority]
  155 : 'Unassigned [155]',                                                     # [Internet_Assigned_Numbers_Authority]
  156 : 'Unassigned [156]',                                                     # [Internet_Assigned_Numbers_Authority]
  157 : 'Unassigned [157]',                                                     # [Internet_Assigned_Numbers_Authority]
  158 : 'Unassigned [158]',                                                     # [Internet_Assigned_Numbers_Authority]
  159 : 'Unassigned [159]',                                                     # [Internet_Assigned_Numbers_Authority]
  160 : 'Unassigned [160]',                                                     # [Internet_Assigned_Numbers_Authority]
  161 : 'Unassigned [161]',                                                     # [Internet_Assigned_Numbers_Authority]
  162 : 'Unassigned [162]',                                                     # [Internet_Assigned_Numbers_Authority]
  163 : 'Unassigned [163]',                                                     # [Internet_Assigned_Numbers_Authority]
  164 : 'Unassigned [164]',                                                     # [Internet_Assigned_Numbers_Authority]
  165 : 'Unassigned [165]',                                                     # [Internet_Assigned_Numbers_Authority]
  166 : 'Unassigned [166]',                                                     # [Internet_Assigned_Numbers_Authority]
  167 : 'Unassigned [167]',                                                     # [Internet_Assigned_Numbers_Authority]
  168 : 'Unassigned [168]',                                                     # [Internet_Assigned_Numbers_Authority]
  169 : 'Unassigned [169]',                                                     # [Internet_Assigned_Numbers_Authority]
  170 : 'Unassigned [170]',                                                     # [Internet_Assigned_Numbers_Authority]
  171 : 'Unassigned [171]',                                                     # [Internet_Assigned_Numbers_Authority]
  172 : 'Unassigned [172]',                                                     # [Internet_Assigned_Numbers_Authority]
  173 : 'Unassigned [173]',                                                     # [Internet_Assigned_Numbers_Authority]
  174 : 'Unassigned [174]',                                                     # [Internet_Assigned_Numbers_Authority]
  175 : 'Unassigned [175]',                                                     # [Internet_Assigned_Numbers_Authority]
  176 : 'Unassigned [176]',                                                     # [Internet_Assigned_Numbers_Authority]
  177 : 'Unassigned [177]',                                                     # [Internet_Assigned_Numbers_Authority]
  178 : 'Unassigned [178]',                                                     # [Internet_Assigned_Numbers_Authority]
  179 : 'Unassigned [179]',                                                     # [Internet_Assigned_Numbers_Authority]
  180 : 'Unassigned [180]',                                                     # [Internet_Assigned_Numbers_Authority]
  181 : 'Unassigned [181]',                                                     # [Internet_Assigned_Numbers_Authority]
  182 : 'Unassigned [182]',                                                     # [Internet_Assigned_Numbers_Authority]
  183 : 'Unassigned [183]',                                                     # [Internet_Assigned_Numbers_Authority]
  184 : 'Unassigned [184]',                                                     # [Internet_Assigned_Numbers_Authority]
  185 : 'Unassigned [185]',                                                     # [Internet_Assigned_Numbers_Authority]
  186 : 'Unassigned [186]',                                                     # [Internet_Assigned_Numbers_Authority]
  187 : 'Unassigned [187]',                                                     # [Internet_Assigned_Numbers_Authority]
  188 : 'Unassigned [188]',                                                     # [Internet_Assigned_Numbers_Authority]
  189 : 'Unassigned [189]',                                                     # [Internet_Assigned_Numbers_Authority]
  190 : 'Unassigned [190]',                                                     # [Internet_Assigned_Numbers_Authority]
  191 : 'Unassigned [191]',                                                     # [Internet_Assigned_Numbers_Authority]
  192 : 'Unassigned [192]',                                                     # [Internet_Assigned_Numbers_Authority]
  193 : 'Unassigned [193]',                                                     # [Internet_Assigned_Numbers_Authority]
  194 : 'Unassigned [194]',                                                     # [Internet_Assigned_Numbers_Authority]
  195 : 'Unassigned [195]',                                                     # [Internet_Assigned_Numbers_Authority]
  196 : 'Unassigned [196]',                                                     # [Internet_Assigned_Numbers_Authority]
  197 : 'Unassigned [197]',                                                     # [Internet_Assigned_Numbers_Authority]
  198 : 'Unassigned [198]',                                                     # [Internet_Assigned_Numbers_Authority]
  199 : 'Unassigned [199]',                                                     # [Internet_Assigned_Numbers_Authority]
  200 : 'Unassigned [200]',                                                     # [Internet_Assigned_Numbers_Authority]
  201 : 'Unassigned [201]',                                                     # [Internet_Assigned_Numbers_Authority]
  202 : 'Unassigned [202]',                                                     # [Internet_Assigned_Numbers_Authority]
  203 : 'Unassigned [203]',                                                     # [Internet_Assigned_Numbers_Authority]
  204 : 'Unassigned [204]',                                                     # [Internet_Assigned_Numbers_Authority]
  205 : 'Unassigned [205]',                                                     # [Internet_Assigned_Numbers_Authority]
  206 : 'Unassigned [206]',                                                     # [Internet_Assigned_Numbers_Authority]
  207 : 'Unassigned [207]',                                                     # [Internet_Assigned_Numbers_Authority]
  208 : 'Unassigned [208]',                                                     # [Internet_Assigned_Numbers_Authority]
  209 : 'Unassigned [209]',                                                     # [Internet_Assigned_Numbers_Authority]
  210 : 'Unassigned [210]',                                                     # [Internet_Assigned_Numbers_Authority]
  211 : 'Unassigned [211]',                                                     # [Internet_Assigned_Numbers_Authority]
  212 : 'Unassigned [212]',                                                     # [Internet_Assigned_Numbers_Authority]
  213 : 'Unassigned [213]',                                                     # [Internet_Assigned_Numbers_Authority]
  214 : 'Unassigned [214]',                                                     # [Internet_Assigned_Numbers_Authority]
  215 : 'Unassigned [215]',                                                     # [Internet_Assigned_Numbers_Authority]
  216 : 'Unassigned [216]',                                                     # [Internet_Assigned_Numbers_Authority]
  217 : 'Unassigned [217]',                                                     # [Internet_Assigned_Numbers_Authority]
  218 : 'Unassigned [218]',                                                     # [Internet_Assigned_Numbers_Authority]
  219 : 'Unassigned [219]',                                                     # [Internet_Assigned_Numbers_Authority]
  220 : 'Unassigned [220]',                                                     # [Internet_Assigned_Numbers_Authority]
  221 : 'Unassigned [221]',                                                     # [Internet_Assigned_Numbers_Authority]
  222 : 'Unassigned [222]',                                                     # [Internet_Assigned_Numbers_Authority]
  223 : 'Unassigned [223]',                                                     # [Internet_Assigned_Numbers_Authority]
  224 : 'Unassigned [224]',                                                     # [Internet_Assigned_Numbers_Authority]
  225 : 'Unassigned [225]',                                                     # [Internet_Assigned_Numbers_Authority]
  226 : 'Unassigned [226]',                                                     # [Internet_Assigned_Numbers_Authority]
  227 : 'Unassigned [227]',                                                     # [Internet_Assigned_Numbers_Authority]
  228 : 'Unassigned [228]',                                                     # [Internet_Assigned_Numbers_Authority]
  229 : 'Unassigned [229]',                                                     # [Internet_Assigned_Numbers_Authority]
  230 : 'Unassigned [230]',                                                     # [Internet_Assigned_Numbers_Authority]
  231 : 'Unassigned [231]',                                                     # [Internet_Assigned_Numbers_Authority]
  232 : 'Unassigned [232]',                                                     # [Internet_Assigned_Numbers_Authority]
  233 : 'Unassigned [233]',                                                     # [Internet_Assigned_Numbers_Authority]
  234 : 'Unassigned [234]',                                                     # [Internet_Assigned_Numbers_Authority]
  235 : 'Unassigned [235]',                                                     # [Internet_Assigned_Numbers_Authority]
  236 : 'Unassigned [236]',                                                     # [Internet_Assigned_Numbers_Authority]
  237 : 'Unassigned [237]',                                                     # [Internet_Assigned_Numbers_Authority]
  238 : 'Unassigned [238]',                                                     # [Internet_Assigned_Numbers_Authority]
  239 : 'Unassigned [239]',                                                     # [Internet_Assigned_Numbers_Authority]
  240 : 'Unassigned [240]',                                                     # [Internet_Assigned_Numbers_Authority]
  241 : 'Unassigned [241]',                                                     # [Internet_Assigned_Numbers_Authority]
  242 : 'Unassigned [242]',                                                     # [Internet_Assigned_Numbers_Authority]
  243 : 'Unassigned [243]',                                                     # [Internet_Assigned_Numbers_Authority]
  244 : 'Unassigned [244]',                                                     # [Internet_Assigned_Numbers_Authority]
  245 : 'Unassigned [245]',                                                     # [Internet_Assigned_Numbers_Authority]
  246 : 'Unassigned [246]',                                                     # [Internet_Assigned_Numbers_Authority]
  247 : 'Unassigned [247]',                                                     # [Internet_Assigned_Numbers_Authority]
  248 : 'Unassigned [248]',                                                     # [Internet_Assigned_Numbers_Authority]
  249 : 'Unassigned [249]',                                                     # [Internet_Assigned_Numbers_Authority]
  250 : 'Unassigned [250]',                                                     # [Internet_Assigned_Numbers_Authority]
  251 : 'Unassigned [251]',                                                     # [Internet_Assigned_Numbers_Authority]
  252 : 'Unassigned [252]',                                                     # [Internet_Assigned_Numbers_Authority]
  253 : 'Use for experimentation and testing [253]',                            # [RFC 3692]
  254 : 'Use for experimentation and testing [254]',                            # [RFC 3692]
  255 : 'Reserved [255]',                                                       # [Internet_Assigned_Numbers_Authority]
}
