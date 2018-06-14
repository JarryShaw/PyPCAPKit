# JSPCAP Manual

&emsp; `jspcap` is an open sourse library for PCAP extarction and analysis, written in __Python 3.6__. The following is a manual for this library.

 - [Fundations](https://github.com/JarryShaw/jspcap/tree/master/src/fundations#fundations-manual)
    * [`fundations`](#index-fundations)
 - [ToolKit](https://github.com/JarryShaw/jspcap/tree/master/src/toolkit#toolkit-manual)
    * [`toolkit`](#index-toolkit)
 - [Interfaces](https://github.com/JarryShaw/jspcap/tree/master/src/interfaces#interfaces-manual)
 	* [`interfaces`](#index-interfaces)
 - [Protocols](https://github.com/JarryShaw/jspcap/tree/master/src/protocols#protocols-manual)
    * [Macros](#macros)
    * [`protocols`](#index-protocols)
 - [Reassembly](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#reassembly-manual)
    * [`reassembly`](#index-reassembly)
 - [Utilities](https://github.com/JarryShaw/jspcap/tree/master/src/utilities#utilities-manual)
    * [`utilities`](#index-utilities)
 - [TODO](#todo)

---

<a name="fundations"> </a> 

## Fundations

 > described in [`src/fundations`](https://github.com/JarryShaw/jspcap/tree/master/src/fundations#fundations-manual)

&emsp; `jspcap.fundations` is a collection of fundations for `jspcap`, including PCAP file extraction tool `Extrator` and application layer protocol analyser `analyse`.

<a name="index-fundations"> </a>

##### Fundations

|                                        NAME                                        |             DESCRIPTION              |
| :--------------------------------------------------------------------------------: | :----------------------------------: |
| [`analyse`](https://github.com/JarryShaw/jspcap/tree/master/src/fundations#analyse)     | match protocols & extract attributes |
| [`Extractor`](https://github.com/JarryShaw/jspcap/tree/master/src/fundations#extractor) | extract parameters from a PCAP file  |

&nbsp;

<a name="toolkit"> </a> 

## ToolKit

 > described in [`src/toolkit`](https://github.com/JarryShaw/jspcap/tree/master/src/toolkit)

&emsp; For vast scale of this library, `jspcap.toolkit` standardises library interfaces, which implements three major verbs of the library.

<a name="index-toolkit"> </a>

##### ToolKit

|                                         NAME                                         |            DESCRIPTION            |
| :----------------------------------------------------------------------------------: | :-------------------------------: |
| [`extract`](https://github.com/JarryShaw/jspcap/tree/master/src/toolkit#extract)       |        extract a PCAP file        |
| [`analyse`](https://github.com/JarryShaw/jspcap/tree/master/src/toolkit#analyse)       | analyse application layer packets |
| [`reassemble`](https://github.com/JarryShaw/jspcap/tree/master/src/toolkit#reassemble) |  reassemble fragmented datagrams  |

&nbsp;

<a name="interfaces"> </a>

## Interfaces

 > described in [`src/interfaces`](https://github.com/JarryShaw/jspcap/tree/master/src/interfaces)

&emsp; Since `jspcap` has massive classes and numerous functions, `jspcap.interfaces` defines several user-oriented interfaces, variables, and etc. These interfaces are designed to help and simplify the usage of `jspcap`.

<a name="index-interfaces"> </a>

##### Interfaces

| NAME | DESCRIPTION |
| :--: | :---------: |

&nbsp;

<a name="protocols"> </a>

## Protocols

 > described in [`src/protocols`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols#protocols-manual)

&emsp; `jspcap.protocols` is a collection of all protocol families, with detailed implementation and methods. Currently, it includes altogehter 22 different protocols and three macro variables.

##### Macros

|                                               NAME                                              |           DESCRIPTION            |
| :---------------------------------------------------------------------------------------------: | :------------------------------: |
| [`LINKTYPE`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#linktype)       |  Link-Layer Header Type Values   |
| [`ETHERTYPE`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#ethertype) |    Ethertype IEEE 802 Numbers    |
| [`TP_PROTO`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/transport#tp_proto)  | Transport Layer Protocol Numbers |

<a name="index-protocols"> </a>

##### Protocols

|                                                NAME                                               |             DESCRIPTION             |
| :-----------------------------------------------------------------------------------------------: | :---------------------------------: |
| [`Header`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/pcap#header)             |            Global Header            |
| [`Frame`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/pcap#frame)               |            Frame Header             |
| [`Raw`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols#raw)                        |           Raw Packet Data           |
| [`ARP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#arp)                   |     Address Resolution Protocol     |
| [`Ethernet`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#ethernet)         |          Ethernet Protocol          |
| [`L2TP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#l2tp)                 |    Layer Two Tunneling Protocol     |
| [`OSPF`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#ospf)                 |      Open Shortest Path First       |
| [`RARP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#rarp)                 | Reverse Address Resolution Protocol |
| [`VLAN`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#vlan)                 |    802.1Q Customer VLAN Tag Type    |
| [`AH`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#ah)                 |        Athentication Header         |
| [`HIP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#hip)               |       Host Identity Protocol        |
| [`HOPOPT`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#hopopt)         |       IPv6 Hop-by-Hop Options       |
| [`IP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#ip)                 |          Internet Protocol          |
| [`IPsec`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#ipsec)           |     Internet Protocol Security      |
| [`IPv4`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#ipv4)             |     Internet Protocol version 4     |
| [`IPv6`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#ipv6)             |     Internet Protocol version 6     |
| [`IPv6_Frag`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#ipv6_frag)   |      Fragment Header for IPv6       |
| [`IPv6_Opts`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#ipv6_opts)   |    Destination Options for IPv6     |
| [`IPv6_Route`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#ipv6_route) |       Routing Header for IPv6       |
| [`IPX`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#ipx)               |    Internetwork Packet Exchange     |
| [`MH`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#mh)                 |           Mobility Header           |
| [`TCP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/transport#tcp)              |    Transmission Control Protocol    |
| [`UDP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/transport#udp)              |       User Datagram Protocol        |
| [`HTTP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/application#http)          |     Hypertext Transfer Protocol     |

&nbsp;

<a name="reassembly"> </a> 

## Reassembly

 > described in [`src/reassembly`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#reassembly-manual)

&emsp; `jspcap.reassembly` bases on algorithms described in [`RFC 815`](https://tools.ietf.org/html/rfc815), implements datagram reassembly of IP and TCP packets. Currently, it supports reassembly of only 3 different protocols.

<a name="index-reassembly"> </a>

##### Reassembly

|                                                 NAME                                                |   DESCRIPTION   |
| :-------------------------------------------------------------------------------------------------: | :-------------: |
| [`IPv4_Reassembly`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#ipv4_reassembly) | IPv4 Reassembly |
| [`IPv6_Reassembly`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#ipv6_reassembly) | IPv6 Reassembly |
| [`TCP_Reassembly`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#tcp_reassembly)   | TCP Reassembly  |

&nbsp;

<a name="utilities"> </a> 

## Utilities

 > described in [`src/utilities`](https://github.com/JarryShaw/jspcap/tree/master/src/utilities#utilities-manual)

&emsp; `jspcap.utilities` contains several useful functions and classes which are fundations of `jspcap`, including decorater function `seekset` and `beholder`, `dict`-like class `Info`, `tuple`-like class `VersionInfo`, and protocol collection class `ProtoChain`.

<a name="index-utilities"> </a>

##### Utilities

|                                            NAME                                            |            DESCRIPTION            |
| :----------------------------------------------------------------------------------------: | :-------------------------------: |
| [`decorators`](https://github.com/JarryShaw/jspcap/tree/master/src/utilities#decorators)   |    Python decorator functions     |
| [`Info`](https://github.com/JarryShaw/jspcap/tree/master/src/utilities#info)               |         `dict`-like class         |
| [`VersionInfo`](https://github.com/JarryShaw/jspcap/tree/master/src/utilities#versioninfo) |        `tuple`-like class         |
| [`ProtoChain`](https://github.com/JarryShaw/jspcap/tree/master/src/utilities#protochain)   |     protocol collection class     |
| [`validations`](https://github.com/JarryShaw/jspcap/tree/master/src/utilities#validations) | user-defined validation functions |
| [`exceptions`](https://github.com/JarryShaw/jspcap/tree/master/src/utilities#exceptions)   |  user-refined exception classes   |

&nbsp;

## TODO

 - [x] interface verbs
 - [x] review docstrings
 - [ ] write documentation for `jspcap`
 - [ ] implement IP and MAC address containers
