# JSPCAP Manual

&emsp; `jspcap` is an open source library for PCAP extraction and analysis, written in __Python 3.6__. The following is a manual for this library.

 - [Foundation](#foundation)
    * [Module Manual](https://github.com/JarryShaw/jspcap/tree/master/src/foundation#foundation-manual)
    * [Module Index](#index-foundation)
 - [Interface](#interface)
    * [Module Manual](https://github.com/JarryShaw/jspcap/tree/master/src/interface#interface-manual)
    * [Module Index](#index-interface)
 - [Reassembly](#reassembly)
    * [Module Manual](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#reassembly-manual)
    * [Module Index](#index-reassembly)
 - [IPSuite](#ipsuite)
    * [Module Manual](https://github.com/JarryShaw/jspcap/tree/master/src/ipsuite#ipsuite-manual)
    * [Module Index](#index-ipsuite)
 - [Protocols](protocols)
    * [Module Manual](https://github.com/JarryShaw/jspcap/tree/master/src/protocols#protocols-manual)
    * [Module Index](#index-protocols)
 - [Utilities](#utilities)
    * [Module Manual](https://github.com/JarryShaw/jspcap/tree/master/src/utilities#utilities-maunal)
    * [Module Index](#index-utilities)
 - [CoreKit](#corekit)
    * [Module Manual](https://github.com/JarryShaw/jspcap/tree/master/src/corekit#corekit-manual)
    * [Module Index](#index-corekit)
 - [DumpKit](#dumpkit)
    * [Module Manual](https://github.com/JarryShaw/jspcap/tree/master/src/dumpkit#dumpkit-manual)
    * [Module Index](#index-dumpkit)
 - [TODO](#todo)

---

## Foundation

 > described in [`src/foundation`](https://github.com/JarryShaw/jspcap/tree/master/src/foundation#foundation-manual)

&emsp; `jspcap.foundation` is a collection of foundation for `jspcap`, including PCAP file extraction tool `Extractor`, application layer protocol analyser `analyse` and TCP packet flow tracer `TraceFlow`.

<a name="index-foundation"> </a>

|                                          NAME                                           |             DESCRIPTION              |
| :-------------------------------------------------------------------------------------: | :----------------------------------: |
| [`Analysis`](https://github.com/JarryShaw/jspcap/tree/master/src/foundation#analysis)   | match protocols & extract attributes |
| [`Extractor`](https://github.com/JarryShaw/jspcap/tree/master/src/foundation#extractor) | extract parameters from a PCAP file  |
| [`TraceFlow`](https://github.com/JarryShaw/jspcap/tree/master/src/foundation#traceflow) |        trace TCP packet flows        |

&nbsp;

## Interface

 > described in [`src/interface`](https://github.com/JarryShaw/jspcap/tree/master/src/interface#interfaces-manual)

&emsp; Since `jspcap` has massive classes and numerous functions, `jspcap.interface` defines several user-oriented interfaces, variables, and etc. These interfaces are designed to help and simplify the usage of `jspcap`.

<a name="index-interface"> </a>

|                                           NAME                                           |            DESCRIPTION            |
| :--------------------------------------------------------------------------------------: | :-------------------------------: |
| [`extract`](https://github.com/JarryShaw/jspcap/tree/master/src/interface#extract)       |        extract a PCAP file        |
| [`analyse`](https://github.com/JarryShaw/jspcap/tree/master/src/interface#analyse)       | analyse application layer packets |
| [`reassemble`](https://github.com/JarryShaw/jspcap/tree/master/src/interface#reassemble) |  reassemble fragmented datagrams  |
| [`trace`](https://github.com/JarryShaw/jspcap/tree/master/src/interface#trace)           |      trace TCP packet flows       |

&nbsp;

## Reassembly

 > described in [`src/reassembly`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#reassembly-manual)

&emsp; `jspcap.reassembly` bases on algorithms described in [`RFC 815`](https://tools.ietf.org/html/rfc815), implements datagram reassembly of IP and TCP packets. Currently, it supports reassembly of only 3 different protocols.

<a name="index-reassembly"> </a>

|                                                 NAME                                                |   DESCRIPTION   |
| :-------------------------------------------------------------------------------------------------: | :-------------: |
| [`IPv4_Reassembly`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#ipv4_reassembly) | IPv4 Reassembly |
| [`IPv6_Reassembly`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#ipv6_reassembly) | IPv6 Reassembly |
| [`TCP_Reassembly`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#tcp_reassembly)   | TCP Reassembly  |

&nbsp;

## IPSuite

 > described in [`src/ipsuite`](https://github.com/JarryShaw/jspcap/tree/master/src/ipsuite#ipsuite-manual)

&emsp; `jspcap.ipsuite` is a collection for protocol constructor described in [Internet Protocol Suite](https://en.wikipedia.org/wiki/Internet_protocol_suite), which is now under construction.

<a name="index-ipsuite"> </a>

|                                          NAME                                          |             DESCRIPTION             |
| :------------------------------------------------------------------------------------: | :---------------------------------: |
| [`IPSHeader`](https://github.com/JarryShaw/jspcap/tree/master/src/ipsuite/pcap#header) |            Global Header            |
| [`IPSFrame`](https://github.com/JarryShaw/jspcap/tree/master/src/ipsuite/pcap#frame)   |            Frame Header             |

&nbsp;

## Protocols

 > described in [`src/protocols`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols#protocols-manual)

&emsp; `jspcap.protocols` is a collection of all protocol families, with detailed implementation and methods. Currently, it includes altogether 22 different protocols and three macro variables.

<a name="index-protocols"> </a>

##### Macros

|                                               NAME                                              |           DESCRIPTION            |
| :---------------------------------------------------------------------------------------------: | :------------------------------: |
| [`LINKTYPE`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#linktype)       |  Link-Layer Header Type Values   |
| [`ETHERTYPE`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#ethertype) |    EtherType IEEE 802 Numbers    |
| [`TP_PROTO`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/transport#tp_proto)  | Transport Layer Protocol Numbers |

##### Protocols

|                                                NAME                                               |             DESCRIPTION             |
| :-----------------------------------------------------------------------------------------------: | :---------------------------------: |
| [`Header`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/pcap#header)             |            Global Header            |
| [`Frame`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/pcap#frame)               |            Frame Header             |
| [`Raw`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols#raw)                        |           Raw Packet Data           |
| [`ARP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#arp)                   |     Address Resolution Protocol     |
| [`Ethernet`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#ethernet)         |          Ethernet Protocol          |
| [`L2TP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#l2tp)                 |   Layer Two Tunnelling Protocol     |
| [`OSPF`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#ospf)                 |      Open Shortest Path First       |
| [`RARP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#rarp)                 | Reverse Address Resolution Protocol |
| [`VLAN`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#vlan)                 |    802.1Q Customer VLAN Tag Type    |
| [`AH`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#ah)                 |       Authentication Header         |
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

## Utilities

 > described in [`src/utilities`](https://github.com/JarryShaw/jspcap/tree/master/src/utilities#utilities-manual)

&emsp; `jspcap.utilities` contains several useful functions and classes which are foundations of `jspcap`, including decorator function `seekset` and `beholder`, user-refined exceptions and validators.

<a name="index-utilities"> </a>

|                                            NAME                                            |            DESCRIPTION            |
| :----------------------------------------------------------------------------------------: | :-------------------------------: |
| [`decorators`](https://github.com/JarryShaw/jspcap/tree/master/src/utilities#decorators)   |    Python decorator functions     |
| [`validations`](https://github.com/JarryShaw/jspcap/tree/master/src/utilities#validations) | user-defined validation functions |
| [`exceptions`](https://github.com/JarryShaw/jspcap/tree/master/src/utilities#exceptions)   |  user-refined exception classes   |

&nbsp;

## CoreKit

 > described in [`src/corekit`](https://github.com/JarryShaw/jspcap/tree/master/src/corekit#corekit-manual)

&emsp; `jspcap.corekit` is the collection of core utilities for `jspcap` implementation, including `dict`-like class `Info`, `tuple`-like class `VersionInfo`, and protocol collection class `ProtoChain`.

<a name="index-corekit"> </a>

|                                           NAME                                           |            DESCRIPTION            |
| :--------------------------------------------------------------------------------------: | :-------------------------------: |
| [`Info`](https://github.com/JarryShaw/jspcap/tree/master/src/corekit#info)               |         `dict`-like class         |
| [`VersionInfo`](https://github.com/JarryShaw/jspcap/tree/master/src/corekit#versioninfo) |        `tuple`-like class         |
| [`ProtoChain`](https://github.com/JarryShaw/jspcap/tree/master/src/corekit#protochain)   |     protocol collection class     |

&nbsp;

## DumpKit

 > described in [`src/dumpkit`](https://github.com/JarryShaw/jspcap/tree/master/src/dumpkit#dumpkit-manual)

&emsp; `jspcap.dumpkit` is the collection of dumpers for `jspcap` implementation, which is alike those described in [`jsformat`](https://github.com/JarryShaw/jsformat).

<a name="index-dumpkit"> </a>

|                                    NAME                                    |    DESCRIPTION    |
| :------------------------------------------------------------------------: | :---------------: |
| [`PCAP`](https://github.com/JarryShaw/jspcap/tree/master/src/dumpkit#pcap) | dump as PCAP file |

&nbsp;

## TODO

 - [x] interface verbs
 - [x] review docstrings
 - [ ] write documentation for `jspcap`
 - [ ] implement IP and MAC address containers
