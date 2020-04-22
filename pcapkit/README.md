# PyPCAPKit Manual

&emsp; `pcapkit` is an open source library for PCAP extraction and analysis, written in __Python 3.5__. The following is a manual for this library.

 - [Interface](#interface)
    * [Module Manual](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#interface-manual)
    * [Module Index](#index-interface)
 - [Foundation](#foundation)
    * [Module Manual](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/foundation#foundation-manual)
    * [Module Index](#index-foundation)
 - [Reassembly](#reassembly)
    * [Module Manual](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly#reassembly-manual)
    * [Module Index](#index-reassembly)
 - [IPSuite](#ipsuite)
    * [Module Manual](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/ipsuite#ipsuite-manual)
    * [Module Index](#index-ipsuite)
 - [Protocols](protocols)
    * [Module Manual](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#protocols-manual)
    * [Module Index](#index-protocols)
 - [Utilities](#utilities)
    * [Module Manual](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/utilities#utilities-maunal)
    * [Module Index](#index-utilities)
 - [CoreKit](#corekit)
    * [Module Manual](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/corekit#corekit-manual)
    * [Module Index](#index-corekit)
 - [ToolKit](#toolkit)
    * [Module Manual](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit#toolkit-manual)
    * [Module Index](#index-toolkit)
 - [DumpKit](#dumpkit)
    * [Module Manual](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/dumpkit#dumpkit-manual)
    * [Module Index](#index-dumpkit)
 - [TODO](#todo)

---

## Interface

 > described in [`src/interface`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#interfaces-manual)

&emsp; Since `pcapkit` has massive classes and numerous functions, `pcapkit.interface` defines several user-oriented interfaces, variables, and etc. These interfaces are designed to help and simplify the usage of `pcapkit`.

<a name="index-interface"> </a>

#### Library Interfaces

| NAME                                                                                        | DESCRIPTION                       |
| :------------------------------------------------------------------------------------------ | :-------------------------------- |
| [`extract`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#extract)       | extract a PCAP file               |
| [`analyse`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#analyse)       | analyse application layer packets |
| [`reassemble`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#reassemble) | reassemble fragmented datagrams   |
| [`trace`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#trace)           | trace TCP packet flows            |

#### Output Formats

| NAME                                                                                | DESCRIPTION                              |
| :---------------------------------------------------------------------------------- | :--------------------------------------- |
| [`JSON`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#formats)  | JavaScript Object Notation (JSON) format |
| [`PLIST`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#formats) | macOS Property LIST (PLIST) format       |
| [`TREE`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#formats)  | Tree-View TeXT (TXT) format              |
| [`PCAP`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#formats)  | Packet CAPture (PCAP) format             |

#### Layer Thresholds

| NAME                                                                               | DESCRIPTION       |
| :--------------------------------------------------------------------------------- | :---------------- |
| [`RAW`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#layers)   | no specific layer |
| [`LINK`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#layers)  | data-link layer   |
| [`INET`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#layers)  | internet layer    |
| [`TRANS`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#layers) | transport layer   |
| [`APP`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#layers)   | application layer |

#### Extraction Engines

| NAME                                                                                     | DESCRIPTION                                                 |
| :--------------------------------------------------------------------------------------- | :---------------------------------------------------------- |
| [`PCAPKit`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#engines)    | the default engine                                          |
| [`MPServer`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#engines)   | the multiprocessing engine with server process strategy     |
| [`MPPipeline`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#engines) | the multiprocessing engine with pipeline strategy           |
| [`DPKT`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#engines)       | the [`DPKT`](https://github.com/kbandla/dpkt) engine        |
| [`Scapy`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#engines)      | the [`Scapy`](https://scapy.net) engine                     |
| [`PyShark`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#engines)    | the [`PyShark`](https://kiminewt.github.io/pyshark/) engine |

&nbsp;

## Foundation

 > described in [`src/foundation`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/foundation#foundation-manual)

&emsp; `pcapkit.foundation` is a collection of foundation for `pcapkit`, including PCAP file extraction tool `Extractor`, application layer protocol analyser `analyse` and TCP packet flow tracer `TraceFlow`.

<a name="index-foundation"> </a>

| NAME                                                                                       | DESCRIPTION                          |
| :----------------------------------------------------------------------------------------- | :----------------------------------- |
| [`Analysis`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/foundation#analysis)   | match protocols & extract attributes |
| [`Extractor`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/foundation#extractor) | extract parameters from a PCAP file  |
| [`TraceFlow`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/foundation#traceflow) | trace TCP packet flows               |

&nbsp;

## Reassembly

 > described in [`src/reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly#reassembly-manual)

&emsp; `pcapkit.reassembly` bases on algorithms described in [`RFC 815`](https://tools.ietf.org/html/rfc815), implements datagram reassembly of IP and TCP packets. Currently, it supports reassembly of only 3 different protocols.

<a name="index-reassembly"> </a>

| NAME                                                                                                   | DESCRIPTION     |
| :----------------------------------------------------------------------------------------------------- | :-------------- |
| [`IPv4_Reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly#ipv4_reassembly) | IPv4 Reassembly |
| [`IPv6_Reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly#ipv6_reassembly) | IPv6 Reassembly |
| [`TCP_Reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly#tcp_reassembly)   | TCP Reassembly  |

&nbsp;

## IPSuite

 > described in [`src/ipsuite`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/ipsuite#ipsuite-manual)

&emsp; `pcapkit.ipsuite` is a collection for protocol constructor described in [Internet Protocol Suite](https://en.wikipedia.org/wiki/Internet_protocol_suite), which is now under construction.

<a name="index-ipsuite"> </a>

| NAME                                                                                      | DESCRIPTION   |
| :---------------------------------------------------------------------------------------- | :------------ |
| [`IPSHeader`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/ipsuite/pcap#header) | Global Header |
| [`IPSFrame`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/ipsuite/pcap#frame)   | Frame Header  |

&nbsp;

## Protocols

 > described in [`src/protocols`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#protocols-manual)

&emsp; `pcapkit.protocols` is a collection of all protocol families, with detailed implementation and methods. Currently, it includes altogether 22 different protocols and three macro variables.

<a name="index-protocols"> </a>

##### Macros

| NAME                                                                                               | DESCRIPTION                      |
| :------------------------------------------------------------------------------------------------- | :------------------------------- |
| [`LINKTYPE`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/link#linktype)       | Link-Layer Header Type Values    |
| [`ETHERTYPE`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ethertype) | EtherType IEEE 802 Numbers       |
| [`TP_PROTO`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/transport#tp_proto)  | Transport Layer Protocol Numbers |

##### Protocols

| NAME                                                                                                 | DESCRIPTION                         |
| :--------------------------------------------------------------------------------------------------- | :---------------------------------- |
| [`Header`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/pcap#header)             | Global Header                       |
| [`Frame`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/pcap#frame)               | Frame Header                        |
| [`NoPayload`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#nopayload)            | No-Payload                          |
| [`Raw`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#raw)                        | Raw Packet Data                     |
| [`ARP`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/link#arp)                   | Address Resolution Protocol         |
| [`Ethernet`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/link#ethernet)         | Ethernet Protocol                   |
| [`L2TP`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/link#l2tp)                 | Layer Two Tunnelling Protocol       |
| [`OSPF`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/link#ospf)                 | Open Shortest Path First            |
| [`RARP`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/link#rarp)                 | Reverse Address Resolution Protocol |
| [`VLAN`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/link#vlan)                 | 802.1Q Customer VLAN Tag Type       |
| [`AH`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ah)                 | Authentication Header               |
| [`HIP`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#hip)               | Host Identity Protocol              |
| [`HOPOPT`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#hopopt)         | IPv6 Hop-by-Hop Options             |
| [`IP`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ip)                 | Internet Protocol                   |
| [`IPsec`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ipsec)           | Internet Protocol Security          |
| [`IPv4`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ipv4)             | Internet Protocol version 4         |
| [`IPv6`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ipv6)             | Internet Protocol version 6         |
| [`IPv6_Frag`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ipv6_frag)   | Fragment Header for IPv6            |
| [`IPv6_Opts`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ipv6_opts)   | Destination Options for IPv6        |
| [`IPv6_Route`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ipv6_route) | Routing Header for IPv6             |
| [`IPX`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ipx)               | Internetwork Packet Exchange        |
| [`MH`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#mh)                 | Mobility Header                     |
| [`TCP`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/transport#tcp)              | Transmission Control Protocol       |
| [`UDP`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/transport#udp)              | User Datagram Protocol              |
| [`HTTP`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/application#http)          | Hypertext Transfer Protocol         |

&nbsp;

## Utilities

 > described in [`src/utilities`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/utilities#utilities-manual)

&emsp; `pcapkit.utilities` contains several useful functions and classes which are foundations of `pcapkit`, including decorator function `seekset` and `beholder`, user-refined exceptions and validators.

<a name="index-utilities"> </a>

| NAME                                                                                          | DESCRIPTION                       |
| :-------------------------------------------------------------------------------------------- | :-------------------------------- |
| [`decorators`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/utilities#decorators)   | Python decorator functions        |
| [`validations`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/utilities#validations) | user-defined validation functions |
| [`exceptions`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/utilities#exceptions)   | user-refined exception classes    |

&nbsp;

## CoreKit

 > described in [`src/corekit`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/corekit#corekit-manual)

&emsp; `pcapkit.corekit` is the collection of core utilities for `pcapkit` implementation, including `dict`-like class `Info`, `tuple`-like class `VersionInfo`, and protocol collection class `ProtoChain`.

<a name="index-corekit"> </a>

| NAME                                                                                        | DESCRIPTION               |
| :------------------------------------------------------------------------------------------ | :------------------------ |
| [`Info`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/corekit#info)               | `dict`-like class         |
| [`VersionInfo`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/corekit#versioninfo) | `tuple`-like class        |
| [`ProtoChain`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/corekit#protochain)   | protocol collection class |

&nbsp;

## ToolKit

 > described in [`src/toolkit`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit#toolkit-manual)

&emsp; `pcapkit.toolkit` is the collections of tools for capability with PCAP extraction engine, such as the default engine, [`Scapy`](https://scapy.net) engine, [`DPKT`](https://github.com/kbandla/dpkt) engine, and [`PyShark`](https://kiminewt.github.io/pyshark/) engine.

<a name="index-toolkit"> </a>

#### [`PyPCAPKit`](https://github.com/JarryShaw/PyPCAPKit#PyPCAPKit) Engines

| NAME                                                                                                | DESCRIPTION     |
| :-------------------------------------------------------------------------------------------------- | :-------------- |
| [`ipv4_reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit#ipv4_reassembly) | IPv4 reassembly |
| [`ipv6_reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit#ipv6_reassembly) | IPv6 reassembly |
| [`tcp_reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit#tcp_reassembly)   | TCP reassembly  |
| [`tcp_traceflow`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit#tcp_traceflow)     | trace TCP flows |

#### [`DPKT`](https://github.com/kbandla/dpkt) Engine

| NAME                                                                                                          | DESCRIPTION                                                                                    |
| :------------------------------------------------------------------------------------------------------------ | :--------------------------------------------------------------------------------------------- |
| [`dpkt_ipv6_hdr_len`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit#dpkt_ipv6_hdr_len)       | header length                                                                                  |
| [`dpkt_packet2chain`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit#dpkt_packet2chain)       | make [`ProtoChain`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/corekit#protochain) |
| [`dpkt_packet2dict`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit#dpkt_packet2dict)         | convert to `dict`                                                                              |
| [`dpkt_ipv4_reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit#dpkt_pv4_reassembly)  | IPv4 reassembly                                                                                |
| [`dpkt_ipv6_reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit#dpkt_ipv6_reassembly) | IPv6 reassembly                                                                                |
| [`dpkt_tcp_reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit#dpkt_tcp_reassembly)   | TCP reassembly                                                                                 |
| [`dpkt_tcp_traceflow`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit#dpkt_tcp_traceflow)     | trace TCP flows                                                                                |

#### [`PyShark`](https://kiminewt.github.io/pyshark/) Engine

| NAME                                                                                                            | DESCRIPTION       |
| :-------------------------------------------------------------------------------------------------------------- | :---------------- |
| [`pyshark_packet2dict`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit#pyshark_packet2dict)     | convert to `dict` |
| [`pyshark_tcp_traceflow`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit#pyshark_tcp_traceflow) | trace TCP flows   |

#### [`Scapy`](https://scapy.net) Engine

| NAME                                                                                                            | DESCRIPTION                                                                                    |
| :-------------------------------------------------------------------------------------------------------------- | :--------------------------------------------------------------------------------------------- |
| [`scapy_packet2chain`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit#scapy_packet2chain)       | make [`ProtoChain`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/corekit#protochain) |
| [`scapy_packet2dict`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit#scapy_packet2dict)         | convert to `dict`                                                                              |
| [`scapy_ipv4_reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit#scapy_pv4_reassembly)  | IPv4 reassembly                                                                                |
| [`scapy_ipv6_reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit#scapy_ipv6_reassembly) | IPv6 reassembly                                                                                |
| [`scapy_tcp_reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit#scapy_tcp_reassembly)   | TCP reassembly                                                                                 |
| [`scapy_tcp_traceflow`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit#scapy_tcp_traceflow)     | trace TCP flows                                                                                |

## DumpKit

 > described in [`src/dumpkit`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/dumpkit#dumpkit-manual)

&emsp; `pcapkit.dumpkit` is the collection of dumpers for `pcapkit` implementation, which is alike those described in [`dictdumper`](https://github.com/JarryShaw/DictDumper#dictdumper).

<a name="index-dumpkit"> </a>

| NAME                                                                                                  | DESCRIPTION                  |
| :---------------------------------------------------------------------------------------------------- | :--------------------------- |
| [`NotImplementedIO`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/dumpkit#notimplementedio) | NotImplemented I/O simulator |
| [`PCAP`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/dumpkit#pcap)                         | dump as PCAP file            |

&nbsp;

## TODO

 - [x] interface verbs
 - [x] review docstrings
 - [ ] write documentation for `pcapkit`
 - [ ] implement IP and MAC address containers
