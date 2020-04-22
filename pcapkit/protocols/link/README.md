# Link Layer Protocols Manual

&emsp; `pcapkit.protocols.link` is collection of all protocols in link layer, with detailed implementation and methods.

 - [`Link`](#link)
    * [`LINKTYPE`](#linktype)
 - [`ARP`](#arp)
 - [`Ethernet`](#ethernet)
 - [`L2TP`](#l2tp)
 - [`OSPF`](#ospf)
 - [`RARP`](#rarp)
 - [`VLAN`](#vlan)

---

## `Link`

 > described in [`src/protocols/link/link.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/link/link.py)

```python
class Link(pcapkit.protocols.protocol.Protocol)
```

##### Abstract base class for link layer protocol family.

 - Properties:
    * `name` -- `str`, name of corresponding protocol
    * `info` -- `Info`, info dict of current instance
    * `alias` -- `str`, acronym of corresponding protocol
    * `layer` -- `str`, `'Link'`
    * `length` -- `int`, header length of corresponding protocol
    * `protocol` -- `str`, name of next layer protocol
    * `protochain` -- `ProtoChain`, protocol chain of current instance

 - Utility functions (for development use):
    * `_import_next_layer` -- import next layer protocol extractor
        ```python
        @beholder
        _import_next_layer(self, proto, length=None)
        ```
        - Positional arguments:
            * `proto` -- `str`, next layer protocol name
            * `length` -- `int`, valid (not padding) length
        - Returns:
            * `bool` -- flag if extraction of next layer succeeded
            * `Info` -- info of next layer
            * `ProtoChain` -- protocol chain of next layer
            * `str` -- alias of next layer
        - Supported protocols:
            * [Link Layer](#link-layer-protocols-manual):
                - [`ARP`](#arp) -- Address Resolution Protocol
                - [`RARP`](#rarp) -- Reversed Address Resolution Protocol
                - [`VLAN`](#vlan) -- 802.1Q Customer VLAN Tag Type
            * [Internet Layer](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#internet-layer-protocols-manual):
                - [`IPv4`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ipv4) -- Internet Protocol version 4
                - [`IPv6`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ipv6) -- Internet Protocol version 6
                - [`IPX`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ipx) -- Internetwork Protocol Exchange
    * all other utility functions inherited from [`Protocol`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#protocol)

### `LINKTYPE`

&emsp; `LINKTYPE` is a `dict` containing link layer type values registered in [TCPDump](http://www.tcpdump.org/linktypes.html).

##### Link-Layer Header Type Values

| VALUE | NAME                                                                                     | DESCRIPTION                |
| :---- | :--------------------------------------------------------------------------------------- | :------------------------- |
| `0`   | `Null`                                                                                   | BSD loopback encapsulation |
| `1`   | [`Ethernet`](#ethernet)                                                                  | IEEE 802.3 Ethernet        |
| `101` | `Raw`                                                                                    | Raw IP                     |
| `228` | [`IPv4`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ipv4) | Raw IPv4                   |
| `229` | [`IPv6`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ipv6) | Raw IPv6                   |
| `248` | `SCTP`                                                                                   | SCTP packets               |

## `ARP`

 > described in [`src/protocols/link/arp.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/link/arp.py)

```python
class ARP(pcapkit.protocols.link.link.Link)
```

##### This class implements all protocols in ARP family.

 - Relative protocols:
    * Address Resolution Protocol (ARP) [[RFC 826](https://tools.ietf.org/html/rfc826)]
    * Reverse Address Resolution Protocol (RARP) [[RFC 903](https://tools.ietf.org/html/rfc903)]
    * Dynamic Reverse Address Resolution Protocol (DRARP) [[RFC 1931](https://tools.ietf.org/html/rfc1931)]
    * Inverse Address Resolution Protocol (InARP) [[RFC 2390](https://tools.ietf.org/html/rfc2390)]

 - Properties:
    * `name` -- `str`, name of corresponding protocol
    * `info` -- `Info`, info dict of current instance [[RFC 826](https://tools.ietf.org/html/rfc826)]
        ```
        ARP
         |-- htype --> str, Hardware Type
         |-- ptype --> str, Protocol Type
         |-- hlen --> int, Hardware Address Length
         |-- plen --> int, Protocol Address Length
         |-- oper --> str, Operation
         |-- sha --> str, Sender Hardware Address
         |-- spa --> str, Sender Protocol Address
         |-- tha --> str, Target Hardware Address
         |-- tpa --> str, Target Hardware Address
         |-- len --> int, protocol header length
        ```
    * `alias` -- `str`, acronym of corresponding protocol
    * `layer` -- `str`, `'Link'`
    * `length` -- `int`, header length of corresponding protocol
    * `protocol` -- `str`, name of next layer protocol
    * `protochain` -- `ProtoChain`, protocol chain of current instance
    * `src` -- `tuple<str, str>`, sender hardware & protocol address
    * `dst` -- `tuple<str, str>`, target hardware & protocol address
    * `type` -- `tuple<str, str>`, hardware & protocol type

 - Methods:
    * `decode_bytes` -- try to decode `bytes` into `str` (cf. [`pcapkit.protocols.protocol.Protocol`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#protocol))
    * `decode_url` -- decode URLs into Unicode (cf. [`pcapkit.protocols.protocol.Protocol`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#protocol))
    * `read_arp` -- read Address Resolution Protocol

## `Ethernet`

 > described in [`src/protocols/link/ethernet.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/link/ethernet.py)

```python
class Ethernet(pcapkit.protocols.link.link.Link)
```

##### This class implements Ethernet Protocol.

 - Properties:
    * `name` -- `str`, name of corresponding protocol
    * `info` -- `Info`, info dict of current instance [[RFC 7042](https://tools.ietf.org/html/rfc7042)]
        ```
        Ethernet
         |-- dst --> str, destination MAC address
         |-- src --> str, source MAC address
         |-- type --> str, next layer protocol's name
        ```
    * `alias` -- `str`, acronym of corresponding protocol
    * `layer` -- `str`, `'Link'`
    * `length` -- `int`, header length of corresponding protocol
    * `protocol` -- `str`, name of next layer protocol
    * `protochain` -- `ProtoChain`, protocol chain of current instance
    * `src` -- `str`, destination MAC address
    * `dst` -- `str`, source MAC address

 - Methods:
    * `decode_bytes` -- try to decode `bytes` into `str` (cf. [`pcapkit.protocols.protocol.Protocol`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#protocol))
    * `decode_url` -- decode URLs into Unicode (cf. [`pcapkit.protocols.protocol.Protocol`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#protocol))
    * `read_ethernet` -- read Ethernet Protocol

## `L2TP`

 > described in [`src/protocols/link/l2tp.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/link/l2tp.py)

```python
class L2TP(pcapkit.protocols.link.link.Link)
```

##### This class implements Layer Two Tunnelling Protocol.

 - Properties:
    * `name` -- `str`, name of corresponding protocol
    * `info` -- `Info`, info dict of current instance [[RFC 2661](https://tools.ietf.org/html/rfc2661)]
        ```
        L2TP
        |-- flags --> dict, flags and version info
        |    |-- type --> str, type string
        |    |-- len --> bool, length flag
        |    |-- seq --> bool, sequence flag
        |    |-- offset --> bool, offset flag
        |    |-- prio --> bool, priority flag
        |-- ver --> int, version
        |-- length --> int, header length
        |-- tunnelid --> int, tunnel ID
        |-- sessionid --> int, session ID
        |-- ns --> int, sequence number
        |-- nr --> int, next sequence number
        |-- offset --> int, offset size
        ```
    * `alias` -- `str`, acronym of corresponding protocol
    * `layer` -- `str`, `'Link'`
    * `length` -- `int`, header length of corresponding protocol
    * `protocol` -- `str`, name of next layer protocol
    * `protochain` -- `ProtoChain`, protocol chain of current instance
    * `type` -- `str`, L2TP type

 - Methods:
    * `decode_bytes` -- try to decode `bytes` into `str` (cf. [`pcapkit.protocols.protocol.Protocol`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#protocol))
    * `decode_url` -- decode URLs into Unicode (cf. [`pcapkit.protocols.protocol.Protocol`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#protocol))
    * read_l2tp -- read Layer Two Tunnelling Protocol

## `OSPF`

 > described in [`src/protocols/link/ospf.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/link/ospf.py)

```python
class OSPF(pcapkit.protocols.link.link.Link)
```

##### This class implements Open Shortest Path First.

 - Properties:
    * `name` -- `str`, name of corresponding protocol
    * `info` -- `Info`, info dict of current instance [[RFC 2661](https://tools.ietf.org/html/rfc2661)]
        ```
        OSPF
         |-- version --> int, version number
         |-- type --> str, type string
         |-- len --> int, packet length
         |-- router_id --> int, router ID
         |-- area_id --> int, area_id
         |-- chksum --> bytes, checksum
         |-- autype --> str, authentication type
         |-- auth --> bytes/dict, authentication
              |-- key_id --> int, key ID
              |-- len --> authentication data length
              |-- seq --> cryptographic sequence number
        ```
    * `alias` -- `str`, acronym of corresponding protocol
    * `layer` -- `str`, `'Link'`
    * `length` -- `int`, header length of corresponding protocol
    * `protocol` -- `str`, name of next layer protocol
    * `protochain` -- `ProtoChain`, protocol chain of current instance
    * `type` -- `str`, OSPF packet type

 - Methods:
    * `decode_bytes` -- try to decode `bytes` into `str` (cf. [`pcapkit.protocols.protocol.Protocol`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#protocol))
    * `decode_url` -- decode URLs into Unicode (cf. [`pcapkit.protocols.protocol.Protocol`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#protocol))
    * `read_ospf` -- read Open Shortest Path First

## `RARP`

 > described in [`src/protocols/link/rarp.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/link/rarp.py)

```python
class RARP(pcapkit.protocols.link.arp.ARP)
```

##### This class implements Reverse Address Resolution Protocol.

 - Relative protocols:
    * Reverse Address Resolution Protocol (RARP) [[RFC 903](https://tools.ietf.org/html/rfc903)]
    * Dynamic Reverse Address Resolution Protocol (DRARP) [[RFC 1931](https://tools.ietf.org/html/rfc1931)]

 - Properties:
    * `name` -- `str`, name of corresponding protocol
    * `info` -- `Info`, info dict of current instance [[RFC 826](https://tools.ietf.org/html/rfc826)]
        ```
        RARP
         |-- htype --> str, Hardware Type
         |-- ptype --> str, Protocol Type
         |-- hlen --> int, Hardware Address Length
         |-- plen --> int, Protocol Address Length
         |-- oper --> str, Operation
         |-- sha --> str, Sender Hardware Address
         |-- spa --> str, Sender Protocol Address
         |-- tha --> str, Target Hardware Address
         |-- tpa --> str, Target Hardware Address
         |-- len --> int, protocol header length
        ```
    * `alias` -- `str`, acronym of corresponding protocol
    * `layer` -- `str`, `'Link'`
    * `length` -- `int`, header length of corresponding protocol
    * `protocol` -- `str`, name of next layer protocol
    * `protochain` -- `ProtoChain`, protocol chain of current instance
    * `src` -- `tuple<str, str>`, sender hardware & protocol address
    * `dst` -- `tuple<str, str>`, target hardware & protocol address
    * `type` -- `tuple<str, str>`, hardware & protocol type

 - Methods:
    * `decode_bytes` -- try to decode `bytes` into `str` (cf. [`pcapkit.protocols.protocol.Protocol`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#protocol))
    * `decode_url` -- decode URLs into Unicode (cf. [`pcapkit.protocols.protocol.Protocol`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#protocol))
    * `read_arp` -- read Address Resolution Protocol

## `VLAN`

 > described in [`src/protocols/link/vlan.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/link/vlan.py)

```python
class VLAN(pcapkit.protocols.link.link.Link)
```

##### This class implements 802.1Q Customer VLAN Tag Type.

 - Properties:
    * `name` -- `str`, name of corresponding protocol
    * `info` -- `Info`, info dict of current instance [[RFC 7042](https://tools.ietf.org/html/rfc7042)]
        ```
        VLAN
         |-- tci --> dict, tag control information
         |    |-- pcp --> str, priority code point
         |    |-- dei --> bool, drop eligible indicator
         |    |-- vid --> int, VLAN identifier
         |-- type --> str, protocol
        ```
    * `alias` -- `str`, acronym of corresponding protocol
    * `layer` -- `str`, `Link`
    * `length` -- `int`, header length of corresponding protocol
    * `protocol` -- `str`, next layer protocol
    * `protochain` -- `ProtoChain`, protocol chain of current instance

 - Methods:
    * `decode_bytes` -- try to decode `bytes` into `str` (cf. [`pcapkit.protocols.protocol.Protocol`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#protocol))
    * `decode_url` -- decode URLs into Unicode (cf. [`pcapkit.protocols.protocol.Protocol`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#protocol))
    * `read_vlan` -- read 802.1Q Customer VLAN Tag Type
