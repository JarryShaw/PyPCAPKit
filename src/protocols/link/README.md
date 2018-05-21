# Link Layer Protocols Manual

<!-- NotImplemented -->

&emsp; `jspcap.protocols.link` is collection of all protocols in link layer, with detailed implementation and methods.

 - [`LINKTYPE`](#linktype)
 - [`Link`](#link)
 - [`ARP`](#arp)
 - [`Ethernet`](#ethernet)
 - [`L2TP`](#l2tp)
 - [`OSPF`](#ospf)
 - [`RARP`](#rarp)
 - [`VLAN`](#vlan)

---

## `LINKTYPE`

 > described in [`src/protocols/link.py`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link/link.py)

&emsp; `LINKTYPE` is a `dict` containing link layer type values registered in [TCPDump](http://www.tcpdump.org/linktypes.html).

##### Link-Layer Header Type Values

| VALUE |                                          NAME                                         |        DESCRIPTION         |
| :---: | :-----------------------------------------------------------------------------------: | :------------------------: |
|  `0`  | `Null`                                                                                | BSD loopback encapsulation |
|  `1`  | [`Ethernet`](#ethernet)                                                               |    IEEE 802.3 Ethernet     |
| `101` | `Raw`                                                                                 |           Raw IP           |
| `228` | [`IPv4`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#ipv4) |          Raw IPv4          |
| `229` | [`IPv6`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#ipv6) |          Raw IPv6          |
| `248` | `SCTP`                                                                                |        SCTP packets        |

## `Link`

 > described in [`src/protocols/link/link.py`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link/link.py)

```python
class Link(jspcap.protocols.protocol.Protocol)
```

##### Abstract base class for link layer protocol family.

 - Properties:
    * `name` -- `str`, name of corresponding procotol
    * `info` -- `Info`, info dict of current instance
    * `alias` -- `str`, acronym of corresponding procotol
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
            * [Internet Layer](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#internet-layer-protocols-manual):
                - [`IPv4`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#ipv4) -- Internet Protocol version 4
                - [`IPv6`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#ipv6) -- Internet Protocol version 6
                - [`IPX`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#ipx) -- Internetwork Protocol Exchange
    * all other utility functions inherited from [`Protocol`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols#protocol)

## `ARP`

 > described in [`src/protocols/link/link/arp.py`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link/arp.py)

```python
class ARP(jspcap.protocols.link.link.Link)
```

##### This class implements all protocols in ARP family.

 - Relative protocols:
    * Address Resolution Protocol (ARP) [RFC 826](https://tools.ietf.org/html/rfc826)
    * Reverse Address Resolution Protocol (RARP) [RFC 903](https://tools.ietf.org/html/rfc903)
    * Dynamic Reverse Address Resolution Protocol (DRARP) [RFC 1931](https://tools.ietf.org/html/rfc1931)
    * Inverse Address Resolution Protocol (InARP) [RFC 2390](https://tools.ietf.org/html/rfc2390)

 - Properties:
    * `name` -- `str`, name of corresponding procotol
    * `info` -- `Info`, info dict of current instance
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
    * `alias` -- `str`, acronym of corresponding procotol
    * `layer` -- `str`, `Link`
    * `length` -- `int`, header length of corresponding protocol
    * `protocol` -- `str`, name of next layer protocol
    * `protochain` -- `ProtoChain`, protocol chain of current instance
    * `src` -- `tuple<str, str>`, sender hardware & protocol address
    * `dst` -- `tuple<str, str>`, target hardware & protocol address
    * `type` -- `tuple<str, str>`, hardware & protocol type

 - Methods:
    * `read_arp` -- read Address Resolution Protocol
