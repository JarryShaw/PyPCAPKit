# Protocols Manual

<!-- writing: Link Layer Protocols -->

&emsp; `jspcap.protocols` is collection of all protocol families, with detailed implementation and methods.

 - [Base Protocol](#base-protocol)
    * [`Protocol`](#protocol)
 - [Utility Protocols](#utility-protocols)
    * [`Raw`](#raw)
    * [`Header`](#header)
    * [`Frame`](#frame)
 - [Link Layer Protocols](https://gihub.com/JarryShaw/jspcap/tree/master/src/protocols/link#link-layer-protocols-manual)
    * [Macros](#link-macros)
    * [Protocols](#link-protocols)
 - [Internet Layer Protocols](https://gihub.com/JarryShaw/jspcap/tree/master/src/protocols/internet#internet-layer-protocols-manual)
    * [Macros](#internet-macros)
    * [Protocols](#internet-protocols)
 - [Transport Layer Protocols](https://gihub.com/JarryShaw/jspcap/tree/master/src/protocols/transport#transport-layer-protocols-manual)
    * [Macros](#transport-macros)
    * [Protocols](#transport-protocols)
 - [Application Layer Protocols](https://gihub.com/JarryShaw/jspcap/tree/master/src/protocols/application#application-layer-protocols-manual)
    * [Protocols](#application-protocols)
 - [TODO](#todo)

---

## Base Protocol

 > described in [src/protocols/protocol.py](https://gihub.com/JarryShaw/jspcap/tree/master/src/protocols/protocol.py)

&emsp; `jspcap.protocols.protocol` contains [`Protocol`](#protocol) only, which is an abstract base clss for all protocol family, with pre-defined utility arguments and methods of specified protocols.

### `Protocol`

```python
class Protocol(builtins.object)
```

##### Abstract base class for all protocol family.

 - Properties:
    * `name` -- `str`, name of corresponding procotol
    * `info` -- `Info`, info dict of current instance
    * `alias` -- `str`, acronym of corresponding procotol
    * `length` -- `int`, header length of corresponding protocol
    * `protocol` -- `str`, name of next layer protocol
    * `protochain` -- `ProtoChain`, protocol chain of current instance

 - Data modules:
    * not hashable
    * iterable
    * subscriptable

 - Utility functions (for development use):
    * `_read_protos` -- read next layer protocol type
        ```python
        _read_protos(self, size)
        ```
        - Positional arguments:
            * `size`  -- `int`, buffer size
        - Returns:
            * *upon success*, `str` -- name of next layer protocol
            * *upon failure*, `None`
    * `_read_fileng` -- read file buffer
        ```python
        _read_fileng(self, *args, **kwargs)
        ```
        - Notes:
            * works exactly the same as `fp.read`, where `fp` is a *file-like* object
    * `_read_unpack` -- read bytes and unpack to integers
        ```python
        _read_unpack(self, size=1, *, signed=False, lilendian=False, quiet=False)
        ```
        - Positional arguments:
            * `size`  -- `int`, buffer size (default is `1`)
        - Keyword arguments:

            |    NAME     |  TYPE  | DEFAULT |     KEYWORD      |        DESCRIPTION        |
            | :---------: | :----: | :-----: | :--------------: | :-----------------------: |
            |  `signed`   | `bool` | `False` | `True` / `False` |        signed flag        |
            | `lilendian` | `bool` | `False` | `True` / `False` |    little-endian flag     |
            |   `quiet`   | `bool` | `False` | `True` / `False` | quiet (no exception) flag |

        - Returns:
            * `int` -- unpacked data upon success
    * `_read_binary` -- read bytes and convert into binaries
        ```python
        _read_binary(self, size=1)
        ```
        - Positional arguments:
            * `size`  -- `int`, buffer size (default is `1`)
        - Returns:
            * `str` -- binary bits (`0`/`1`)
    * `_read_packet` -- read raw packet data
        ```python
        @seekset
        _read_packet(self, length=None, *, header=None, payload=None, discard=False)
        ```
        - Positional arguments:
            * `length` -- `int`, length of the packet
        - Keyword arguments:
            * `header` -- `int`, length of the packet header
            * `payload` -- `int`, length of the packet payload
            * `discard` -- `bool`, flag if discard header data (`False` in default)
        - Returns:
            * *if header omits* `bytes` -- whole packet data
            * *if discard set True* `bytes` -- packet body only
            * `dict` -- header and payload data
                ```
                Packet
                 |-- header -- bytes, packet header
                 |-- payload -- bytes, packet payload
                ```
    * `_decode_next_layer` -- decode next layer protocol type
        ```python
        _decode_next_layer(self, dict_, proto=None, length=None)
        ```
        - Positional arguments:
            * `dict_` -- `dict`, info buffer
            * `proto` -- `str`, next layer protocol name
            * `length` -- `int`, valid (not padding) length
        - Returns:
            * `dict` -- current protocol with next layer extracted
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

&emsp;

## Utility Protocols

&emsp; For obvious reasons, besides protocols described in TCP/IP framework, there are several special utility protocols, like PCAP global header [`Header`](#header) and frame header [`Frame`](#frame).

### `Raw`

> described in [`src/protocols/raw.py`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/raw.py)

&emsp; `jspcap.protocols.raw` contains `Raw` only, which implements extractor for unknown protocol, and constructs a [`Protocol`](#protocol) like object.

```python
class Raw(jspcap.protocols.protocol.Protocol)
```

##### This class implements universal unknown procotol.

 - Properties:
    * `name` -- `str`, name of corresponding procotol (`'Unknown'`)
    * `info` -- `Info`, info dict of current instance (shows as below)
        ```
        Raw
         |-- packet --> bytes, raw packet data
         |-- error --> str, error infomation when exception raised
        ```
    * `alias` -- `str`, acronym of corresponding procotol (`'Raw'`)
    * `protochain` -- `ProtoChain`, protocol chain of current instance

 - Methods:
    * `read_raw` -- read raw packet data

 - Data modules:
    * initilisation procedure shows as below
        ```python
        __init__(self, file, length=None, *, error=None, **kwargs)
        ```
        - Positional arguments:
            * `file` -- *file-like* object, packet file to be extracted
            * `length` -- `int`, valid length (paddings excluded) of packet
        - Keyword arguments:
            * `error` -- `str`, exception information
    * all other data modules inherited from [`Protocol`](#protocol)

### `Header`

 > described in [`src/protocols/header.py`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/header.py)

&emsp; `jspcap.protocols.header` contains `Header` only, which implements extractor for global headers of PCAP.

```python
class Header(jspcap.protocols.protocol.Protocol)
```

##### PCAP file global header extractor.

 - Properties:
    * `name` -- `str`, name of corresponding procotol (`'Global Header'`)
    * `info` -- `Info`, info dict of current instance
        ```
        Header
         |-- magic_number --> bytes, magic number
         |-- version_major --> int, major version number
         |-- version_minor --> int, minor version number
         |-- thiszone --> int, GMT to local correction
         |-- sigfigs --> int, accuracy of timestamps
         |-- snaplen --> int, max length of captured packets, in octets
         |-- network --> str, data link type
        ```
    * `alias` -- `str`, acronym of corresponding procotol (`'Header'`)
    * `length` -- `int`, header length of global header, (`24`)
    * `version` -- `VersionInfo`, version infomation of input PCAP file
    * `protocol` -- `str`, data link type

 - Methods:
    * `index` -- call [`ProtoChain.index`](https://github.com/JarryShaw/jspcap/tree/master/src#protochain)
    * `read_header` -- read global header of PCAP file

 - Data modules:
    * initilisation procedure shows as below
        ```python
        __init__(self, file)
        ```
        - Positional arguments:
            * `file` -- *file-like* object, packet file to be extracted
    * all other data modules inherited from [`Protocol`](#protocol)

### `Frame`

 > described in [`src/protocols/frame.py`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/frame.py)

&emsp; `jspcap.protocols.frame` contains `Frame` only, which implements extractor for frame headers of PCAP.

```python
class Frame(jspcap.protocols.protocol.Protocol)
```

##### Per packet frame header extractor.

 - Properties:
    * `name` -- `str`, name of corresponding procotol
    * `info` -- `Info`, info dict of current instance
        ```
        Frame
         |-- frame_info --> dict, original frame header
         |      |-- ts_sec --> int, timestamp seconds
         |      |-- ts_usec --> int, timestamp microseconds
         |      |-- incl_len --> int, number of octets of packet saved in file
         |      |-- orig_len --> int, actual length of packet
         |-- time --> datetime.datetime, timestamp
         |-- number --> int, frame number
         |-- time_epoch --> str, time since Unix epoch
         |-- len --> int, number of octets of packet saved in file
         |-- cap_len --> int, actual length of packet
        ```
    * `alias` -- `str`, acronym of corresponding procotol (`'Frame'`)
    * `length` -- `int`, header length of global header, (`16`)
    * `protocol` -- `str`, data link type
    * `protochain` -- `ProtoChain`, protocol chain of current frame

 - Methods:
    * `index` -- call [`ProtoChain.index`](https://github.com/JarryShaw/jspcap/tree/master/src#protochain)
    * `read_header` -- read each block after global header
 
 - Data modules:
    * initilisation procedure shows as below
        ```python
        __init__(self, file, *, num, proto)
        ```
        - Positional arguments:
            * `file` -- *file-like* object, packet file to be extracted
        - Keyword arguments:
            * `num` -- `int`, frame number
            * `proto` -- `str`, data link type from [`Header`](#header)
    * all other data modules inherited from [`Protocol`](#protocol)

&emsp;

## Link Layer Protocols

 > described in [`src/protocols/link`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#link-layer-protocols-manual)

&emsp; `jspcap.protocols.link` is collection of all protocols in link layer, with detailed implementation and methods.

<a name="link-macros"> </a>

### Macros

 - [`LINKTYPE`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#linktype) -- Link-Layer Header Type Values

<a name="link-protocols"> </a>

### Protocols

|                                            NAME                                           |             DESCRIPTION             |
| :---------------------------------------------------------------------------------------: | :---------------------------------: |
| [`ARP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#arp)           |     Address Resolution Protocol     |
| [`Ethernet`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#ethernet) |          Ethernet Protocol          |
| [`L2TP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#l2tp)         |    Layer Two Tunneling Protocol     |
| [`OSPF`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#ospf)         |      Open Shortest Path First       |
| [`RARP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#rarp)         | Reverse Address Resolution Protocol |
| [`VLAN`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#vlan)         |    802.1Q Customer VLAN Tag Type    |

## Internet Layer Protocols

 > described in [`src/protocols/internet`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#internet-layer-protocols-manual)

&emsp; `jspcap.protocols.internet` is collection of all protocols in internet layer, with detailed implementation and methods.

<a name="internet-macros"> </a>

### Macros

 - [`ETHERTYPE`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#ethertype) -- Ethertype IEEE 802 Numbers

<a name="internet-protocols"> </a>

### Protocols

|                                                NAME                                               |             DESCRIPTION             |
| :-----------------------------------------------------------------------------------------------: | :---------------------------------: |
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

## Transport Layer Protocols

 > described in [`src/protocols/transport`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/transport#transport-layer-protocols-manual)

&emsp; `jspcap.protocols.transport` is collection of all protocols in transport layer, with detailed implementation and methods.

<a name="transport-macros"> </a>

### Macros

 - [`TP_PROTO`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/transport#tp_proto) -- Transport Layer Protocol Numbers

<a name="transport-protocols"> </a>

### Protocols

|                                         NAME                                         |             DESCRIPTION             |
| :----------------------------------------------------------------------------------: | :---------------------------------: |
| [`TCP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/transport#tcp) |    Transmission Control Protocol    |
| [`UDP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/transport#udp) |       User Datagram Protocol        |


## Application Layer Protocols

 > described in [`src/protocols/application`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/application#application-layer-protocols-manual)

&emsp; `jspcap.protocols.application` is collection of all protocols in application layer, with detailed implementation and methods.

<a name="application-protocols"> </a>

### Protocols

|                                           NAME                                           |             DESCRIPTION             |
| :--------------------------------------------------------------------------------------: | :---------------------------------: |
| [`HTTP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/application#http) |     Hypertext Transfer Protocol     |

## TODO

 - [x] review docstrings
 - [ ] write documentation for `jspcap.protocols`
