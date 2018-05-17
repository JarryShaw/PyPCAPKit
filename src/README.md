# JSPCAP Manual

<!-- Current Progress: Utilities -->

&emsp; `jspcap` is an open sourse library for PCAP extarction and analysis, written in __Python 3.6__. The following is a manual for this library. Usage instructions and samples attached.

 - [Interface](#interface)
    * [Variables](#varaibales)
    * [`extract`](#extract)
    * [`analyse`](#analyse)
    * [`reassemble`](#reassemble)
 - [Extraction](#extraction)
    * [`Extractor`](#extractor)
 - [Analysis](#analysis)
    * [`analyse`](#func-analyse)
    * [`Analysis`](#class-analysis)
 - [Protocols](https://github.com/JarryShaw/jspcap/tree/master/src/protocols#protocols-manual)
    * [Macros](#macros)
    * [Protocols](#index-protocols)
 - [Reassembly](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#reassembly-manual)
    * [Reassembly](#index-reassembly)
 - [Utilities](#utilities)
    * [`seekset`](#seekset)
    * [`seekset_ng`](#seekset_ng)
    * [`beholder`](#beholder)
    * [`beholder_ng`](#beholder_ng)
    * [`Info`](#info)
    * [`VersionInfo`](#versioninfo)
    * [`ProtoChain`](#protochain)
 - [Validations](#validations)
 - [Exceptions](#exceptions)
 - [TODO](#todo)

---

## Intterface

 > described in [`src/interface.py`](https://github.com/JarryShaw/jspcap/tree/master/src/interface.py)

&emsp; Since `jspcap` has massive classes and numerous functions, `jspcap.interface` defines several user-oriented functions, variables, and etc. These interfaces are designed to help and simplify the usage of `jspcap`.

### Variables

 - `TREE` -- tree-view text output format
 - `JSON` -- JavaScript Object Notation (JSON) format
 - `PLIST` -- macOS Property List (PLIST) format

&emsp; There are three macro variables defined in this part, as shown above. They indicate the output format of extraction operation, which should simplify the usage of [`extract`](#extract).

### `extract`

##### Extract a PCAP file.

```python
extract(*, fin=None, fout=None, format=None, 
            store=True, files=False, nofile=False,
            auto=True, verbose=False, extension=True,
            ip=False, ipv4=False, ipv6=False, tcp=False, strict=False)
```

 - Keyword arguments:
    * `fin`  -- `str`, file name to be read; if file not exist, raise an error
    * `fout` -- `str`, file name to be written
    * `format`  -- `str`, file format of output
                    **KEYWORD** `plist` / `json` / `tree` / `html`

    * `store` -- `bool`, if store extracted packet info (default is `True`)
                    **KEYWORD** `True` / `False`
    * `verbose` -- `bool`, if print verbose output information (default is `False`)
                    **KEYWORD** `True` / `False`

    * `auto` -- `bool`, if automatically run till EOF (default is `True`)
                    **KEYWORD** `True` / `False`
    * `extension` -- `bool`, if check and append axtensions to output file (default is `True`)
                    **KEYWORD** `True` / `False`

    * `files` -- `bool`, if split each frame into different files (default is `False`)
                    **KEYWORD** `True` / `False`
    * `nofile` -- `bool`, if no output file is to be dumped (default is False)
                    **KEYWORD** `True` / `False`

    * `ip` -- `bool`, if record data for IPv4 & IPv6 reassembly (default is `False`)
                    **KEYWORD** `True` / `False`
    * `ipv4` -- `bool`, if record data for IPv4 reassembly (default is `False`)
                    **KEYWORD** `True` / `False`
    * `ipv6` -- `bool`, if record data for IPv6 reassembly (default is `False`)
                    **KEYWORD** `True` / `False`
    * `tcp` -- `bool`, if record data for TCP reassembly (default is `False`)
                     **KEYWORD** `True` / `False`

    * `strict` -- `bool`, if set strict flag for reassembly (default is `False`)
                    **KEYWORD** `True` / `False`

 - Returns:
    * `Extractor` -- an [`Extractor`](#extractor) object form [`jspcap.extractor`](#extraction)

<a name="analyse"> </a>

### `analyse`

##### Analyse application layer packets.

```python
analyse(*, file, length=None)
```

 - Keyword arguments:
    * `file` -- file-like object, packet to be analysed
    * `length` -- `int`, length of the analysing packet

 - Returns:
    * `Analysis` -- an [`Analysis`](#class-analysis) object from [`jspcap.analyser`](#analysis)

### `reassemble`

##### Reassemble fragmented datagrams.

```python
reassemble(*, protocol, strict=False)
```

 - Keyword arguments:
    * `protocol` -- `str`, protocol to be reassembled
    * `strict` -- `bool`, if return all datagrams (including those not implemented) when submit (default is `False`)
                    **KEYWORD** `True` / `False`

 - Returns:
    * *if protocol is IPv4* `IPv4_Reassembly` -- a Reassembly object from [`jspcap.reassembly`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#reassembly-manual)
    * *if protocol is IPv6* `IPv6_Reassembly` -- a Reassembly object from [`jspcap.reassembly`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#reassembly-manual)
    * *if protocol is TCP* `TCP_Reassembly` -- a Reassembly object from [`jspcap.reassembly`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#reassembly-manual)

&nbsp;

## Extraction

 > described in [`src/extractor.py`](https://github.com/JarryShaw/jspcap/tree/master/src/extractor.py)

&emsp; `jspcap.extractor` contains `Extractor` only, which synthesises file I/O and protocol analysis, coordinates information exchange in all network layers, extracst parametres from a PCAP file.

### `Extactor`

##### Extractor for PCAP files.

```python
class Extractor(builtins.object)
```

 - Properties:
    * `info` -- `VerionInfo`, version of input PCAP file
    * `length` -- `int`, frame number (of current extracted frame or all)
    * `format` -- `str`, format of output file
    * `input` -- `str`, name of input PCAP file
    * `output` -- `str` name of output file
    * `header` -- `Info`, extracted global header
    * `frames` -- `tuple<Info>`, extracted frames
    * `protocol` -- `ProtoChain`, protocol chain (of current/last frame)
    * `reassembly` -- `Info`, frame record for reassembly
        |--> `tcp` -- `tuple<TCP_Reassembly>`, TCP payload fragment reassembly
        |--> `ipv4` -- `tuple<IPv4_Reassembly>`, IPv4 frame fragment reassembly
        |--> `ipv6` -- `tuple<IPv6_Reassembly>`, IPv6 frame fragment reassembly

 - Methods:
    * *`classmethod`* `make_name` -- formatting input & output file name
        - Positional arguments:
            * `fin` -- `str`, input file
            * `fout` -- `str`, output file
            * `fmt` -- `str`, output format
            * `extension` -- `bool`, auto-complete extension flag
        - Keyword arguments:
            * `files` -- `bool`, flag if write a file per frame
            * `nofile` -- `bool`, disable output flag
        - Returns:
            * `str` -- input file name
            * `str` -- output file name
            * `str` -- output format name
            * `str` -- output file's extension
            * `files` -- flag if write a file per frame
    * `record_header` -- extract global header
    * `record_frames` -- extract frames

 - Data modules:
    * not hashable
    * iterable -- if only `auto` set `False`
    * callable -- if only `auto` set `False`
    * support `with` statement

&nbsp;

<a name="analysis"> </a>

## Analysis

 > described in [`src/analyser.py`](https://github.com/JarryShaw/jspcap/tree/master/src/analyser.py)

&emsp; `jspcap.analyser` works as a header quater to analyse and match application layer protocol. Then, call corresponding modules and functions to extract the attributes.

<a name="func-analyse"> </a>

### `analyse`

##### Analyse application layer packets.

```python
@beholder_ng
analyse(file, length=None)
```

 - Positional arguments:
    * `file` -- file-like object, packet to be analysed
    * `length` -- `int`, length of the analysing packet

 - Returns:
    * `Analysis` -- an [`Analysis`](#class-analysis) object from [`jspcap.analyser`](#analysis)

### `Analysis`

##### Analyse report.

```python
class Analysis(builtins.object)
```

 - Properties:
    * `info` -- `Info`, extracted packet
    * `name` -- `str`, protocol name
    * `alias` -- `str`, protocol alias
    * `protochain` -- `ProtoChain`, protocol chain of packet

&nbsp;

<a name="protocols"> </a> 

## Protocols

 > described in [`src/protocols`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols#protocols-manual)

##### Macros

|                                               NAME                                              |           DESCRIPTION            |
| :---------------------------------------------------------------------------------------------: | :------------------------------: |
| [`LINKTYPE`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#linktype)       |  Link-Layer Header Type Values   |
| [`ETHERTYPE`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#ethertype) |    Ethertype IEEE 802 Numbers    |
| [`TP_PROTO`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/transport#tp_proto)  | Transport Layer Protocol Numbers |

<a name="index-protocols"> </a> 

##### Protocols

|                                            NAME                                           |             DESCRIPTION             |
| :---------------------------------------------------------------------------------------: | :---------------------------------: |
| [`Header`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols#header)          |            Global Header            |
| [`Frame`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols#frame)            |            Frame Header             |
| [`ARP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#arp)           |     Address Resolution Protocol     |
| [`Ethernet`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#ethernet) |          Ethernet Protocol          |
| [`L2TP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#l2tp)         |    Layer Two Tunneling Protocol     |
| [`OSPF`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#ospf)         |      Open Shortest Path First       |
| [`RARP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#rarp)         | Reverse Address Resolution Protocol |
| [`AH`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#ah)         |        Athentication Header         |
| [`IP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#ip)         |          Internet Protocol          |
| [`IPX`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/internet#ipx)       |    Internetwork Packet Exchange     |
| [`TCP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/transport#tcp)      |    Transmission Control Protocol    |
| [`UDP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/transport#udp)      |       User Datagram Protocol        |
| [`HTTP`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/application#http)  |     Hypertext Transfer Protocol     |

&emsp; `jspcap.protocols` is collection of all protocol families, with detailed implementation and methods. Currently, it includes altogehter 22 different protocols and three macro variables.

&nbsp;

## Reassembly

 > described in [`src/reassembly`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#reassembly-manual)

<a name="index-reassembly"> </a>

##### Reassembly

|                                                 NAME                                                |   DESCRIPTION   |
| :-------------------------------------------------------------------------------------------------: | :-------------: |
| [`IPv4_Reassembly`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#ipv4_reassembly) | IPv4 Reassembly |
| [`IPv6_Reassembly`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#ipv6_reassembly) | IPv6 Reassembly |
| [`TCP_Reassembly`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols/link#arp)          | TCP Reassembly  |

&emsp; `jspcap.reassembly` bases on algorithms described in [`RFC 815`](https://tools.ietf.org/html/rfc815), implements datagram reassembly of IP and TCP packets. Currently, it supports reassembly of only 3 different protocols.

&nbsp;

## Utilities


