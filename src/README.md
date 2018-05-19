# JSPCAP Manual

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
    * [`BaseError`](#baseerror)
    * [Refined Exceptions](#refined-exceptions)
 - [TODO](#todo)

---

## Interface

 > described in [`src/interface.py`](https://github.com/JarryShaw/jspcap/tree/master/src/interface.py)

&emsp; Since `jspcap` has massive classes and numerous functions, `jspcap.interface` defines several user-oriented functions, variables, and etc. These interfaces are designed to help and simplify the usage of `jspcap`.

### Variables

 - `TREE` -- tree-view text output format
 - `JSON` -- JavaScript Object Notation (JSON) format
 - `PLIST` -- macOS Property List (PLIST) format

&emsp; There are three macro variables defined in this part, as shown above. They indicate the output format of extraction operation, which should simplify the usage of [`extract`](#extract).

### `extract`

```python
extract(*, fin=None, fout=None, format=None, 
            store=True, files=False, nofile=False,
            auto=True, verbose=False, extension=True,
            ip=False, ipv4=False, ipv6=False, tcp=False, strict=False)
```

##### Extract a PCAP file.

 - Keyword arguments:

    |    NAME     |  TYPE  | DEFAULT |              KEYWORD               |                       DESCRIPTION                       |
    | :---------: | :----: | :-----: | :--------------------------------: | :-----------------------------------------------------: |
    |    `fin`    | `str`  | `None`  |                                    | file name to be read; if file not exist, raise an error |
    |   `fout`    | `str`  | `None`  |                                    |                 file name to be written                 |
    |  `format`   | `str`  | `None`  | `plist` / `json` / `tree` / `html` |                  file format of output                  |
    |   `store`   | `bool` | `True`  |          `True` / `False`          |             if store extracted packet info              |
    |  `verbose`  | `bool` | `False` |          `True` / `False`          |           if print verbose output information           |
    |   `auto`    | `bool` | `True`  |          `True` / `False`          |              if automatically run till EOF              |
    | `extension` | `bool` | `True`  |          `True` / `False`          |      if check and append axtensions to output file      |
    |   `files`   | `bool` | `False` |          `True` / `False`          |        if split each frame into different files         |
    |  `nofile`   | `bool` | `False` |          `True` / `False`          |            if no output file is to be dumped            |
    |    `ip`     | `bool` | `False` |          `True` / `False`          |            if perform IPv4 & IPv6 reassembly            |
    |   `ipv4`    | `bool` | `False` |          `True` / `False`          |               if perform IPv4 reassembly                |
    |   `ipv6`    | `bool` | `False` |          `True` / `False`          |               if perform IPv6 reassembly                |
    |    `tcp`    | `bool` | `False` |          `True` / `False`          |                if perform TCP reassembly                |
    |  `strict`   | `bool` | `False` |          `True` / `False`          |            if set strict flag for reassembly            |

 - Returns:
    * `Extractor` -- an [`Extractor`](#extractor) object form [`jspcap.extractor`](#extraction)

<a name="analyse"> </a>

### `analyse`

```python
analyse(*, file, length=None)
```

##### Analyse application layer packets.

 - Keyword arguments:
    * `file` -- file-like object, packet to be analysed
    * `length` -- `int`, length of the analysing packet

 - Returns:
    * `Analysis` -- an [`Analysis`](#class-analysis) object from [`jspcap.analyser`](#analysis)

### `reassemble`

```python
reassemble(*, protocol, strict=False)
```

##### Reassemble fragmented datagrams.

 - Keyword arguments:

    |    NAME    |  TYPE  | DEFAULT |         KEYWORD         |                         DESCRIPTION                                   |
    | :--------: | :----: | :-----: | :---------------------: | :-------------------------------------------------------------------: |
    | `protocol` | `str`  |         | `IPv4` / `IPv6` / `TCP` |                  protocol to be reassembled                           |
    |  `strict`  | `bool` | `False` |    `True` / `False`     | if return all datagrams (including those not implemented) when submit |

 - Returns:
    * *if protocol is IPv4* `IPv4_Reassembly` -- a Reassembly object from [`jspcap.reassembly`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#reassembly-manual)
    * *if protocol is IPv6* `IPv6_Reassembly` -- a Reassembly object from [`jspcap.reassembly`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#reassembly-manual)
    * *if protocol is TCP* `TCP_Reassembly` -- a Reassembly object from [`jspcap.reassembly`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#reassembly-manual)

&nbsp;

## Extraction

 > described in [`src/extractor.py`](https://github.com/JarryShaw/jspcap/tree/master/src/extractor.py)

&emsp; `jspcap.extractor` contains `Extractor` only, which synthesises file I/O and protocol analysis, coordinates information exchange in all network layers, extracst parametres from a PCAP file.

### `Extactor`

```python
class Extractor(builtins.object)
```

##### Extractor for PCAP files.

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
        - `tcp` -- `tuple<TCP_Reassembly>`, TCP payload fragment reassembly
        - `ipv4` -- `tuple<IPv4_Reassembly>`, IPv4 frame fragment reassembly
        - `ipv6` -- `tuple<IPv6_Reassembly>`, IPv6 frame fragment reassembly

 - Methods:
    * *`classmethod`* `make_name` -- formatting input & output file name
        ```python
        @classmethod
        make_name(cls, fin, fout, fmt, extension, *, files, nofile)
        ```
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
    * initialisation takes numerous keyword arguments as decribed in [`jspcap.extract`](#extract)

&nbsp;

<a name="analysis"> </a>

## Analysis

 > described in [`src/analyser.py`](https://github.com/JarryShaw/jspcap/tree/master/src/analyser.py)

&emsp; `jspcap.analyser` works as a header quater to analyse and match application layer protocol. Then, call corresponding modules and functions to extract the attributes.

<a name="func-analyse"> </a>

### `analyse`

```python
@beholder_ng
analyse(file, length=None)
```

##### Analyse application layer packets.

 - Positional arguments:
    * `file` -- file-like object, packet to be analysed
    * `length` -- `int`, length of the analysing packet

 - Returns:
    * `Analysis` -- an [`Analysis`](#class-analysis) object from [`jspcap.analyser`](#analysis)

### `Analysis`

```python
class Analysis(builtins.object)
```

##### Analyse report.

 - Properties:
    * `info` -- `Info`, extracted packet
    * `name` -- `str`, protocol name
    * `alias` -- `str`, protocol alias
    * `protochain` -- `ProtoChain`, protocol chain of packet

&nbsp;

<a name="protocols"> </a> 

## Protocols

 > described in [`src/protocols`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols#protocols-manual)

&emsp; `jspcap.protocols` is collection of all protocol families, with detailed implementation and methods. Currently, it includes altogehter 22 different protocols and three macro variables.

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
| [`Header`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols#header)                  |            Global Header            |
| [`Frame`](https://github.com/JarryShaw/jspcap/tree/master/src/protocols#frame)                    |            Frame Header             |
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

## Utilities

 > described in [`src/utilities.py`](https://github.com/JarryShaw/jspcap/tree/master/src/utilities.py)

### `seekset`

```python
def seekset(func):
    def seekcur(self, *args, **kw):
        ...
        return func(self, *args, **kw)
    return seekcur
```

##### Read file from start then set back to original.

__NOTE__: this decorator works with class methods, which has a *file-like* attribute names `self._file`.

### `seekset_ng`

```python
def seekset_ng(func):
    def seekcur(file, *args, **kw):
        ...
        return func(file, *args, **kw)
    return seekcur
```

##### Read file from start then set back to original.

__NOTE__: positional argument `file` in `seekcur` must be a *file-like* object.

### `beholder`

```python
def beholder(func):
    def behold(self, proto, length, *args, **kwargs):
        ...
        return func(self, proto, length, *args, **kwargs)
    return behold
```

##### Behold extraction procedure.

__NOTE__: this decorator works with class method `self._import_next_layer`, which has a *file-like* attribute names `self._file`.

### `beholder_ng`

```python
def beholder_ng(func):
    def behold(file, length, *args, **kwargs):
        ...
        return func(file, length, *args, **kwargs)
    return behold
```

##### Behold extraction procedure.

__NOTE__: positional argument `file` in `behold` must be a *file-like* object.

### `Info`

```python
class Info(builtins.dict)
```

##### Turn dictionaries into object-like instances.

 - Properties:
    * indicated as `Info` initialisation procedure

 - Methods:
    * `infotodict` -- reverse `Info` object into `dict` type
    * all other methods inherited from `dict`

 - Data modules:
    * **immutable** -- cannot delete or set value of a key
    * any other data modules inherited from `dict`

 - Notes:
    * `Info` objects inherit from `dict` type
    * `Info` objects are iterable, and support all functions as `dict`
    * `Info` objects are one-time-modeling, thus cannot set or delete attributes after initialisation

### `VersionInfo`

```python
class VersionInfo(builtins.object)
```

##### VersionInfo alikes `sys.version_info`.

 - Properties:
    * `major` -- `int`, major version
    * `minor` -- `int`, minor version

 - Data modules:
    * immutable
    * subscriptable

### `ProtoChain`

```python
class ProtoChain(builtins.object)
```

##### Protocols chain.

 - Properties:
    * `alias` -- `tuple`, aliases of protocols in chain
    * `tuple` -- `tuple`, name of protocols in chain
    * `proto` -- `tuple`, lowercase name of protocols in chain
    * `chain` -- `str`, chain of protocols seperated by colons

 - Methods:
    * `index` -- same as `index` function of `tuple` type

 - Data modules:
    * iterable
    * subscriptable

&nbsp;

## Validations

 > described in [`src/validations.py`](https://github.com/JarryShaw/jspcap/tree/master/src/validations.py)

&emsp; `jspcap.validations` contains functions to validate arguments for functions and classes. It first appears in
[`jsntlib`](https://github.com/JarryShaw/jsntlib) as validators.

##### Validators

```python
type_check(*agrs, func=None)
```

|       NAME        |                 DESCRIPTION                 |
| :---------------: | :-----------------------------------------: |
|    `int_check`    |      Check if arguments are integrals.      |
|   `real_check`    |    Check if arguments are real numbers.     |
|  `complex_check`  |   Check if arguments are complex numbers.   |
|  `number_check`   |       Check if arguments are numbers.       |
|   `bytes_check`   |    Check if arguments are `bytes` type.     |
| `bytearray_check` |  Check if arguments are `bytearray` type.   |
|    `str_check`    |     Check if arguments are `str` type.      |
|   `bool_check`    |    Check if arguments are `bytes` type.     |
|   `list_check`    |     Check if arguments are `list` type.     |
|   `tuple_check`   |    Check if arguments are `tuple` type.     |
|    `io_check`     |  Check if arguments are *file-like* type.   |
|   `frag_check`    |   Check if arguments are valid fragments.   |
| `_ip_frag_check`  | Check if arguments are valid IP fragments.  |
| `_tcp_frag_check` | Check if arguments are valid TCP fragments. |

&emsp; __EXCEPT__ `frag_check`, all validators take arbitrary positional arguments with one keyword argument named `func`, which takes a `str` type indicates the caller function of validation procedure.

##### Nota Bene

```python
frag_check(*args, protocol, func=None)
_ip_frag_check(*args, func=None)
_tcp_frag_check(*args, func=None)
```

&emsp; As for `frag_check`, `str` type keyword argument `protocol` indicats what protocol the fragment is reassembled for, which must be either `IP` (`IPv4` & `IPv6`) or `TCP`. Then, `_ip_frag_check` or `_tcp_frag_check` shall be called to validate arguments caller passed into. For more infomation on fragment format, please refer to the documentation of [`IP_Reassembly`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#ip_reassembly) and [`TCP_Reassembly`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#tcp_reassembly).

&nbsp;

## Exceptions

 > described in [`src/exceptions.py`](https://github.com/JarryShaw/jspcap/tree/master/src/exceptions.py)

&emsp; `jspcap.exceptions` refined built-in exceptions. Make it possible to show only user error stack infomation, when exception raised on user's operation.

### `BaseError`

```python
class BaseError(builtins.Exception)
```

##### Base error class of all kinds.

 - Data modules:
    * initialisation takes a special keyword argument `quiet` of `bool` type, referring if print no traceback information when exception raised
    * all other data modules inherited from `Exception`

 - Notes:

    * Turn off system-default traceback function by set `sys.tracebacklimit` to 0.

    * But bugs appear in Python 3.6, so we have to set `sys.tracebacklimit` to None.

        > this note is deprecated since Python fixed the problem above

    * In Python 2.7, `trace.print_stack(limit=None)` dose not support negative limit.

### Refined Exceptions

```python
class error(jspcap.exceptions.BaseError, builtins.Exception)
```

|        NAME        |            INHERIT FROM            |                     DESCRIPTION                     |
| :----------------: | :--------------------------------: | :-------------------------------------------------: |
|    `DigitError`    |     `BaseError` / `TypeError`      |       The argument(s) must be (a) number(s).        |
|     `IntError`     |     `BaseError` / `TypeError`      |          The argument(s) must be integral.          |
|    `RealError`     |     `BaseError` / `TypeError`      |    The function is not defined for real number.     |
|   `ComplexError`   |     `BaseError` / `TypeError`      | The function is not defined for `complex` instance. |
|    `BytesError`    |     `BaseError` / `TypeError`      |        The argument(s) must be `bytes` type.        |
|  `BytearrayError`  |     `BaseError` / `TypeError`      |      The argument(s) must be `bytearray` type.      |
|    `BoolError`     |     `BaseError` / `TypeError`      |        The argument(s) must be `bool` type.         |
|   `StringError`    |     `BaseError` / `TypeError`      |         The argument(s) must be `str` type.         |
|    `DictError`     |     `BaseError` / `TypeError`      |        The argument(s) must be `dict` type.         |
|    `ListError`     |     `BaseError` / `TypeError`      |        The argument(s) must be `list` type.         |
|    `TupleError`    |     `BaseError` / `TypeError`      |        The argument(s) must be `tuple` type.        |
|  `IterableError`   |     `BaseError` / `TypeError`      |          The argument(s) must be iterable.          |
|  `CallableError`   |     `BaseError` / `TypeError`      |          The argument(s) must be callable.          |
| `ProtocolUnbound`  |     `BaseError` / `TypeError`      |               Protocol slice unbound.               |
|    `IOObjError`    |     `BaseError` / `TypeError`      |      The argument(s) must be *file-like* type.      |
|   `FormatError`    |   `BaseError` / `AttributeError`   |                  Unknow format(s).                  |
| `UnsupportedCall`  |   `BaseError` / `AttributeError`   |       Unsupported function or property call.        |
|    `FileError`     |      `BaseError` / `IOError`       |                 Wrong file format.                  |
|   `FileNotFound`   | `BaseError` /  `FileNotFoundError` |                   File not found.                   |
| `ProtocolNotFound` |     `BaseError` / `IndexError`     |         Protocol not found in `ProtoChain`.         |
|   `VersionError`   |     `BaseError` / `ValueError`     |                 Unknown IP version.                 |
|  `IndexNotFound`   |     `BaseError` / `ValueError`     |            Protocol not in `ProtoChain`.            |
|  `ProtocolError`   |     `BaseError` / `ValueError`     |              Invalid protocol format.               |
|   `StructError`    |    `BaseError` / `struct.error`    |                   Unpack failed.                    |
|  `FragmentError`   |      `BaseError` / `KeyError`      |               Invalid fragment dict.                |

&nbsp;

## TODO

 - [x] interface verbs
 - [x] review docstrings
 - [ ] write documentation for `jspcap`
 - [ ] implement IP and MAC address containers
