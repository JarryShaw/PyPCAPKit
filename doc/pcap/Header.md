---
Layer: PCAP File

Acronym: Header

Reference: [Libpcap File Format](https://wiki.wireshark.org/Development/LibpcapFileFormat#Global_Header)
---

&nbsp;

# PCAP Global Header

## Description

&emsp; This header starts the `libpcap` file and will be followed by the first packet header:

 - `magic_number`: used to detect the file format itself and the byte ordering.
 - `version_major`, `version_minor`: the version number of this file format (current version is 2.4)
 - `thiszone`: the correction time in seconds between GMT (UTC) and the local timezone of the following packet header timestamps.
 - `sigfigs`: in theory, the accuracy of time stamps in the capture; in practice, all tools set it to 0
 - `snaplen`: the "snapshot length" for the capture (typically 65535 or even more, but might be limited by the user), see: incl_len vs. orig_len below
 - `network`: link-layer header type, specifying the type of headers at the beginning of the packet; this can be various types such as 802.11, 802.11 with various radio information, PPP, Token Ring, FDDI, etc.

&nbsp;

## Format

```c
typedef struct pcap_hdr_s {
    guint32 magic_number;   /\* magic number \*/
    guint16 version_major;  /\* major version number \*/
    guint16 version_minor;  /\* minor version number \*/
    gint32  thiszone;       /\* GMT to local correction \*/
    guint32 sigfigs;        /\* accuracy of timestamps \*/
    guint32 snaplen;        /\* max length of captured packets, in octets \*/
    guint32 network;        /\* data link type \*/
} pcap_hdr_t;
```

&nbsp;

## Extraction

 > described in [`src/protocols/pcap/header.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/pcap/header.py)

```python
class Header(file=None, *args, **kwargs)
```

 > PCAP file global header extractor.

### Resolution Order

 1. `builtins.object`
 2. `pcapkit.protocols.protocol.Protocol`
 3. `pcapkit.protocols.pcap.header.Header`

### Data Format

```
(Info) Header
 |-- (Info) magic_number -> magic number
 |      |-- (bytes) data -> raw magic number
 |      |-- (str) byteorder -> header byte order
 |      |-- (bool) nanosecond -> nanosecond-resolution file flag
 |-- (int) version_major -> major version number
 |-- (int) version_minor -> minor version number
 |-- (int) thiszone --> GMT to local correction
 |-- (int) sigfigs --> accuracy of timestamps
 |-- (int) snaplen --> max length of captured packets, in octets
 |-- (LinkType) network --> data link type
```

### Initialisation

 - Positional arguments:
    * `file` -- *file-like* object, packet file to be extracted

### Properties

| NAME         | TYPE                                  | DESCRIPTION                       | POSSIBLE VALUES      |
| :----------- | :------------------------------------ | :-------------------------------- | :------------------- |
| `name`       | `str`                                 | name of corresponding protocol    | `'Global Header'`    |
| `info`       | `pcapkit.corekit.infoclass.Info`      | info dict of current instance     |                      |
| `alias`      | `str`                                 | acronym of corresponding protocol | `'Header'`           |
| `length`     | `int`                                 | header length of global header    | `24`                 |
| `version`    | `pcapkit.corekit.version.VersionInfo` | version information of PCAP file  |                      |
| `protocol`   | `pcapkit._common.linktype.LinkType`   | data link type                    |                      |
| `byteorder`  | `str`                                 | header byte order                 | `'little'` / `'big'` |
| `nanosecond` | `bool`                                | nanosecond-resolution flag        | `True` / `False`     |

### Methods

#### Decode `bytes` into `str`

```python
@staticmethod Header.decode(byte, *, encoding=None, errors='strict')
```

 > cf. [`pcapkit.protocols.protocol.Protocol`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#protocol)

 - Positional arguments:
    * `byte` -- `bytes`, byte string to be decoded

 - Keyword arguments:
    * `encoding` -- `str`, the encoding with which to decode the bytes
    * `error` -- `str`, the error handling scheme to use for the handling of decoding errors

 - Returns:
    * `str` -- decoded string

#### Unquote URLs into Unicode

```python
@staticmethod Header.unquote(url, *, encoding='utf-8', errors='replace')
```

 > cf. [`pcapkit.protocols.protocol.Protocol`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#protocol)

 - Positional arguments:
    * `url` -- `str`, URL to be unquoted

 - Keyword arguments:
    * `encoding` -- `str`, the encoding with which to decode the bytes
    * `error` -- `str`, the error handling scheme to use for the handling of decoding errors

 - Returns:
    * `str` -- unquoted URL

&nbsp;

## Construction

 > described in [`src/ipsuite/pcap/header.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/ipsuite/pcap/header.py)

```python
class Header(args={}, **kwargs)
```

 > PCAP global header constructor.

### Resolution Order

 1. `builtins.object`
 2. `pcapkit.ipsuite.protocol.Protocol`
 3. `pcapkit.ipsuite.pcap.header.Header`

### Initialisation

 - Positional arguments:
    * `args` -- *`dict`-like* object (default: `{}`)

 - Keyword arguments:
    | NAME                | TYPE                                                                 | DESCRIPTION                               | DEFAULT VALUE                                   | POSSIBLE VALUES      |
    | :------------------ | :------------------------------------------------------------------- | :---------------------------------------- | :---------------------------------------------- | :------------------- |
    | `byteorder`         | `str`                                                                | header byte order                         | _depends on platform_                           | `'little'` / `'big'` |
    | `lilendian`         | `bool`                                                               | little-endian flag                        | _depends on platform_                           | `True` / `False`     |
    | `bigendian`         | `bool`                                                               | big-endian flag                           | _depends on platform_                           | `True` / `False`     |
    | `nanosecond`        | `bool`                                                               | nanosecond-resolution file flag           | `False`                                         | `True` / `False`     |
    | `version`           | `tuple<int>`                                                         | version information                       | `(2, 4)`                                        |                      |
    | `version_major`     | `int`                                                                | major version number                      | `2`                                             |                      |
    | `version_minor`     | `int`                                                                | minor version number                      | `4`                                             |                      |
    | `thiszone`          | `int`                                                                | GMT to local correction                   | `0`                                             |                      |
    | `sigfigs`           | `int`                                                                | accuracy of timestamps                    | `0`                                             |                      |
    | `snaplen`           | `int`                                                                | max length of captured packets, in octets | `262144`                                        |                      |
    | `network`           | `pcapkit._common.linktype.LinkType` / `enum.IntEnum` / `str` / `int` | data link type                            | `pcapkit.protocols.link.link.LINKTYPE.DLT_NULL` |                      |
    | `network_default`   | `int`                                                                | default value for unknown data link type  |                                                 |                      |
    | `network_namespace` | `pcapkit._common.linktype.LinkType` / `enum.IntEnum` / `str` / `int` | data link type namespace                  | `pcapkit.protocols.link.link.LINKTYPE`          |                      |
    | `network_reversed`  | `bool`                                                               | if namespace is `dict<str: int>` pairs    | `False`                                         | `True` / `False`     |

### Properties

| NAME    | TYPE                             | DESCRIPTION                            | POSSIBLE VALUES   |
| :------ | :------------------------------- | :------------------------------------- | :---------------- |
| `name`  | `str`                            | name of corresponding protocol         | `'Global Header'` |
| `info`  | `pcapkit.corekit.infoclass.Info` | info dict of current instance          |                   |
| `data`  | `bytes`                          | binary packet data if current instance |                   |
| `alias` | `str`                            | acronym of corresponding protocol      | `'Header'`        |

### Methods

#### Indexing from Enumerations

```python
@classmethod Header.index(name, default=None, *, namespace=None, reversed=False, pack=False, size=4, signed=False, lilendian=False)
```

 > Return first index of name from a dict or enumeration.

 - Positional arguments:
    * `name` -- `str` / `int` / `enum.IntEnum`, item to be indexed
    * `default` -- `int`, default value

 - Keyword arguments:
    * `namespace` -- `dict` / `enum.EnumMeta`, namespace for `name`
    * `reversed` -- `bool`, if `namespace` is `dict<str: int>` pairs
    * `pack` -- `bool`, if need `struct.pack`
    * `size` -- `int`, buffer size
    * `signed` -- `bool`, signed flag
    * `lilendian` -- `bool`, little-endian flag

 - Returns:
    * *if `pack` is `True`* `bytes` -- packed index
    * *if `pack` is `False`* `int` -- index of `name` from `namespace`

 - May raise:
    * `pcapkit.utilities.exceptions.ProtocolNotImplemented` -- when `name` is unknown in `namespace` and `default` is `None`
    * `pcapkit.utilities.exceptions.StructError` -- when `pack` is `True` and packing procedure failed
    * any other builtin exceptions raised by the programs itself

#### Packing `int` to `bytes`

```python
@staticmethod Header.pack(integer, *, size=1, signed=False, lilendian=False)
```

 > Pack integers to bytes.

 - Positional arguments:
    * `integer` -- `int`, integer to be packed

 - Keyword arguments:
    * `size` -- `int`, buffer size
    * `signed` -- `bool`, signed flag
    * `lilendian` -- `bool`, little-endian flag

 - Returns:
    * `bytes` -- packed integer

 - May raise:
   * `pcapkit.utilities.exceptions.StructError` -- when `pack` is `True` and packing procedure failed
   * any other builtin exceptions raised by the programs itself
