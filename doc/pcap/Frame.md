---
Layer: PCAP File

Acronym: Frame

Reference: [Libpcap File Format](https://wiki.wireshark.org/Development/LibpcapFileFormat#Record_.28Packet.29_Header)
---

# PCAP Frame Header

## Description

&nbsp;

## Format

```c
typedef struct pcaprec_hdr_s {
    guint32 ts_sec;     /\* timestamp seconds \*/
    guint32 ts_usec;    /\* timestamp microseconds \*/
    guint32 incl_len;   /\* number of octets of packet saved in file \*/
    guint32 orig_len;   /\* actual length of packet \*/
} pcaprec_hdr_t;
```

&nbsp;

## Extraction

 > described in [`src/protocols/pcap/frame.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/pcap/frame.py)

```python
class Frame(file, *, num, proto, nanosecond, **kwrags)
```

 > Per packet frame header extractor.

### Resolution Order

  1. `builtins.object`
  2. `pcapkit.protocols.protocol.Protocol`
  3. `pcapkit.protocols.misc.pcap.frame.Frame`

### Data Format

```
(Info) Frame
    |-- (Info) frame_info -> original frame header
    |      |-- (int) ts_sec -> timestamp seconds
    |      |-- (int) ts_usec -> timestamp microseconds
    |      |-- (int) incl_len -> number of octets of packet saved in file
    |      |-- (int) orig_len -> actual length of packet
    |-- (datetime) time -> timestamp
    |-- (int) number -> frame number
    |-- (str) time_epoch -> time since Unix epoch
    |-- (int) len -> number of octets of packet saved in file
    |-- (int) cap_len -> actual length of packet
```

### Initialisation

 - Positional arguments:
    * `file` -- *file-like* object, packet file to be extracted

 - Keyword arguments:
    * `num` -- `int`, frame number
    * `proto` -- `str`, data link type from [`Header`](https://github.com/JarryShaw/PyPCAPKit/tree/master/doc/pcap/Header.md#data-format)
    * `nanosecond` -- `bool`, nanosecond-resolution file flag from [`Header`](https://github.com/JarryShaw/PyPCAPKit/tree/master/doc/pcap/Header.md#data-format)
    * *multiprocessing only* `mpfdp` -- `multiprocessing.queues.Queue<int>`, file descriptor pointer
    * *multiprocessing only* `mpkit` -- `multiprocessing.managers.NamespaceProxy`, multiprocessing work kit

### Properties

| NAME         | TYPE                                    | DESCRIPTION                        | POSSIBLE VALUES  |
| :----------- | :-------------------------------------- | :--------------------------------- | :--------------- |
| `name`       | `str`                                   | name of corresponding protocol     | `'Frame Header'` |
| `info`       | `pcapkit.corekit.infoclass.Info`        | info dict of current instance      |                  |
| `alias`      | `str`                                   | acronym of corresponding protocol  | `'Frame'`        |
| `length`     | `int`                                   | header length of global header     | `16`             |
| `payload`    | `pcapkit.protocols.protocol.Protocol`   | payload of current instance        |                  |
| `protocol`   | `pcapkit._common.linktype.LinkType`     | name of next layer protocol        |                  |
| `protochain` | `pcapkit.corekit.protochain.ProtoChain` | protocol chain of current instance |                  |

### Methods

#### Decode `bytes` into `str`

```python
@staticmethod Frame.decode(byte, *, encoding=None, errors='strict')
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
@staticmethod Frame.unquote(url, *, encoding='utf-8', errors='replace')
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

 > described in [`src/ipsuite/pcap/frame.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/ipsuite/pcap/frame.py)

```python
class Frame(args, **kwargs)
```

> PCAP frame header constructor.

### Resolution Order

 1. `builtins.object`
 2. `pcapkit.ipsuite.protocol.Protocol`
 3. `pcapkit.ipsuite.pcap.frame.Frame`

### Initialisation

- Positional arguments:
   * `args` -- *`dict`-like* object (default: `{}`)

- Keyword arguments:
    | NAME         | TYPE    | DESCRIPTION                              | DEFAULT VALUE      | POSSIBLE VALUES  |
    | :----------- | :------ | :--------------------------------------- | :----------------- | :--------------- |
    | `timestamp`  | `float` | UNIX-Epoch timestamp                     | _time at run_      |                  |
    | `ts_sec`     | `int`   | timestamp seconds                        | _time at run_      |                  |
    | `ts_usec`    | `int`   | timestamp microseconds                   | _time at run_      |                  |
    | `incl_len`   | `int`   | number of octets of packet saved in file | length of `packet` |                  |
    | `orig_len`   | `int`   | actual length of packet                  | length of `packet` |                  |
    | `packet`     | `bytes` | raw packet data                          | `b''`              |                  |
    | `nanosecond` | `bool`  | nanosecond-resolution file flag          | `False`            | `True` / `False` |

### Properties

| NAME    | TYPE                             | DESCRIPTION                            | POSSIBLE VALUES  |
| :------ | :------------------------------- | :------------------------------------- | :--------------- |
| `name`  | `str`                            | name of corresponding protocol         | `'Frame Header'` |
| `info`  | `pcapkit.corekit.infoclass.Info` | info dict of current instance          |                  |
| `data`  | `bytes`                          | binary packet data if current instance |                  |
| `alias` | `str`                            | acronym of corresponding protocol      | `'Frame'`        |

### Methods

#### Indexing from Enumerations

```python
@classmethod Frame.index(name, default=None, *, namespace=None, reversed=False, pack=False, size=4, signed=False, lilendian=False)
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
@staticmethod Frame.pack(integer, *, size=1, signed=False, lilendian=False)
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
