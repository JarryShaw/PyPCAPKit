# PCAP Headers Manual

&emsp;

 - [`Header`](#header)
 - [`Frame`](#frame)

---

## `Header`

 > described in [`src/protocols/pcap/header.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/pcap/header.py)

&emsp; `pcapkit.protocols.pcap.header` contains `Header` only, which implements extractor for global headers of PCAP.

```python
class Header(pcapkit.protocols.protocol.Protocol)
```

##### PCAP file global header extractor.

 - Properties:
    * `name` -- `str`, name of corresponding protocol (`'Global Header'`)
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
    * `alias` -- `str`, acronym of corresponding protocol (`'Header'`)
    * `length` -- `int`, header length of global header, (`24`)
    * `version` -- `VersionInfo`, version infomation of input PCAP file
    * `protocol` -- `str`, data link type

 - Methods:
    * `decode_bytes` -- try to decode `bytes` into `str` (cf. [`pcapkit.protocols.protocol.Protocol`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#protocol))
    * `decode_url` -- decode URLs into Unicode (cf. [`pcapkit.protocols.protocol.Protocol`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#protocol))
    * `index` -- call [`ProtoChain.index`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit#protochain)
    * `read_header` -- read global header of PCAP file

 - Data modules:
    * initilisation procedure shows as below
        ```python
        __init__(self, file)
        ```
        - Positional arguments:
            * `file` -- *file-like* object, packet file to be extracted
    * all other data modules inherited from [`Protocol`](#protocol)

&nbsp;

## `Frame`

 > described in [`src/protocols/pcap/frame.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/pcap/frame.py)

&emsp; `pcapkit.protocols.pcap.frame` contains `Frame` only, which implements extractor for frame headers of PCAP.

```python
class Frame(pcapkit.protocols.protocol.Protocol)
```

##### Per packet frame header extractor.

 - Properties:
    * `name` -- `str`, name of corresponding protocol
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
    * `alias` -- `str`, acronym of corresponding protocol (`'Frame'`)
    * `length` -- `int`, header length of global header, (`16`)
    * `protocol` -- `str`, data link type
    * `protochain` -- `ProtoChain`, protocol chain of current frame

 - Methods:
    * `decode_bytes` -- try to decode `bytes` into `str` (cf. [`pcapkit.protocols.protocol.Protocol`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#protocol))
    * `decode_url` -- decode URLs into Unicode (cf. [`pcapkit.protocols.protocol.Protocol`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#protocol))
    * `index` -- call [`ProtoChain.index`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit#protochain)
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
