# Foundation Manual

&emsp; `jspcap` is an open source library for PCAP extraction and analysis, written in __Python 3.6__. The following is a manual for fundamental tools in the library.

 - [Extraction](#extraction)
    * [Reference](https://github.com/JarryShaw/jspcap/tree/master/src/foundation/extraction.py)
    * [`Extractor`](#extractor)
 - [Analysis](#analysis)
    * [Reference](https://github.com/JarryShaw/jspcap/tree/master/src/foundation/analysis.py)
    * [`analyse`](#analyse)
    * [`Analysis`](#class-analysis)

---

## Extraction

 > described in [`src/foundation/extraction.py`](https://github.com/JarryShaw/jspcap/tree/master/src/foundation/extraction.py)

&emsp; `jspcap.foundation.extraction` contains `Extractor` only, which synthesises file I/O and protocol analysis, coordinates information exchange in all network layers, extract parameters from a PCAP file.

### `Extractor`

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
    * `trace` -- `tuple`, traced TCP packet flow index

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
    * initialisation takes numerous keyword arguments
        ```python
        __init__(self, *, fin=None, fout=None, format=None,                             # basic settings
                            auto=True, extension=True, store=True,                      # internal settings
                            files=False, nofile=False, verbose=False,                   # output settings
                            ip=False, ipv4=False, ipv6=False, tcp=False, strict=False,  # reassembly settings
                            trace=False, trace_fout=None, trace_format=None)            # trace settings
        ```
        |      NAME      |  TYPE  | DEFAULT |                       KEYWORD                        |                       DESCRIPTION                       |
        | :------------: | :----: | :-----: | :--------------------------------------------------: | :-----------------------------------------------------: |
        |     `fin`      | `str`  | `None`  |                                                      | file name to be read; if file not exist, raise an error |
        |     `fout`     | `str`  | `None`  |                                                      |                 file name to be written                 |
        |    `format`    | `str`  | `None`  |          `plist` / `json` / `tree` / `html`          |                  file format of output                  |
        |    `store`     | `bool` | `True`  |                   `True` / `False`                   |             if store extracted packet info              |
        |   `verbose`    | `bool` | `False` |                   `True` / `False`                   |           if print verbose output information           |
        |     `auto`     | `bool` | `True`  |                   `True` / `False`                   |              if automatically run till EOF              |
        |  `extension`   | `bool` | `True`  |                   `True` / `False`                   |      if check and append extensions to output file      |
        |    `files`     | `bool` | `False` |                   `True` / `False`                   |        if split each frame into different files         |
        |    `nofile`    | `bool` | `False` |                   `True` / `False`                   |            if no output file is to be dumped            |
        |      `ip`      | `bool` | `False` |                   `True` / `False`                   |            if perform IPv4 & IPv6 reassembly            |
        |     `ipv4`     | `bool` | `False` |                   `True` / `False`                   |               if perform IPv4 reassembly                |
        |     `ipv6`     | `bool` | `False` |                   `True` / `False`                   |               if perform IPv6 reassembly                |
        |     `tcp`      | `bool` | `False` |                   `True` / `False`                   |                if perform TCP reassembly                |
        |    `strict`    | `bool` | `False` |                   `True` / `False`                   |            if set strict flag for reassembly            |
        |    `trace`     | `bool` | `False` |                   `True` / `False`                   |                if trace TCP packet flows                |
        |  `trace_fout`  | `str`  | `None`  |                                                      |                root path for flow tracer                |
        | `trace_format` | `str`  | `None`  | `plist` / `json` / `tree` / `html` / `pcap` / `None` |              output format of flow tracer               |

&nbsp;

## Analysis

 > described in [`src/foundation/analysis.py`](https://github.com/JarryShaw/jspcap/tree/master/src/foundation/analysis.py)

&emsp; `jspcap.foundation.analysis` works as a header quarter to analyse and match application layer protocol. Then, call corresponding modules and functions to extract the attributes.

<a name="class-analysis"> </a>

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

 - Methods:
    * *`classmethod`* `analyse` -- analyse application layer packets
        ```python
        @classmethod
        analyse(cls, file, length=None)
        ```
        - Positional arguments:
           * `file` -- file-like object, packet to be analysed
           * `length` -- `int`, length of the analysing packet
        - Returns:
           * `Analysis` -- an [`Analysis`](#class-analysis) object from [`jspcap.foundation.analysis`](#analysis)
