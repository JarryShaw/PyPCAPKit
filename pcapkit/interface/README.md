# Interface Manual

&emsp; `pcapkit` is an open source library for PCAP extraction and analysis, written in __Python 3.6__. The following is a manual for interface usage.

 - [Macros](#macros)
    * [Formats](#formats)
    * [Layers](#layers)
    * [Engines](#engines)
 - [`extract`](#extract)
 - [`analyse`](#analyse)
 - [`reassemble`](#reassemble)
 - [`trace`](#trace)

---

## Macros

### Formats

 - `TREE` -- tree-view text output format
 - `JSON` -- JavaScript Object Notation (JSON) format
 - `PLIST` -- macOS Property List (PLIST) format
 - `PCAP` -- PCAP format

&emsp; There are four format macro variables defined in this part, as shown above. They indicate the output format of extraction operation, which should simplify the usage of [`extract`](#extract).

### Layers

 - `RAW` -- no specific layer
 - `LINK` -- data-link layer
 - `INET` -- internet layer
 - `TRANS` -- transport layer
 - `APP` -- application layer

&emsp; There are five layer macro variables defined in this part, as shown above. They indicate the maximum layer-depth of extraction operation, which should simplify the usage of [`extract`](#extract).

### Engines

 - `PCAPKit` -- the default engine
 - `MPServer` -- the multiprocessing engine with server process strategy
 - `MPPipeline` -- the multiprocessing engine with pipeline strategy
 - `DPKT` -- the [`DPKT`](https://github.com/kbandla/dpkt) engine
 - `Scapy` -- the [`Scapy`](https://scapy.net) engine
 - `PyShark` -- the [`PyShark`](https://kiminewt.github.io/pyshark/) engine

&emsp; There are six format macro variables defined in this part, as shown above. They indicate the engine of extraction operation, which should simplify the usage of [`extract`](#extract).

&nbsp;

## `extract`

```python
extract(*,
        fin=None, fout=None, format=None,                           # basic settings
        auto=True, extension=True, store=True,                      # internal settings
        files=False, nofile=False, verbose=False,                   # output settings
        engine=None, layer=None, protocol=None,                     # extraction settings
        ip=False, ipv4=False, ipv6=False, tcp=False, strict=False,  # reassembly settings
        trace=False, trace_fout=None, trace_format=None):           # trace settings
```

##### Extract a PCAP file.

 - Keyword arguments:

    | NAME           | TYPE   | DEFAULT | KEYWORD                                                         | DESCRIPTION                                             |
    | :------------- | :----- | :------ | :-------------------------------------------------------------- | :------------------------------------------------------ |
    | `fin`          | `str`  | `None`  |                                                                 | file name to be read; if file not exist, raise an error |
    | `fout`         | `str`  | `None`  |                                                                 | file name to be written                                 |
    | `format`       | `str`  | `None`  | `plist` / `json` / `tree` / `html`                              | file format of output                                   |
    | `store`        | `bool` | `True`  | `True` / `False`                                                | if store extracted packet info                          |
    | `verbose`      | `bool` | `False` | `True` / `False`                                                | if print verbose output information                     |
    | `auto`         | `bool` | `True`  | `True` / `False`                                                | if automatically run till EOF                           |
    | `extension`    | `bool` | `True`  | `True` / `False`                                                | if check and append extensions to output file           |
    | `files`        | `bool` | `False` | `True` / `False`                                                | if split each frame into different files                |
    | `nofile`       | `bool` | `False` | `True` / `False`                                                | if no output file is to be dumped                       |
    | `engine`       | `str`  | `None`  | `default` / `scapy` / `dpkt` / `pyshark` / `server` / `pipline` | extraction engine                                       |
    | `layer`        | `str`  | `None`  | `Link` / `Internet` / `Transport` / `Application`               | extract until layer                                     |
    | `protocol`     | `str`  | `None`  |                                                                 | extract until protocol                                  |
    | `ip`           | `bool` | `False` | `True` / `False`                                                | if perform IPv4 & IPv6 reassembly                       |
    | `ipv4`         | `bool` | `False` | `True` / `False`                                                | if perform IPv4 reassembly                              |
    | `ipv6`         | `bool` | `False` | `True` / `False`                                                | if perform IPv6 reassembly                              |
    | `tcp`          | `bool` | `False` | `True` / `False`                                                | if perform TCP reassembly                               |
    | `strict`       | `bool` | `False` | `True` / `False`                                                | if set strict flag for reassembly                       |
    | `trace`        | `bool` | `False` | `True` / `False`                                                | if trace TCP packet flows                               |
    | `trace_fout`   | `str`  | `None`  |                                                                 | root path for flow tracer                               |
    | `trace_format` | `str`  | `None`  | `plist` / `json` / `tree` / `html` / `pcap` / `None`            | output format of flow tracer                            |

 - Returns:
    * `Extractor` -- an Extractor object form [`pcapkit.foundation.extraction`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/foundation#extraction)

&nbsp;

## `analyse`

```python
analyse(*, file, length=None)
```

##### Analyse application layer packets.

 - Keyword arguments:
    * `file` -- file-like object, packet to be analysed
    * `length` -- `int`, length of the analysing packet

 - Returns:
    * `Analysis` -- an `Analysis` object from [`pcapkit.foundation.analysis`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/foundation#analysis)

&nbsp;

## `reassemble`

```python
reassemble(*, protocol, strict=False)
```

##### Reassemble fragmented datagrams.

 - Keyword arguments:

    | NAME       | TYPE   | DEFAULT | KEYWORD                 | DESCRIPTION                                                           |
    | :--------- | :----- | :------ | :---------------------- | :-------------------------------------------------------------------- |
    | `protocol` | `str`  |         | `IPv4` / `IPv6` / `TCP` | protocol to be reassembled                                            |
    | `strict`   | `bool` | `False` | `True` / `False`        | if return all datagrams (including those not implemented) when submit |

 - Returns:
    * *if protocol is IPv4* `IPv4_Reassembly` -- a `IPv4_Reassembly` object from [`pcapkit.reassembly.ipv4`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly#ipv4_reassembly)
    * *if protocol is IPv6* `IPv6_Reassembly` -- a` IPv6_Reassembly` object from [`pcapkit.reassembly.ipv6`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly#ipv6_reassembly)
    * *if protocol is TCP* `TCP_Reassembly` -- a `TCP_Reassembly` object from [`pcapkit.reassembly.tcp`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly#tcp_reassembly)

&nbsp;

## `trace`

```python
trace(*, fout=None, format=None)
```

##### Trace TCP flows.

 - Keyword arguments:
    * `fout` -- `str`, output path
    * `format` -- `str`, output format

 - Returns:
    * `TraceFlow` -- a [`TraceFlow`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/foundation#class-traceflow) object
