# ToolKit Manual

&emsp; `jspcap` is an open sourse library for PCAP extarction and analysis, written in __Python 3.6__. The following is a manual for function ToolKit usage. 

 - [Macros](#macros)
 - [`extract`](#extract)
 - [`analyse`](#analyse)
 - [`reassemble`](#reassemble)

---

## Macros

 - `TREE` -- tree-view text output format
 - `JSON` -- JavaScript Object Notation (JSON) format
 - `PLIST` -- macOS Property List (PLIST) format

&emsp; There are three macro variables defined in this part, as shown above. They indicate the output format of extraction operation, which should simplify the usage of [`extract`](#extract).

&nbsp;

## `extract`

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
    * `Extractor` -- an Extractor object form [`jspcap.fundations.extraction`](https://github.com/JarryShaw/jspcap/tree/master/src/fundations#extraction)

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
    * `Analysis` -- an [`Analysis`](https://github.com/JarryShaw/jspcap/tree/master/src/fundations#class-analysis) object from [`jspcap.fundations.analysis`](https://github.com/JarryShaw/jspcap/tree/master/src/fundations#analysis)

&nbsp;

## `reassemble`

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
    * *if protocol is IPv4* `IPv4_Reassembly` -- a Reassembly object from [`jspcap.reassembly.ipv4`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#reassembly-manual)
    * *if protocol is IPv6* `IPv6_Reassembly` -- a Reassembly object from [`jspcap.reassembly.ipv6`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#reassembly-manual)
    * *if protocol is TCP* `TCP_Reassembly` -- a Reassembly object from [`jspcap.reassembly.tcp`](https://github.com/JarryShaw/jspcap/tree/master/src/reassembly#reassembly-manual)
