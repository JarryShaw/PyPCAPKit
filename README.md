# PyPCAPKit

> For any technical and/or maintenance information, please kindly refer to the [**Official Documentation**](https://pypcapkit.jarryshaw.me).

<!-- reconstruct Frame, each protocol instance should be stored within the Frame instance; IPv6 pending more consideration -->

&emsp; The `pcapkit` project is an open source Python program focus on [PCAP](https://en.wikipedia.org/wiki/Pcap) parsing and analysis, which works as a stream PCAP file extractor. With support of [`dictdumper`](https://github.com/JarryShaw/dictdumper), it shall support multiple output report formats.

 > Note that the whole project supports __Python 3.4__ or later.

 - [About](#about)
    * [Module Structure](#module-structure)
        - [Interface](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#interface-manual)
        - [Foundation](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/foundation#foundation-manual)
        - [Reassembly](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly#reassembly-manual)
        - [IPSuite](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/ipsuite#ipsuite-manual)
        - [Protocols](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#protocols-manual)
        - [Utilities](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/utilities#utilities-maunal)
        - [CoreKit](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/corekit#corekit-manual)
        - [ToolKit](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit#toolkit-manual)
        - [DumpKit](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/dumpkit#dumpkit-manual)
    * [Engine Comparison](#engine-comparison)
 - [Installation](#installation)
 - [Usage](#usage)
    * [Documentation](#documentation)
        - [Interfaces](#interfaces)
        - [Macros](#macros)
            * [Formats](#formats)
            * [Layers](#layers)
            * [Engines](#engines)
        - [Protocols](#protocols)
    * [CLI Usage](#cli-usage)
 - [Samples](#samples)
    * [Usage Samples](#usage-samples)
    * [CLI Samples](#cli-samples)
 - [TODO](#todo)

---

## About

&emsp; `pcapkit` is an independent open source library, using only [`dictdumper`](https://github.com/JarryShaw/dictdumper) as its formatted output dumper.

> There is a project called [`jspcapy`](https://github.com/JarryShaw/jspcapy) works on `pcapkit`, which is a command line tool for PCAP extraction but now ***DEPRECATED***.

&emsp; Unlike popular PCAP file extractors, such as `Scapy`, `dpkt`, `pyshark`, and etc, `pcapkit` uses __streaming__ strategy to read input files. That is to read frame by frame, decrease occupation on memory, as well as enhance efficiency in some way.

### Module Structure

&emsp; In `pcapkit`, all files can be described as following eight parts.

 - Interface (`pcapkit.interface`) -- user interface for the `pcapkit` library, which standardise and simplify the usage of this library
 - Foundation (`pcapkit.foundation`) -- synthesise file I/O and protocol analysis, coordinate information exchange in all network layers
 - Reassembly (`pcapkit.reassembly`) -- base on algorithms described in [`RFC 815`](https://tools.ietf.org/html/rfc815), implement datagram reassembly of IP and TCP packets
 - Protocols (`pcapkit.protocols`) -- collection of all protocol family, with detail implementation and methods as well as constructors
 - Utilities (`pcapkit.utilities`) -- collection of four utility functions and classes
 - CoreKit (`pcapkit.corekit`) -- core utilities for `pcapkit` implementation
 - ToolKit (`pcapkit.toolkit`) -- compatibility tools for `pcapkit` implementation
 - DumpKit (`pcapkit.dumpkit`) -- dump utilities for `pcapkit` implementation

![](https://github.com/JarryShaw/PyPCAPKit/blob/master/doc/img/jspcap.png)

### Engine Comparison

&emsp; Besides, due to complexity of `pcapkit`, its extraction procedure takes around ~0.01~ *0.0009* seconds per packet, which is not ideal enough. Thus, `pcapkit` introduced alternative extraction engines to accelerate this procedure. By now, `pcapkit` supports [`Scapy`](https://scapy.net), [`DPKT`](https://github.com/kbandla/dpkt), and [`PyShark`](https://kiminewt.github.io/pyshark/). Plus, `pcapkit` supports two strategies of multiprocessing (`server` & `pipeline`). For more information, please refer to the document.

> PyPCAPKit finally boosts a bit up thanks to [@59e5aaf4](https://github.com/59e5aaf4) with issue [#29](https://github.com/JarryShaw/PyPCAPKit/issues/29) 🎉

#### Test environment

| Key                   | Value         |
| :-------------------- | :------------ |
| Operating System      | macOS Mojave  |
| Processor Name        | Intel Core i7 |
| Processor Speed       | 2.6 GHz       |
| Total Number of Cores | 6             |
| Memory                | 16 GB         |

#### Test results

| Engine     | Performance (seconds per packet) |
| :--------- | :------------------------------- |
| `dpkt`     | `0.00017389218012491862`         |
| `scapy`    | `0.00036091208457946774`         |
| `default`  | `0.0009537641207377116`          |
| `pipeline` | `0.0009694552421569824`          |
| `server`   | `0.018088217973709107`           |
| `pyshark`  | `0.04200994372367859`            |

&nbsp;

## Installation

> Note that `pcapkit` supports Python versions __since 3.4__

&emsp; Simply run the following to install the current version from PyPI:

```sh
pip install pypcapkit
```

&emsp; Or install the latest version from the git repository:

```sh
git clone https://github.com/JarryShaw/PyPCAPKit.git
cd pypcapkit
pip install -e .
# and to update at any time
git pull
```

&emsp; And since `pcapkit` supports various extraction engines, and extensive plug-in functions, you may want to install the optional ones:

```sh
# for DPKT only
pip install pypcapkit[DPKT]
# for Scapy only
pip install pypcapkit[Scapy]
# for PyShark only
pip install pypcapkit[PyShark]
# and to install all the optional packages
pip install pypcapkit[all]
# or to do this explicitly
pip install pypcapkit dpkt scapy pyshark
```

&nbsp;

## Usage

### Documentation

#### Interfaces

| NAME                                                                                        | DESCRIPTION                       |
| :------------------------------------------------------------------------------------------ | :-------------------------------- |
| [`extract`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#extract)       | extract a PCAP file               |
| [`analyse`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#analyse)       | analyse application layer packets |
| [`reassemble`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#reassemble) | reassemble fragmented datagrams   |
| [`trace`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#trace)           | trace TCP packet flows            |


#### Macros

##### Formats

| NAME                                                                                | DESCRIPTION                              |
| :---------------------------------------------------------------------------------- | :--------------------------------------- |
| [`JSON`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#formats)  | JavaScript Object Notation (JSON) format |
| [`PLIST`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#formats) | macOS Property List (PLIST) format       |
| [`TREE`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#formats)  | Tree-View text format                    |
| [`PCAP`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#formats)  | PCAP format                              |


##### Layers

| NAME                                                                               | DESCRIPTION       |
| :--------------------------------------------------------------------------------- | :---------------- |
| [`RAW`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#layers)   | no specific layer |
| [`LINK`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#layers)  | data-link layer   |
| [`INET`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#layers)  | internet layer    |
| [`TRANS`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#layers) | transport layer   |
| [`APP`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#layers)   | application layer |

##### Engines

| NAME                                                                                     | DESCRIPTION                                                 |
| :--------------------------------------------------------------------------------------- | :---------------------------------------------------------- |
| [`PCAPKit`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#engines)    | the default engine                                          |
| [`MPServer`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#engines)   | the multiprocessing engine with server process strategy     |
| [`MPPipeline`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#engines) | the multiprocessing engine with pipeline strategy           |
| [`DPKT`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#engines)       | the [`DPKT`](https://github.com/kbandla/dpkt) engine        |
| [`Scapy`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#engines)      | the [`Scapy`](https://scapy.net) engine                     |
| [`PyShark`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/interface#engines)    | the [`PyShark`](https://kiminewt.github.io/pyshark/) engine |

#### Protocols

| NAME                                                                                                 | DESCRIPTION                         |
| :--------------------------------------------------------------------------------------------------- | :---------------------------------- |
| [`NoPayload`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#nopayload)            | No-Payload                          |
| [`Raw`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols#raw)                        | Raw Packet Data                     |
| [`ARP`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/link#arp)                   | Address Resolution Protocol         |
| [`Ethernet`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/link#ethernet)         | Ethernet Protocol                   |
| [`L2TP`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/link#l2tp)                 | Layer Two Tunnelling Protocol       |
| [`OSPF`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/link#ospf)                 | Open Shortest Path First            |
| [`RARP`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/link#rarp)                 | Reverse Address Resolution Protocol |
| [`VLAN`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/link#vlan)                 | 802.1Q Customer VLAN Tag Type       |
| [`AH`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ah)                 | Authentication Header               |
| [`HIP`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#hip)               | Host Identity Protocol              |
| [`HOPOPT`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#hopopt)         | IPv6 Hop-by-Hop Options             |
| [`IP`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ip)                 | Internet Protocol                   |
| [`IPsec`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ipsec)           | Internet Protocol Security          |
| [`IPv4`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ipv4)             | Internet Protocol version 4         |
| [`IPv6`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ipv6)             | Internet Protocol version 6         |
| [`IPv6_Frag`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ipv6_frag)   | Fragment Header for IPv6            |
| [`IPv6_Opts`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ipv6_opts)   | Destination Options for IPv6        |
| [`IPv6_Route`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ipv6_route) | Routing Header for IPv6             |
| [`IPX`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#ipx)               | Internetwork Packet Exchange        |
| [`MH`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/internet#mh)                 | Mobility Header                     |
| [`TCP`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/transport#tcp)              | Transmission Control Protocol       |
| [`UDP`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/transport#udp)              | User Datagram Protocol              |
| [`HTTP`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/protocols/application#http)          | Hypertext Transfer Protocol         |

&emsp; Documentation can be found in submodules of `pcapkit`. Or, you may find usage sample in the [`test`](https://github.com/JarryShaw/PyPCAPKit/tree/master/test#test-samples) folder. For further information, please refer to the source code -- the docstrings should help you :)

__ps__: `help` function in Python should always help you out.

### CLI Usage

 > The following part was originally described in [`jspcapy`](https://github.com/JarryShaw/jspcapy), which is now deprecated and merged into this repository.

&emsp; As it shows in the help manual, it is quite easy to use:

```
$ pcapkit-cli --help
usage: pcapkit-cli [-h] [-V] [-o file-name] [-f format] [-j] [-p] [-t] [-a]
                   [-v] [-F] [-E PKG] [-P PROTOCOL] [-L LAYER]
                   input-file-name

PCAP file extractor and formatted dumper

positional arguments:
  input-file-name       The name of input pcap file. If ".pcap" omits, it will
                        be automatically appended.

optional arguments:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit
  -o file-name, --output file-name
                        The name of input pcap file. If format extension
                        omits, it will be automatically appended.
  -f format, --format format
                        Print a extraction report in the specified output
                        format. Available are all formats supported by
                        dictdumper, e.g.: json, plist, and tree.
  -j, --json            Display extraction report as json. This will yield
                        "raw" output that may be used by external tools. This
                        option overrides all other options.
  -p, --plist           Display extraction report as macOS Property List
                        (plist). This will yield "raw" output that may be used
                        by external tools. This option overrides all other
                        options.
  -t, --tree            Display extraction report as tree view text. This will
                        yield "raw" output that may be used by external tools.
                        This option overrides all other options.
  -a, --auto-extension  If output file extension omits, append automatically.
  -v, --verbose         Show more information.
  -F, --files           Split each frame into different files.
  -E PKG, --engine PKG  Indicate extraction engine. Note that except default
                        or pcapkit engine, all other engines need support of
                        corresponding packages.
  -P PROTOCOL, --protocol PROTOCOL
                        Indicate extraction stops after which protocol.
  -L LAYER, --layer LAYER
                        Indicate extract frames until which layer.
```

&emsp; Under most circumstances, you should indicate the name of input PCAP file (extension may omit) and at least, output format (`json`, `plist`, or `tree`). Once format unspecified, the name of output file must have proper extension (`*.json`, `*.plist`, or `*.txt`), otherwise `FormatError` will raise.

&emsp; As for `verbose` mode, detailed information will print while extraction (as following examples). And `auto-extension` flag works for the output file, to indicate whether extensions should be appended.

&nbsp;

## Samples

### Usage Samples

&emsp; As described in `test` folder, `pcapkit` is quite easy to use, with simply three verbs as its main interface. Several scenarios are shown as below.

 - extract a PCAP file and dump the result to a specific file (with no reassembly)

    ```python
    import pcapkit
    # dump to a PLIST file with no frame storage (property frame disabled)
    plist = pcapkit.extract(fin='in.pcap', fout='out.plist', format='plist', store=False)
    # dump to a JSON file with no extension auto-complete
    json = pcapkit.extract(fin='in.cap', fout='out.json', format='json', extension=False)
    # dump to a folder with each tree-view text file per frame
    tree = pcapkit.extract(fin='in.pcap', fout='out', format='tree', files=True)
    ```

 - extract a PCAP file and fetch IP packet (both IPv4 and IPv6) from a frame (with no output file)

    ```python
    >>> import pcapkit
    >>> extraction = pcapkit.extract(fin='in.pcap', nofile=True)
    >>> frame0 = extraction.frame[0]
    # check if IP in this frame, otherwise ProtocolNotFound will be raised
    >>> flag = pcapkit.IP in frame0
    >>> tcp = frame0[pcapkit.IP] if flag else None
    ```

 - extract a PCAP file and reassemble TCP payload (with no output file nor frame storage)

    ```python
    import pcapkit
    # set strict to make sure full reassembly
    extraction = pcapkit.extract(fin='in.pcap', store=False, nofile=True, tcp=True, strict=True)
    # print extracted packet if HTTP in reassembled payloads
    for packet in extraction.reassembly.tcp:
        for reassembly in packet.packets:
            if pcapkit.HTTP in reassembly.protochain:
                print(reassembly.info)
    ```

### CLI Samples

&emsp; The CLI (command line interface) of `pcapkit` has two different access.

 - through console scripts -- use command name `pcapkit [...]` directly (as shown in samples)
 - through Python module -- `python -m pypcapkit [...]` works exactly the same as above

Here are some usage samples:

 - export to a macOS Property List ([`Xcode`](https://developer.apple.com/xcode) has special support for this format)

 ```
 $ pcapkit in --format plist --verbose
 🚨Loading file 'in.pcap'
  - Frame   1: Ethernet:IPv6:ICMPv6
  - Frame   2: Ethernet:IPv6:ICMPv6
  - Frame   3: Ethernet:IPv4:TCP
  - Frame   4: Ethernet:IPv4:TCP
  - Frame   5: Ethernet:IPv4:TCP
  - Frame   6: Ethernet:IPv4:UDP
 🍺Report file stored in 'out.plist'
 ```

 - export to a JSON file (with no format specified)

 ```
 $ pcapkit in --output out.json --verbose
 🚨Loading file 'in.pcap'
  - Frame   1: Ethernet:IPv6:ICMPv6
  - Frame   2: Ethernet:IPv6:ICMPv6
  - Frame   3: Ethernet:IPv4:TCP
  - Frame   4: Ethernet:IPv4:TCP
  - Frame   5: Ethernet:IPv4:TCP
  - Frame   6: Ethernet:IPv4:UDP
 🍺Report file stored in 'out.json'
 ```

 - export to a text tree view file (without extension autocorrect)

 ```
 $ pcapkit in --output out --format tree --verbose
 🚨Loading file 'in.pcap'
  - Frame   1: Ethernet:IPv6:ICMPv6
  - Frame   2: Ethernet:IPv6:ICMPv6
  - Frame   3: Ethernet:IPv4:TCP
  - Frame   4: Ethernet:IPv4:TCP
  - Frame   5: Ethernet:IPv4:TCP
  - Frame   6: Ethernet:IPv4:UDP
 🍺Report file stored in 'out'
 ```

&nbsp;

## TODO

 - [x] specify `Raw` packet
 - [x] interface verbs
 - [x] review docstrings
 - [x] merge `jspcapy`
 - [x] write documentation
 - [x] implement IP and MAC address containers
 - [ ] implement option list extractors
 - [ ] implement more protocols
