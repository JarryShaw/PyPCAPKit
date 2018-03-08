# jspcap

&emsp; The `jspcap` project is an open source Python program focus on [PCAP](https://en.wikipedia.org/wiki/Pcap) parsing and analysis, which works as a stream pcap file extractor. With support of [`jsformat`](https://github.com/JarryShaw/jsformat), it shall support multiple output report formats.

> Note that the whole project only supports __Python 3.6__ or later.

 - [About](#about)
    * Extraction
    * Reassembly
    * Protocols
    * Utilities
    * Exceptions
 - [Installation](#installation)
 - [Usage](#usage)

---

### About

&emsp; `jspcap` is an independent open source library, using only [`jsformat`](https://github.com/JarryShaw/jsformat) as its formatted output dumper.

> There is a project called [`jspcapy`](https://github.com/JarryShaw/jspcapy) works on `jspcap`, which is a command line tool for PCAP extraction.

&emsp; Unlike popular PCAP file extractors, such as `Scapy`, `dkpt`, `pyshark`, and etc, `jspcap` uses __streaming__ strategy to read input files. That is to read frame by frame, decrease occupation on memory, as well as enhance efficiency in some way.

&emsp; In `jspcap`, all files can be described as following five parts.

 - Extraction (`jspcap.extractor`) -- synthesise file I/O and protocol analysis, coordinate information exchange in all network layers
 - Reassembly (`jspcap.reassembly`) -- base on algorithms described in [`RFC 815`](https://tools.ietf.org/html/rfc815), implement datagram reassembly of IP and TCP packets
 - Protocls (`jspcap.protocols`) -- collection of all protocol family, with detailed implementation and methods
 - Utilities (`jspcap.utilities`) -- collection of four utility functions and classes
 - Exceptions (`jspcap.exceptions`) -- collection of refined custom exceptions

![](./doc/jspcap.png)

&nbsp;

### Installation

> Note that `jspcap` only supports Python verions __since 3.6__

```
pip install jspcap
```

&nbsp;

### Usage

&emsp; You may find usage sample in the [`test`](https://github.com/JarryShaw/jspcap/tree/master/test) folder. For further information, please refer to the source code -- the docstrings should help you :)

__ps__: `help` function in Python should always help you out.
