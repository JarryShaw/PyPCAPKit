# PyPCAPKit -- Comprehensive Network Packet Analysis Library

> For any technical and/or maintenance information, please kindly refer to the
> **[Official Documentation](https://jarryshaw.github.io/PyPCAPKit/)**.

The PyPCAPKit project is an open source Python program focused on network packet
parsing and analysis, which works as a comprehensive
[PCAP](https://en.wikipedia.org/wiki/Pcap) file extraction, construction and
analysis library, with [DictDumper](https://github.com/JarryShaw/DictDumper) as
its formatted output dumper.

Unlike popular PCAP file extractors such as [Scapy](https://scapy.net),
[DPKT](https://dpkt.readthedocs.io) and [PyShark](https://kiminewt.github.io/pyshark),
`pcapkit` is designed to be much more comprehensive: it reports more detailed
information about each packet, and offers a more *Pythonic* interface to work
with it. When that depth is not what you need, the same interface will also drive
six third-party extraction engines instead.

The whole project supports **Python 3.6** or later.

## Installation

```shell
pip install pypcapkit
```

Or from a clone, for the latest version and for development:

```shell
git clone https://github.com/JarryShaw/PyPCAPKit.git
cd PyPCAPKit
pip install -e .
```

The extraction engines and plug-ins are optional extras:

```shell
pip install pypcapkit[DPKT]         # or Scapy, PyShark, PyPCAPFile, PyPCAP, PCAP_CT
pip install pypcapkit[crypto]       # ESP payload decryption
pip install pypcapkit[cli]          # command line interface
pip install pypcapkit[all]          # every pure-Python extra
```

Four of the engines need something beyond a `pip install` -- a `tshark` binary, a
C compiler, `libpcap` headers, or an older interpreter -- and `all` deliberately
excludes both `pypcap` and `pcap-ct`, which must never be installed together.
The [installation guide](https://jarryshaw.github.io/PyPCAPKit/#installation)
covers every constraint and the reason for it, and `pcapkit` enforces each one in
code: asking for an engine that cannot run in the current environment warns with
the actual cause and falls back to `pcapkit`'s own parser.

## Usage

```python
>>> import pcapkit
>>> extraction = pcapkit.extract('in.pcap', nofile=True)
>>> len(extraction.frame)
6
>>> frame = extraction.frame[0]
>>> str(frame.protochain)
'Ethernet:IPv6:IPv6_ICMP'
>>> frame.info.time
datetime.datetime(2017, 11, 19, 15, 49, 5, 471719, tzinfo=datetime.timezone.utc)
>>> frame.payload.payload.src
IPv6Address('fe80::a6:87f9:2793:16ee')
```

The output above is from `examples/captures/in.pcap`, which is committed, so it
is reproducible from a clone.

Reassembly, TCP flow tracing and a different engine are all keyword arguments on
the same call:

```python
>>> scapy = pcapkit.extract('in.pcap', nofile=True, engine='scapy')
>>> reasm = pcapkit.extract('in.pcap', nofile=True, reassembly=True, ipv6=True)
>>> flows = pcapkit.extract('in.pcap', nofile=True, trace=True, tcp=True)
>>> len(flows.trace)
3
```

More worked examples, including the command line interface, are in
[How to ...](https://jarryshaw.github.io/PyPCAPKit/demo.html).

## Documentation

The [official documentation](https://jarryshaw.github.io/PyPCAPKit/) is the
reference for everything below. The pages worth knowing by name:

| Page | What is in it |
|---|---|
| [API reference](https://jarryshaw.github.io/PyPCAPKit/pcapkit/index.html) | Every module, protocol and constant |
| [Module structure](https://jarryshaw.github.io/PyPCAPKit/#module-structure) | What each of the eight subpackages is for |
| [Engine comparison](https://jarryshaw.github.io/PyPCAPKit/#engine-comparison) | Which engines exist, which Python versions they run on, and measured speed per packet |
| [Engine support](https://jarryshaw.github.io/PyPCAPKit/pcapkit/foundation/engines/index.html) | What each engine does *not* support, and how the gap is surfaced |
| [Installation](https://jarryshaw.github.io/PyPCAPKit/#installation) | Extras, engine prerequisites and the local development setup |
| [Testing](https://jarryshaw.github.io/PyPCAPKit/testing.html) | Running the suite, and the sample captures it needs |
| [How to ...](https://jarryshaw.github.io/PyPCAPKit/demo.html) | Worked examples, library and CLI |
| [Extensions](https://jarryshaw.github.io/PyPCAPKit/ext.html) | Registering your own protocols, engines and dumpers |

Release history is in [CHANGELOG.md](CHANGELOG.md), and contribution guidelines
are in [CONTRIBUTING.md](CONTRIBUTING.md).
