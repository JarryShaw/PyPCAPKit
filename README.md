# PyPCAPKit -- Comprehensive Network Packet Analysis Library

> For technical and maintenance information, see the
> **[Official Documentation](https://jarryshaw.github.io/PyPCAPKit/)**.

PyPCAPKit is an open-source Python library for parsing, constructing and analysing
network packets and [PCAP](https://en.wikipedia.org/wiki/Pcap) files, with
[DictDumper](https://github.com/JarryShaw/DictDumper) as its formatted output dumper.

Unlike popular PCAP extractors such as [Scapy](https://scapy.net),
[DPKT](https://dpkt.readthedocs.io) and [PyShark](https://kiminewt.github.io/pyshark),
`pcapkit` reports more detail about each packet through a more *Pythonic* interface.
Where that depth is not needed, the same interface also drives six third-party
extraction engines.

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
pip install pypcapkit[all]          # core addons only: cli + crypto + NGAP (pycrate)
```

Engines are on demand; `all` bundles only the core addons the library needs for
full functionality. Four engines also need something beyond `pip install` -- a
`tshark` binary, a C compiler, `libpcap` headers, or an older interpreter -- and
`pypcap`/`pcap-ct` must never be installed together. The
[installation guide](https://jarryshaw.github.io/PyPCAPKit/#installation) gives each
constraint and its reason. `pcapkit` enforces them in code: asking for an engine
that cannot run in the current environment warns with the cause and falls back to
its own parser.

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

The output is from the committed `examples/captures/in.pcap`, so it is reproducible
from a clone.

Reassembly, TCP flow tracing and the engine are keyword arguments to the same call:

```python
>>> scapy = pcapkit.extract('in.pcap', nofile=True, engine='scapy')
>>> reasm = pcapkit.extract('in.pcap', nofile=True, reassembly=True, ipv6=True)
>>> flows = pcapkit.extract('in.pcap', nofile=True, trace=True, tcp=True)
>>> len(flows.trace)
3
```

More examples, including the command line interface, are in
[How to ...](https://jarryshaw.github.io/PyPCAPKit/demo.html).

## Documentation

The [official documentation](https://jarryshaw.github.io/PyPCAPKit/) is the
reference. Pages worth knowing by name:

| Page | What is in it |
|---|---|
| [API reference](https://jarryshaw.github.io/PyPCAPKit/pcapkit/index.html) | Every module, protocol and constant |
| [Module structure](https://jarryshaw.github.io/PyPCAPKit/#module-structure) | What each of the nine subpackages is for |
| [Engine comparison](https://jarryshaw.github.io/PyPCAPKit/#engine-comparison) | Which engines exist, which Python versions they run on, and measured speed per packet |
| [Engine support](https://jarryshaw.github.io/PyPCAPKit/pcapkit/foundation/engines/index.html) | What each engine does *not* support, and how the gap is surfaced |
| [Installation](https://jarryshaw.github.io/PyPCAPKit/#installation) | Extras, engine prerequisites and the local development setup |
| [Testing](https://jarryshaw.github.io/PyPCAPKit/contributing/testing.html) | Running the suite, and the sample captures it needs |
| [How to ...](https://jarryshaw.github.io/PyPCAPKit/demo.html) | Worked examples, library and CLI |
| [Extensions](https://jarryshaw.github.io/PyPCAPKit/ext.html) | Registering your own protocols, engines and dumpers |

Release history is in [CHANGELOG.md](CHANGELOG.md), and contribution guidelines
are in [CONTRIBUTING.md](CONTRIBUTING.md).
