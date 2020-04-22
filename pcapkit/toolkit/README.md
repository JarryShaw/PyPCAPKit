# ToolKit Maunal

&emsp; `pcapkit` is an open source library for PCAP extraction and analysis, written in __Python 3.6__. The following is a manual for functions of multiple engine capability support.

 - [`PyPCAPKit`](#pypcapkit)
    * [Reassembly](#reassembly)
        - [IPv4](#ipv4_reassembly)
        - [IPv6](#ipv6_reassembly)
        - [TCP](#tcp_reassembly)
    * [Trace TCP Flows](#tcp_traceflow)
 - [`DPKT`](#dpkt)
    * [Utilities](#dpkt_utilities)
        - [Make Chain of Protocols](#dpkt_packet2chain)
        - [Transform to `dict` Type](#dpkt_packet2dict)
        - [Calculate IPv6 Exclusive Header Length](#dpkt_ipv6_hdr_len)
    * [Reassembly](#dpkt_reassembly)
        - [IPv4](#dpkt_ipv4_reassembly)
        - [IPv6](#dpkt_ipv6_reassembly)
        - [TCP](#dpkt_tcp_reassembly)
    * [Trace TCP Flows](#dpkt_tcp_traceflow)
 - [`PyShark`](#pyshark)
    * [Utlities](#pyshark_utilities)
        - [Transform to `dict` Type](#pyshark_packet2dict)
    * [Trace TCP Flows](#pyshark_tcp_traceflow)
 - [`Scapy`](#scapy)
    * [Utilities](#scapy_utilities)
        - [Make Chain of Protocols](#scapy_packet2chain)
        - [Transform to `dict` Type](#scapy_packet2dict)
    * [Reassembly](#scapy_reassembly)
        - [IPv4](#scapy_ipv4_reassembly)
        - [IPv6](#scapy_ipv6_reassembly)
        - [TCP](#scapy_tcp_reassembly)
    * [Trace TCP Flows](#scapy_tcp_traceflow)

---

## PyPCAPKit

 > described in [`src/toolkit/default.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit/default.py)

&emsp; `pcapkit.toolkit.default` contains all you need for `PyPCAPKit` handy usage. All functions returns with a flag to indicate if usable for its caller.

### Reassembly

<a name="ipv4_reassembly"> </a>

#### IPv4

```python
ipv4_reassembly(frame)
```

##### Make data for IPv4 reassembly.

 - Positional arguments:
    * `frame` -- `Frame`, a [`pcapkit.protocols.pcap.frame.Frame`](https://github.com/JarryShaw/pcapkit/tree/master/pcapkit/protocols/pcap#frame) object

 - Returns:
    * `bool` -- flag if `frame` is usable for IPv4 reassembly
    * *if `True`* `dict` -- data for IPv4 reassembly as described in [`pcapkit.reassembly.ip.IP_Reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly#ip_reassembly)
    * *if `False`* `None`

<a name="ipv6_reassembly"> </a>

#### IPv6

```python
ipv6_reassembly(frame)
```

##### Make data for IPv6 reassembly.

 - Positional arguments:
    * `frame` -- `Frame`, a [`pcapkit.protocols.pcap.frame.Frame`](https://github.com/JarryShaw/pcapkit/tree/master/pcapkit/protocols/pcap#frame) object

 - Returns:
    * `bool` -- flag if `frame` is usable for IPv6 reassembly
    * *if `True`* `dict` -- data for IPv6 reassembly as described in [`pcapkit.reassembly.ip.IP_Reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly#ip_reassembly)
    * *if `False`* `None`

<a name="tcp_reassembly"> </a>

#### TCP

```python
tcp_reassembly(frame)
```

##### Make data for TCP reassembly.

 - Positional arguments:
    * `frame` -- `Frame`, a [`pcapkit.protocols.pcap.frame.Frame`](https://github.com/JarryShaw/pcapkit/tree/master/pcapkit/protocols/pcap#frame) object

 - Returns:
    * `bool` -- flag if `frame` is usable for TCP reassembly
    * *if `True`* `dict` -- data for TCP reassembly as described in [`pcapkit.reassembly.tcp.TCP_Reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly#tcp_reassembly)
    * *if `False`* `None`

<a name="tcp_traceflow"> </a>

### Trace TCP Flows

```python
tcp_traceflow(frame, *, data_link)
```

##### Trace packet flow for TCP.

 - Positional arguments:
    * `frame` -- `Frame`, a [`pcapkit.protocols.pcap.frame.Frame`](https://github.com/JarryShaw/pcapkit/tree/master/pcapkit/protocols/pcap#frame) object

 - Keyword arguments:
    * `data_link` -- `str`, name of data link layer protocol

 - Returns:
    * `bool` -- flag if `frame` is usable for tracing TCP flows
    * *if `True`* `dict` -- data for tracing TCP flows as descibed in [`pcapkit.foundation.traceflow.TraceFlow`](#https://github.com/JarryShaw/pcapkit/tree/master/pcapkit/foundation#class-traceflow)
    * *if `False`* `None`

&nbsp;

## DPKT

 > described in [`src/toolkit/dpkt.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit/dpkt.py)

&emsp; `pcapkit.toolkit.dpkt` contains all you need for [`PyPCAPKit`](https://github.com/JarryShaw/pypcapkit#pypcapkit) handy usage with [`DPKT`](https://github.com/kbandla/dpkt) engine. All reforming functions returns with a flag to indicate if usable for its caller.

 > __NB__: to directly call following methods, please use `dpkt_function` prefixed format

<a name="dpkt_utilities"> </a>

### Utilities

<a name="dpkt_packet2chain"> </a>

#### Make Chain of Protocols

```python
packet2chain(packet)
```

##### Fetch DPKT packet protocol chain.

 - Positional arguments:
    * `packet` -- `Packet`, a [`dpkt.dpkt.Packet`](https://dpkt.readthedocs.io/en/latest/api/api_auto.html#dpkt.dpkt.Packet) object

 - Returns:
    * `str` -- a colon (`:`) seperated string of protocol chain

<a name="dpkt_packet2dict"> </a>

#### Transform to `dict` Type

```python
packet2dict(packet, timestamp, *, data_link)
```

##### Convert DPKT packet into `dict`.

 - Positional arguments:
    * `packet` -- `Packet`, a [`dpkt.dpkt.Packet`](https://dpkt.readthedocs.io/en/latest/api/api_auto.html#dpkt.dpkt.Packet) object
    * `timestamp` -- `float`, UNIX Epoch timestamp of this frame

 - Keyword arguments:
    * `data_link` -- `str`, name of data link layer protocol

 - Returns:
    * `dict` -- a recursive `dict` object containing each layer with keys in `__hdr_fields__` from the original [`dpkt.dpkt.Packet`](https://dpkt.readthedocs.io/en/latest/api/api_auto.html#dpkt.dpkt.Packet) object

<a name="dpkt_ipv6_hdr_len"> </a>

#### Calculate IPv6 Exclusive Header Length

```python
ipv6_hdr_len(ipv6)
```

##### Calculate length of headers before [IPv6-Frag](https://tools.ietf.org/html/rfc2460#section-4.5).

 - Positional arguments:
    * `ipv6` -- `IP6`, a [`dpkt.ip6.IP6`](https://dpkt.readthedocs.io/en/latest/api/api_auto.html#dpkt.ip6.IP6) object

 - Returns:
    * `int` -- exclusive length of IPv6 header with IPv6 extension headers before Fragment Header ([IPv6-Frag](https://tools.ietf.org/html/rfc2460#section-4.5))

<a name="dpkt_reassembly"> </a>

### Reassembly

<a name="dpkt_ipv4_reassembly"> </a>

#### IPv4

```python
ipv4_reassembly(packet, *, count=NotImplemented)
```

##### Make data for IPv4 reassembly.

 - Positional arguments:
    * `packet` -- `Packet`, a [`dpkt.dpkt.Packet`](https://dpkt.readthedocs.io/en/latest/api/api_auto.html#dpkt.dpkt.Packet) object

 - Keyword arguments:
    * `count` -- `int`, frame number of current packet (`NotImplemented` in default)

 - Returns:
    * `bool` -- flag if `packet` is usable for IPv4 reassembly
    * *if `True`* `dict` -- data for IPv4 reassembly as described in [`pcapkit.reassembly.ip.IP_Reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly#ip_reassembly)
    * *if `False`* `None`

<a name="dpkt_ipv6_reassembly"> </a>

#### IPv6

```python
ipv6_reassembly(packet, *, count=NotImplemented)
```

##### Make data for IPv6 reassembly.

 - Positional arguments:
    * `packet` -- `Packet`, a [`dpkt.dpkt.Packet`](https://dpkt.readthedocs.io/en/latest/api/api_auto.html#dpkt.dpkt.Packet) object

 - Keyword arguments:
    * `count` -- `int`, frame number of current packet (`NotImplemented` in default)

 - Returns:
    * `bool` -- flag if `packet` is usable for IPv6 reassembly
    * *if `True`* `dict` -- data for IPv6 reassembly as described in [`pcapkit.reassembly.ip.IP_Reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly#ip_reassembly)
    * *if `False`* `None`

<a name="dpkt_tcp_reassembly"> </a>

#### TCP

```python
tcp_reassembly(packet, *, count=NotImplemented)
```

##### Make data for TCP reassembly.

 - Positional arguments:
    * `packet` -- `Packet`, a [`dpkt.dpkt.Packet`](https://dpkt.readthedocs.io/en/latest/api/api_auto.html#dpkt.dpkt.Packet) object

 - Keyword arguments:
    * `count` -- `int`, frame number of current packet (`NotImplemented` in default)

 - Returns:
    * `bool` -- flag if `packet` is usable for TCP reassembly
    * *if `True`* `dict` -- data for TCP reassembly as described in [`pcapkit.reassembly.tcp.TCP_Reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly#tcp_reassembly)
    * *if `False`* `None`

<a name="dpkt_tcp_traceflow"> </a>

### Trace TCP Flows

```python
tcp_traceflow(packet, timestamp, *, data_link, count=NotImplemented)
```

##### Trace packet flow for TCP.

 - Positional arguments:
    * `packet` -- `Packet`, a [`dpkt.dpkt.Packet`](https://dpkt.readthedocs.io/en/latest/api/api_auto.html#dpkt.dpkt.Packet) object
    * `timestamp` -- `float`, UNIX Epoch timestamp of this frame

 - Keyword arguments:
    * `data_link` -- `str`, name of data link layer protocol
    * `count` -- `int`, frame number of current packet (`NotImplemented` in default)

 - Returns:
    * `bool` -- flag if `packet` is usable for tracing TCP flows
    * *if `True`* `dict` -- data for tracing TCP flows as descibed in [`pcapkit.foundation.traceflow.TraceFlow`](#https://github.com/JarryShaw/pcapkit/tree/master/pcapkit/foundation#class-traceflow)
    * *if `False`* `None`

&nbsp;

## PyShark

 > described in [`src/toolkit/pyshark.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit/pyshark.py)

&emsp; `pcapkit.toolkit.pyshark` contains all you need for [`PyPCAPKit`](https://github.com/JarryShaw/pypcapkit#pypcapkit) handy usage with [`PyShark`](https://kiminewt.github.io/pyshark/) engine. All reforming functions returns with a flag to indicate if usable for its caller.

 > __NB__: to directly call following methods, please use `pyshark_function` prefixed format

<a name="pyshark_utilities"> </a>

### Utilities

<a name="pyshark_packet2dict"> </a>

#### Transform to `dict` Type

```python
packet2dict(packet)
```

##### Convert PyShark packet into `dict`.

 - Positional arguments:
    * `packet` -- `Packet`, a `pyshark.packet.packet.Packet` object

 - Returns:
    * `dict` -- a recursive `dict` object containing each layer with keys in `field_names` from the original `pyshark.packet.packet.Packet` object

<a name="pyshark_tcp_traceflow"> </a>

### Trace TCP Flows

```python
tcp_traceflow(packet)
```

##### Trace packet flow for TCP.

 - Positional arguments:
    * `packet` -- `Packet`, a `pyshark.packet.packet.Packet` object

 - Returns:
    * `bool` -- flag if `packet` is usable for tracing TCP flows
    * *if `True`* `dict` -- data for tracing TCP flows as descibed in [`pcapkit.foundation.traceflow.TraceFlow`](#https://github.com/JarryShaw/pcapkit/tree/master/pcapkit/foundation#class-traceflow)
    * *if `False`* `None`

&nbsp;

## Scapy

 > described in [`src/toolkit/scapy.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/toolkit/scapy.py)

&emsp; `pcapkit.toolkit.scapy` contains all you need for [`PyPCAPKit`](https://github.com/JarryShaw/pypcapkit#pypcapkit) handy usage with [`Scapy`](https://scapy.net) engine. All reforming functions returns with a flag to indicate if usable for its caller.

 > __NB__: to directly call following methods, please use `scapy_function` prefixed format

<a name="scapy_utilities"> </a>

### Utilities

<a name="scapy_packet2chain"> </a>

#### Make Chain of Protocols

```python
packet2chain(packet)
```

##### Fetch Scapy packet protocol chain.

 - Positional arguments:
    * `packet` -- `Packet`, a `scapy.packet.Packet` object

 - Returns:
    * `str` -- a colon (`:`) seperated string of protocol chain

<a name="scapy_packet2dict"> </a>

#### Transform to `dict` Type

```python
packet2dict(packet, *, count=NotImplemented)
```

 - Positional arguments:
    * `packet` -- `Packet`, a `scapy.packet.Packet` object

 - Keyword arguments:
    * `count` -- `int`, frame number of current packet (`NotImplemented` in default)

 - Returns:
    * `dict` -- a recursive `dict` object containing each layer with keys in `fields` from the original `scapy.packet.Packet` object

<a name="scapy_reassembly"> </a>

### Reassembly

<a name="scapy_ipv4_reassembly"> </a>

#### IPv4

```python
ipv4_reassembly(packet, *, count=NotImplemented)
```

##### Make data for IPv4 reassembly.

 - Positional arguments:
    * `packet` -- `Packet`, a `scapy.packet.Packet` object

 - Keyword arguments:
    * `count` -- `int`, frame number of current packet (`NotImplemented` in default)

 - Returns:
    * `bool` -- flag if `packet` is usable for IPv4 reassembly
    * *if `True`* `dict` -- data for IPv4 reassembly as described in [`pcapkit.reassembly.ip.IP_Reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly#ip_reassembly)
    * *if `False`* `None`

<a name="scapy_ipv6_reassembly"> </a>

#### IPv6

```python
ipv6_reassembly(packet, *, count=NotImplemented)
```

##### Make data for IPv6 reassembly.

 - Positional arguments:
    * `packet` -- `Packet`, a `scapy.packet.Packet` object

 - Keyword arguments:
    * `count` -- `int`, frame number of current packet (`NotImplemented` in default)

 - Returns:
    * `bool` -- flag if `packet` is usable for IPv6 reassembly
    * *if `True`* `dict` -- data for IPv6 reassembly as described in [`pcapkit.reassembly.ip.IP_Reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly#ip_reassembly)
    * *if `False`* `None`

<a name="scapy_tcp_reassembly"> </a>

#### TCP

```python
tcp_reassembly(packet, *, count=NotImplemented)
```

##### Make data for TCP reassembly.

 - Positional arguments:
    * `packet` -- `Packet`, a `scapy.packet.Packet` object

 - Keyword arguments:
    * `count` -- `int`, frame number of current packet (`NotImplemented` in default)

 - Returns:
    * `bool` -- flag if `packet` is usable for TCP reassembly
    * *if `True`* `dict` -- data for TCP reassembly as described in [`pcapkit.reassembly.tcp.TCP_Reassembly`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly#tcp_reassembly)
    * *if `False`* `None`

<a name="scapy_tcp_traceflow"> </a>

### Trace TCP Flows

```python
tcp_traceflow(packet, *, count=NotImplemented)
```

##### Trace packet flow for TCP.

 - Positional arguments:
    * `packet` -- `Packet`, a `scapy.packet.Packet` object

 - Keyword arguments:
    * `count` -- `int`, frame number of current packet (`NotImplemented` in default)

 - Returns:
    * `bool` -- flag if `packet` is usable for tracing TCP flows
    * *if `True`* `dict` -- data for tracing TCP flows as descibed in [`pcapkit.foundation.traceflow.TraceFlow`](#https://github.com/JarryShaw/pcapkit/tree/master/pcapkit/foundation#class-traceflow)
    * *if `False`* `None`
