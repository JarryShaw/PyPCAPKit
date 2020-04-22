# Reassembly Manual

&emsp; `pcapkit` is an open source library for PCAP extraction and analysis, written in __Python 3.6__. The following is a manual for reassembly support. Usage instructions and samples attached.

 - [Algorithms](#algorithms)
    * [Basic Algorithm](#basic-algorithm)
        - [Notations](#notations)
        - [Algorithm](#algorithm)
    * [Altered Algorithm](#altered-algorithm)
 - [Reassembly](#reassembly)
    * [`Reassembly`](#class-reassembly)
    * [`IP_Reassembly`](#ip_reassembly)
        - [`IPv4_Reassembly`](#ipv4_reassembly)
        - [`IPv6_Reassembly`](#ipv6_reassembly)
    * [`TCP_Reassembly`](#tcp_reassembly)
 - [TODO](#todo)

---

## Algorithms

&emsp; `pcapkit` provides reassembly support with algorithms described in [`RFC 791`](https://tools.ietf.org/html/rfc791#section-3.1) and [`RFC 815`](https://tools.ietf.org/html/rfc815).

### Basic Algorithm

&emsp; The following algorithm implementation is based on IP reassembly procedure introduced in [`RFC 791`](https://tools.ietf.org/html/rfc791), using `RCVBT` (fragment received bit table).

##### Notations:

```
FO    - Fragment Offset
IHL   - Internet Header Length
MF    - More Fragments flag
TTL   - Time To Live
NFB   - Number of Fragment Blocks
TL    - Total Length
TDL   - Total Data Length
BUFID - Buffer Identifier
RCVBT - Fragment Received Bit Table
TLB   - Timer Lower Bound
```

##### Algorithm:

```
DO {
    BUFID <- source|destination|protocol|identification;

    IF (FO = 0 AND MF = 0) {
        IF (buffer with BUFID is allocated) {
            flush all reassembly for this BUFID;
            Submit datagram to next step;
            DONE.
        }
    }

    IF (no buffer with BUFID is allocated) {
        allocate reassembly resources with BUFID;
        TIMER <- TLB;
        TDL <- 0;
        put data from fragment into data buffer with BUFID [from octet FO*8 to octet (TL-(IHL*4))+FO*8];
        set RCVBT bits [from FO to FO+((TL-(IHL*4)+7)/8)];
    }

    IF (MF = 0) {
        TDL <- TL-(IHL*4)+(FO*8)
    }

    IF (FO = 0) {
        put header in header buffer
    }

    IF (TDL # 0 AND all RCVBT bits [from 0 to (TDL+7)/8] are set) {
        TL <- TDL+(IHL*4)
        Submit datagram to next step;
        free all reassembly resources for this BUFID;
        DONE.
    }

    TIMER <- MAX(TIMER,TTL);

} give up until (next fragment or timer expires);

timer expires: {
    flush all reassembly with this BUFID;
    DONE.
}
```

### Altered Algorithm

&emsp; The following algorithm implementation is based on `IP Datagram Reassembly Algorithm` introduced in [`RFC 815`](https://tools.ietf.org/html/rfc815). It described an algorithm dealing with `RCVBT` (fragment received bit table) appeared in [`RFC 791`](https://tools.ietf.org/html/rfc791).

 1. Select the next hole descriptor from the hole descriptor list. If there are no more entries, go to *step eight*.
 2. If `fragment.first >= hole.last`, go to *step one*.
 3. If `fragment.last <= hole.first`, go to *step one*.
 4. Delete the current entry from the hole descriptor list.
 5. If `fragment.first >= hole.first`, then create a new hole descriptor `new_hole` with `new_hole.first = hole.first`, and `new_hole.last = fragment.first - 1`.
 6. If `fragment.last <= hole.last` and `fragment.more_fragments` is `true`, then create a new hole descriptor `new_hole`, with `new_hole.first = fragment.last + 1` and `new_hole.last = hole.last`.
 7. Go to *step one*.
 8. If the hole descriptor list is now empty, the datagram is now complete. Pass it on to the higher level protocol processor for further handling. Otherwise, return.

<a name="reassembly"> </a>

## Reassembly

&emsp; `pcapkit.reassembly` bases on algorithms described in [`RFC 815`](https://tools.ietf.org/html/rfc815), implements datagram reassembly of IP and TCP packets.

<a name="class-reassembly"> </a>

### `Reassembly`

 > described in [`src/reassembly/reassembly.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly/reassembly.py)

&emsp; `pcapkit.reassembly.reassembly` contains `Reassembly` only, which is an abstract base class for all reassembly classes, bases on algorithms described in [`RFC 815`](https://tools.ietf.org/html/rfc815), implements datagram reassembly of IP and TCP packets.

```python
class Reassembly(builtins.object)
```

##### Base class for reassembly procedure.

 - Properties:
    * `name` -- `str`, name of current protocol
    * `count` -- `int`, total number of reassembled packets
    * `datagram` -- `tuple<packet>`, reassembled datagram, which structure may vary according to its protocol
    * `protocol` -- `str`, protocol of current reassembly object

 - Methods:
    * *`abstractmethod`* `reassembly` -- perform the reassembly procedure
        ```python
        @abc.abstractmethod
        reassembly(self, info)
        ```
        - Positional arguments:
            * `info` - `Info`, info dict of packets to be reassembled
        - Returns:
            * `NotImplemented`
    * *`abstractmethod`* `submit` -- submit reassembled payload
        ```python
        @abc.abstractmethod
        submit(self, buf, **kwargs)
        ```
        - Positional arguments:
            * `buf` -- `dict`, buffer dict of reassembled packets
        - Returns:
            * `NotImplemented`
    * `fetch` -- fetch datagram
    * `index` -- return datagram index
    * `run` -- run automatically
        ```python
        run(self, packets)
        ```
        - Positional arguments:
            * `packets` -- `list<fragment>`, list of packet dicts to be reassembled

 - Data modules:
    * initialisation procedure shows as below
        ```python
        __init__(self, *, strict=False)
        ```
        - Keyword arguments:
            * `strict` -- `bool`, if return all datagrams (including those not implemented) when submit (default is `False`)
    * callable -- call packet reassembly
        ```python
        __call__(self, packet)
        ```
        - Positional arguments:
            * `packet` -- `dict`, packet dict to be reassembled (detailed format described in corresponding protocol)
    * not hashable

 - Nota Bene:
    * packet dict varies from protocols, for detailed information, please refer to [IP](#ip_reassembly) and [TCP](#tcp_reassembly)
    * datagram structure varies from protocols, for detailed information, please refer to [IP](#ip_reassembly) and [TCP](#tcp_reassembly)

### `IP_Reassembly`

 > described in [`src/reassembly/ip.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly/ip.py)

&emsp; `pcapkit.reassembly.ip` contains `IP_Reassembly` only, which is the base class for IPv4 and IPv6 reassembly. The algorithm implementation is based on IP reassembly procedure introduced in [`RFC 791`](https://tools.ietf.org/html/rfc791), using `RCVBT` (fragment received-bit table). Though another algorithm is explained in [`RFC 815`](https://tools.ietf.org/html/rfc815), replacing `RCVBT`, however, this implementation still used the elder one.

```python
class IP_Reassembly(pcapkit.reassembly.reassembly.Reassembly)
```

##### Reassembly for IP payload.

 - Properties:
    * `name` -- `str`, name of current protocol
    * `count` -- `int`, total number of reassembled packets
    * `datagram` -- `tuple<packet>`, reassembled datagram, which structure may vary according to its protocol
    * `protocol` -- `str`, protocol of current reassembly object

 - Methods:
    * `reassembly` -- perform the reassembly procedure
        ```python
        reassembly(self, info)
        ```
        - Positional arguments:
            * `info` - `Info`, info dict of packets to be reassembled
    * `submit` -- submit reassembled payload
        ```python
        submit(self, buf, **kwargs)
        ```
        - Positional arguments:
            * `buf` -- `dict`, buffer dict of reassembled packets
        - Returns:
            * `list<packet>` -- reassembled packets
    * `fetch` -- fetch datagram
    * `index` -- return datagram index
    * `run` -- run automatically
        ```python
        run(self, packets)
        ```
        - Positional arguments:
            * `packets` -- `list<fragment>`, list of packet dicts to be reassembled

 - Notations:
    * `datagram` structure:
        ```
        (tuple) datagram
            |--> (dict) packet
            |       |--> 'NotImplemented' : (bool) True --> implemented
            |       |--> 'index' : (tuple) packet numbers
            |       |                |--> (int) original packet range number
            |       |--> 'packet' : (bytes/None) reassembled IPv4 packet
            |--> (dict) packet
            |       |--> 'NotImplemented' : (bool) False --> not implemented
            |       |--> 'index' : (tuple) packet numbers
            |       |                |--> (int) original packet range number
            |       |--> 'header' : (bytes/None) IPv4 header
            |       |--> 'payload' : (tuple/None) partially reassembled IPv4 payload
            |                        |--> (bytes/None) IPv4 payload fragment
            |--> (dict) packet ...
        ```
    * `fragment` structure:
        - [IPv4](#ipv4_reassembly)
            ```python
            fragment = dict(
                bufid = tuple(
                    ipv4.src,                   # source IP address
                    ipv4.dst,                   # destination IP address
                    ipv4.id,                    # identification
                    ipv4.proto,                 # payload protocol type
                ),
                num = frame.number,             # original packet range number
                fo = ipv4.frag_offset,          # fragment offset
                ihl = ipv4.hdr_len,             # internet header length
                mf = ipv4.flags.mf,             # more fragment flag
                tl = ipv4.len,                  # total length, header includes
                header = ipv4.header,           # raw bytearray type header
                payload = ipv4.payload,         # raw bytearray type payload
            )
            ```
        - [IPv6](#ipv6_reaseembly)
            ```python
            fragment = dict(
                bufid = tuple(
                    ipv6.src,                   # source IP address
                    ipv6.dst,                   # destination IP address
                    ipv6.label,                 # label
                    ipv6_frag.next,             # next header field in IPv6 Fragment Header
                ),
                num = frame.number,             # original packet range number
                fo = ipv6_frag.offset,          # fragment offset
                ihl = ipv6.hdr_len,             # header length, only headers before IPv6-Frag
                mf = ipv6_frag.mf,              # more fragment flag
                tl = ipv6.len,                  # total length, header includes
                header = ipv6.header,           # raw bytearray type header before IPv6-Frag
                payload = ipv6.payload,         # raw bytearray type payload after IPv6-Frag
            )
            ```

#### `IPv4_Reassembly`

 > described in [`src/reassembly/ipv4.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly/ipv4.py)

```python
class IPv4_Reassembly(pcapkit.reassembly.ip.IP_Reassembly)
```

##### Reassembly for IPv4 payload.

 - Usage:
    ```python
    >>> from pcapkit.reassembly import IPv4_Reassembly
    # Initialise instance:
    >>> ipv4_reassembly = IPv4_Reassembly()
    # Call reassembly:
    >>> ipv4_reassembly(packet)
    # Fetch result:
    >>> result = ipv4_reassembly.datagram
    ```

#### `IPv6_Reassembly`

 > described in [`src/reassembly/ipv6.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly/ipv6.py)

```python
class IPv6_Reassembly(pcapkit.reassembly.ip.IP_Reassembly)
```

##### Reassembly for IPv4 payload.

 - Usage:
    ```python
    >>> from pcapkit.reassembly import IPv6_Reassembly
    # Initialise instance:
    >>> ipv6_reassembly = IPv6_Reassembly()
    # Call reassembly:
    >>> ipv6_reassembly(packet)
    # Fetch result:
    >>> result = ipv6_reassembly.datagram
    ```

### `TCP_Reassembly`

 > described in [`src/reassembly/tcp.py`](https://github.com/JarryShaw/PyPCAPKit/tree/master/pcapkit/reassembly/tcp.py)

&emsp; `pcapkit.reassembly.tcp` contains `TCP_Reassembly` only, which reconstructs fragmented TCP packets back to origin. The algorithm implementation is based on `IP Datagram Reassembly Algorithm` introduced in [`RFC 815`](https://tools.ietf.org/html/rfc815). It described an algorithm dealing with `RCVBT` (fragment received bit table) appeared in [`RFC 791`](https://tools.ietf.org/html/rfc791).

```python
class TCP_Reassembly(pcapkit.reassembly.reassembly.Reassembly)
```

##### Reassembly for TCP payload.

 - Usage:
    ```python
    >>> from pcapkit.reassembly import TCP_Reassembly
    # Initialise instance:
    >>> tcp_reassembly = TCP_Reassembly()
    # Call reassembly:
    >>> ipv6_reassembly(packet)
    # Fetch result:
    >>> result = tcp_reassembly.datagram
    ```

 - Properties:
    * `name` -- `str`, name of current protocol
    * `count` -- `int`, total number of reassembled packets
    * `datagram` -- `tuple<packet>`, reassembled datagram, which structure may vary according to its protocol
    * `protocol` -- `str`, protocol of current reassembly object

 - Methods:
    * `reassembly` -- perform the reassembly procedure
        ```python
        reassembly(self, info)
        ```
        - Positional arguments:
            * `info` - `Info`, info dict of packets to be reassembled
    * `submit` -- submit reassembled payload
        ```python
        submit(self, buf, **kwargs)
        ```
        - Positional arguments:
            * `buf` -- `dict`, buffer dict of reassembled packets
        - Returns:
            * `list<packet>` -- reassembled packets
    * `fetch` -- fetch datagram
    * `index` -- return datagram index
    * `run` -- run automatically
        ```python
        run(self, packets)
        ```
        - Positional arguments:
            * `packets` -- `list<fragment>`, list of packet dicts to be reassembled

 - Notations:
    * `datagram` sturcture:
        ```
        (tuple) datagram
           |--> (Info) data
           |       |--> 'NotImplemented' : (bool) True --> implemented
           |       |--> 'id' : (Info) original packet identifier
           |       |                |--> 'src' --> (tuple)
           |       |                |                |--> (str) ip.src
           |       |                |                |--> (int) tcp.srcport
           |       |                |--> 'dst' --> (tuple)
           |       |                |                |--> (str) ip.dst
           |       |                |                |--> (int) tcp.dstport
           |       |                |--> 'ack' --> (int) original packet ACK number
           |       |--> 'index' : (tuple) packet numbers
           |       |                |--> (int) original packet range number
           |       |--> 'payload' : (bytes/None) reassembled application layer data
           |       |--> 'packets' : (tuple<Analysis>) analysed payload
           |--> (Info) data
           |       |--> 'NotImplemented' : (bool) False --> not implemented
           |       |--> 'id' : (Info) original packet identifier
           |       |                |--> 'src' --> (tuple)
           |       |                |                |--> (str) ip.src
           |       |                |                |--> (int) tcp.srcport
           |       |                |--> 'dst' --> (tuple)
           |       |                |                |--> (str) ip.dst
           |       |                |                |--> (int) tcp.dstport
           |       |                |--> 'ack' --> (int) original packet ACK number
           |       |--> 'ack' : (int) original packet ACK number
           |       |--> 'index' : (tuple) packet numbers
           |       |                |--> (int) original packet range number
           |       |--> 'payload' : (tuple/None) partially reassembled payload
           |       |                |--> (bytes/None) payload fragment
           |       |--> 'packets' : (tuple<Analysis>) analysed payloads
           |--> (Info) data ...
        ```
    * `fragment` structure:
        ```python
        packet = Info(
            bufid = tuple(
                ip.src,                     # source IP address
                ip.dst,                     # destination IP address
                tcp.srcport,                # source port
                tcp.dstport,                # destination port
            ),
            num = frame.number,             # original packet range number
            ack = tcp.ack,                  # acknowledgement
            dsn = tcp.seq,                  # data sequence number
            syn = tcp.flags.syn,            # synchronise flag
            fin = tcp.flags.fin,            # finish flag
            rst = tcp.flags.rst,            # reset connection flag
            len = tcp.raw_len,              # payload length, header excludes
            first = tcp.seq,                # this sequence number
            last = tcp.seq + tcp.raw_len,   # next (wanted) sequence number
            payload = tcp.raw,              # raw bytearray type payload
        )
        ```

&nbsp;

## TODO

 - [x] review docstrings
 - [x] write documentation for `pcapkit.reassembly`
 - [ ] implement HTTP reassembly
 - [ ] implement IP reassembly extraction
