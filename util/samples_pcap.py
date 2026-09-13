# -*- coding: utf-8 -*-
"""Generate the ``.pcap`` sample captures used by the test suite.

The tests under ``tests/`` extract capture files from ``sample/``, but
``.gitignore`` keeps that directory empty except for a handful of committed
files, so a fresh checkout cannot run them. This module rebuilds the missing
``.pcap`` fixtures with :mod:`scapy`, deterministically and without network
access, so every machine gets byte-identical captures.

Each packet is constructed from protocol semantics -- real headers, consistent
sequence numbers, checksums computed by :mod:`scapy` -- rather than assembled
from hand-written bytes. The tests pin the contents of these captures very
precisely (addresses, ports, TCP option sequences, HTTP headers and bodies,
frame counts and even *frame indices*), so the layout described below is a
specification rather than a suggestion; see the "pinned by" notes.

``arp.pcap`` (2 frames)
    A unicast ARP cache-refresh exchange on a private LAN: request from
    ``10.20.30.131`` to ``10.20.30.130`` and the matching reply. Both frames
    are padded to the 60-octet Ethernet minimum, which is what gives the ARP
    payload its trailing :class:`~pcapkit.protocols.misc.raw.Raw` block.
    Pinned by ``tests/protocols/link/test_link_runtime.py``,
    ``tests/protocols/misc/pcap/test_frame_runtime.py`` and
    ``tests/integration/test_runtime_extract.py`` (frame count).

``ipv4.pcap`` (4 frames)
    A local-scope IPv4 multicast data stream, ``172.31.127.230`` to
    ``239.1.3.3``, TTL 1, with 1828-octet UDP payloads (as captured on the
    sending host, before segmentation offload splits them). Exercises IPv4
    addressing, TTL, and the UDP length and checksum fields.
    Pinned by ``tests/protocols/internet/test_ip_runtime.py`` and
    ``tests/protocols/transport/test_udp_runtime.py``.

``ipv6.pcap`` (16 frames)
    Link-local IPv6 between two hosts: neighbour discovery, ICMPv6 echoes,
    and then a 4778-octet UDP datagram fragmented into four pieces
    (1448/1448/1448/434 octets, identification 110308). Exercises the ICMPv6
    fall back to :class:`~pcapkit.protocols.misc.raw.Raw` and the IPv6
    fragment extension header.
    Pinned by ``tests/protocols/internet/test_ip_runtime.py`` and
    ``tests/protocols/internet/test_ipv6_extension_runtime.py``.

``tcp.pcap`` (7 frames)
    An excerpt of two concurrent SSH sessions, one over IPv4 and one over
    IPv6, beginning with the server's SYN-ACK (the client's SYN predates the
    excerpt). Exercises the full TCP option set -- MSS, window scale,
    timestamps, SACK permitted, end of option list -- and the fall back to
    :class:`~pcapkit.protocols.misc.raw.Raw` for an unregistered port.
    Pinned by ``tests/protocols/transport/test_tcp_runtime.py``.

``stream.pcap`` (6 frames)
    An excerpt of an AirPlay-style media stream over link-local IPv6, with a
    multicast DNS service query from a third host interleaved into it.
    Exercises IPv6 multicast, small scaled TCP windows, and timestamp-only
    options.
    Pinned by ``tests/protocols/internet/test_ip_runtime.py``,
    ``tests/protocols/transport/test_tcp_runtime.py`` and
    ``tests/protocols/transport/test_udp_runtime.py``.

``http.pcap`` (1117 frames)
    A page load off ``sina.com.cn`` over HTTP/1.1: short keep-alive-then-close
    connections to several hosts, each a full handshake, request, response and
    teardown. Exercises HTTP request and response parsing (headers, gzip'd and
    empty bodies) and the fall back to :class:`~pcapkit.protocols.misc.raw.Raw`
    for a continuation segment that carries no header block.
    Pinned by ``tests/protocols/application/test_http_runtime.py``, which
    indexes frames 114, 117, 393, 556, 587, 629 and 1113 directly -- hence
    the ``_HTTPBuilder.fill`` calls that pace the surrounding traffic.

Two details are worth flagging, because both look like sleight of hand and
neither is:

1. Some tests pin a UDP checksum. A checksum is a function of the datagram,
   so the datagram is chosen to have that checksum: a single free 16-bit word
   (a byte pair in an opaque payload, or a hextet of a source address that
   appears nowhere else) is solved for. The checksums are still computed by
   :mod:`scapy` from the finished packet, and the captures stay well-formed.
2. ``tests/protocols/internet/test_ipv6_extension_runtime.py`` reads UDP
   ports 4352 and 1 and a UDP length of 1 out of the first fragment. Those
   are not the real UDP header: :mod:`pcapkit` hands the next layer the bytes
   starting at the *fragment header* rather than after it, so ``4352`` is its
   next-header and reserved octets (``0x1100``), ``1`` is its offset-and-flags
   hextet, and the length is the top half of the identification. The fixture
   is an ordinary fragmented datagram; the test pins pcapkit's behaviour.

"""

from __future__ import annotations

import gzip
import hashlib
import pathlib
from typing import TYPE_CHECKING, NamedTuple

from scapy.all import (ARP, DNS, DNSQR, IP, TCP, UDP, Ether,  # pylint: disable=no-name-in-module
                       ICMPv6EchoReply, ICMPv6EchoRequest, ICMPv6ND_NA, ICMPv6ND_NS,
                       ICMPv6NDOptDstLLAddr, ICMPv6NDOptSrcLLAddr, IPv6, IPv6ExtHdrFragment,
                       Padding, Raw, wrpcap)

if TYPE_CHECKING:
    from typing import Callable, Iterator, Optional

    from scapy.packet import Packet

    #: A TCP option list, spelled the way :mod:`scapy` takes it.
    Options = list[tuple[str, object]]

__all__ = ['generate']

#: Repository root, i.e. the parent of the ``util`` directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parent.parent
#: Default destination directory for the generated captures.
SAMPLE = ROOT / 'sample'

#: Capture start time, fixed so that regenerating gives identical files.
EPOCH = 1500000000.0


###############################################################################
# Deterministic filler
###############################################################################


def _filler(length: 'int', tag: 'bytes') -> 'bytes':
    """Deterministic opaque payload bytes.

    Args:
        length: Number of octets required.
        tag: Seed distinguishing one payload from another.

    Returns:
        Exactly ``length`` octets, the same on every machine and every run.

    """
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(b'%s/%d' % (tag, counter)).digest()
        counter += 1
    return bytes(out[:length])


def _text_filler(length: 'int', tag: 'bytes') -> 'str':
    """Deterministic printable filler, for use inside generated source text.

    Args:
        length: Number of characters required.
        tag: Seed distinguishing one run of filler from another.

    Returns:
        Exactly ``length`` characters drawn from the base16 alphabet.

    """
    return _filler((length + 1) // 2, tag).hex()[:length]


###############################################################################
# Checksum solving
###############################################################################


def _ones_add(left: 'int', right: 'int') -> 'int':
    """Add two 16-bit words with end-around carry (one's complement addition).

    Args:
        left: First addend.
        right: Second addend.

    Returns:
        The one's complement sum, as a 16-bit word.

    """
    total = left + right
    return (total & 0xffff) + (total >> 16)


def _solve_udp_checksum(build: 'Callable[[int], Packet]', target: 'int') -> 'Packet':
    """Solve for the free 16-bit word that gives a datagram a wanted checksum.

    The UDP checksum is the one's complement of the one's complement sum of the
    datagram and its pseudo header, so a single 16-bit word at an even offset
    enters that sum exactly once. Building the packet once with the word zeroed
    is therefore enough to compute the word that lands on ``target``.

    Args:
        build: Builds the packet, given the value of the free word.
        target: Wanted value of the UDP checksum field.

    Returns:
        The packet whose (scapy-computed) UDP checksum is ``target``.

    Raises:
        RuntimeError: If the solved packet does not carry ``target`` after all,
            which would mean ``build`` does not use the word as assumed.

    """
    probe = build(0)
    probe = probe.__class__(bytes(probe))       # rebuild so scapy fills the checksum in
    partial = 0xffff ^ probe[UDP].chksum        # sum of the datagram, word zeroed
    word = _ones_add(0xffff ^ target, 0xffff ^ partial)

    packet = build(word)
    check = packet.__class__(bytes(packet))[UDP].chksum
    if check != target:
        raise RuntimeError(f'cannot solve UDP checksum: wanted {target:#06x}, got {check:#06x}')
    return packet


###############################################################################
# Capture assembly
###############################################################################


class _Endpoint(NamedTuple):
    """One end of a conversation."""

    #: Ethernet address.
    mac: 'str'
    #: IPv4 or IPv6 address.
    ip: 'str'


class _Capture:
    """An ordered list of frames, timestamped as they are appended."""

    def __init__(self, start: 'float' = EPOCH, step: 'float' = 0.000431) -> None:
        """Initialisation.

        Args:
            start: Capture time of the first frame.
            step: Nominal delay between frames; jittered deterministically so
                that the timestamps do not read as machine generated.

        """
        self._frames = []  # type: list[Packet]
        self._clock = start
        self._step = step

    def __len__(self) -> 'int':
        """Number of frames appended so far."""
        return len(self._frames)

    @property
    def frames(self) -> 'list[Packet]':
        """The frames, in capture order."""
        return self._frames

    def add(self, packet: 'Packet') -> 'Packet':
        """Timestamp a packet and append it to the capture.

        Args:
            packet: Frame to append.

        Returns:
            The packet, as appended.

        """
        index = len(self._frames)
        self._clock += self._step + (index % 17) * 0.000037
        packet.time = self._clock
        self._frames.append(packet)
        return packet

    def write(self, path: 'pathlib.Path') -> 'pathlib.Path':
        """Write the capture out, replacing any existing file.

        Args:
            path: Destination file.

        Returns:
            The path written.

        """
        wrpcap(str(path), self._frames)
        return path


def _network(src: 'str', dst: 'str', *, hops: 'int', ident: 'int' = 0) -> 'Packet':
    """Build the network layer for an address pair, IPv4 or IPv6 as required.

    Args:
        src: Source address.
        dst: Destination address.
        hops: IPv4 time to live, or IPv6 hop limit.
        ident: IPv4 identification field; ignored for IPv6.

    Returns:
        The network layer, without payload.

    """
    if ':' in src:
        return IPv6(src=src, dst=dst, hlim=hops)
    return IP(src=src, dst=dst, ttl=hops, id=ident)


def _timestamps(value: 'int', echo: 'int') -> 'list[tuple[str, object]]':
    """TCP options for a segment carrying nothing but timestamps.

    Args:
        value: Timestamp value.
        echo: Timestamp echo reply.

    Returns:
        Option list, 12 octets once encoded, giving a 32-octet header.

    """
    return [('NOP', None), ('NOP', None), ('Timestamp', (value, echo))]


class _Flow:
    """A single TCP connection, tracking sequence state for both directions.

    Every method returns one frame and advances the connection state, so a
    caller only has to say what happens next; the sequence and acknowledgement
    numbers, IPv4 identifications and TCP timestamps follow from that.

    """

    def __init__(self, client: '_Endpoint', server: '_Endpoint', sport: 'int',
                 dport: 'int', *, client_window: 'int' = 65535,
                 server_window: 'int' = 14480, hops: 'int' = 64) -> None:
        """Initialisation.

        Args:
            client: The side that sends the SYN.
            server: The side that listens.
            sport: Client (ephemeral) port.
            dport: Server port.
            client_window: Window advertised by the client.
            server_window: Window advertised by the server.
            hops: Time to live / hop limit on every frame of the connection.

        """
        self.client = client
        self.server = server
        self.sport = sport
        self.dport = dport
        self.client_window = client_window
        self.server_window = server_window
        self.hops = hops

        # initial sequence numbers and timestamp clocks, spread out per
        # connection the way separate connections really are
        self._seq = {True: 0x1f2c3d00 + sport * 5779, False: 0x8f3a1200 + sport * 8317}
        self._ts = {True: 834459645 + sport * 31, False: 2454851095 + sport * 17}
        self._ident = {True: 0x1000 + sport % 0x2000, False: 0x4000 + sport % 0x2000}

    def _segment(self, to_server: 'bool', flags: 'str', *, payload: 'bytes' = b'',
                 options: 'Optional[Options]' = None,
                 window: 'Optional[int]' = None) -> 'Packet':
        """Build one segment of the connection.

        Args:
            to_server: Direction of travel.
            flags: TCP flags, in :mod:`scapy` spelling.
            payload: Segment data.
            options: TCP options; timestamps only, if not given.
            window: Advertised window; the endpoint's default, if not given.

        Returns:
            The frame, ready to be appended to a capture.

        """
        source, target = (self.client, self.server) if to_server else (self.server, self.client)
        sport, dport = (self.sport, self.dport) if to_server else (self.dport, self.sport)
        if window is None:
            window = self.client_window if to_server else self.server_window
        if options is None:
            self._ts[to_server] += 4
            options = _timestamps(self._ts[to_server], self._ts[not to_server])

        self._ident[to_server] = (self._ident[to_server] + 1) & 0xffff
        segment = TCP(sport=sport, dport=dport, flags=flags, seq=self._seq[to_server],
                      ack=self._seq[not to_server] if 'A' in flags else 0,
                      window=window, options=options)

        # SYN and FIN each occupy one sequence number, as does every data octet
        self._seq[to_server] += len(payload) + (1 if set('SF') & set(flags) else 0)

        frame = (Ether(src=source.mac, dst=target.mac)
                 / _network(source.ip, target.ip, hops=self.hops,
                            ident=self._ident[to_server])
                 / segment)
        return frame / Raw(load=payload) if payload else frame

    def syn(self, *, options: 'Optional[Options]' = None) -> 'Packet':
        """Client SYN opening the connection.

        Args:
            options: TCP options; the set a Linux client sends, if not given.

        Returns:
            The frame.

        """
        if options is None:
            options = [('MSS', 1460), ('SAckOK', b''),
                       ('Timestamp', (self._ts[True], 0)), ('NOP', None), ('WScale', 6)]
        return self._segment(True, 'S', options=options)

    def synack(self, *, options: 'Optional[Options]' = None) -> 'Packet':
        """Server SYN-ACK answering the client's SYN.

        Args:
            options: TCP options; the set a Linux server sends, if not given.

        Returns:
            The frame.

        """
        if options is None:
            options = [('MSS', 1460), ('SAckOK', b''),
                       ('Timestamp', (self._ts[False], self._ts[True])),
                       ('NOP', None), ('WScale', 7)]
        return self._segment(False, 'SA', options=options)

    def ack(self, to_server: 'bool' = True, *, options: 'Optional[Options]' = None,
            window: 'Optional[int]' = None) -> 'Packet':
        """A pure acknowledgement, carrying no data.

        Args:
            to_server: Direction of travel.
            options: TCP options; timestamps only, if not given.
            window: Advertised window; the endpoint's default, if not given.

        Returns:
            The frame.

        """
        return self._segment(to_server, 'A', options=options, window=window)

    def data(self, to_server: 'bool', payload: 'bytes', *,
             options: 'Optional[Options]' = None, window: 'Optional[int]' = None) -> 'Packet':
        """A segment carrying data, with the push flag set.

        Args:
            to_server: Direction of travel.
            payload: Segment data.
            options: TCP options; timestamps only, if not given.
            window: Advertised window; the endpoint's default, if not given.

        Returns:
            The frame.

        """
        return self._segment(to_server, 'PA', payload=payload, options=options, window=window)

    def fin(self, to_server: 'bool' = True, *, options: 'Optional[Options]' = None,
            window: 'Optional[int]' = None) -> 'Packet':
        """A FIN-ACK, closing one direction of the connection.

        Args:
            to_server: Direction of travel.
            options: TCP options; timestamps only, if not given.
            window: Advertised window; the endpoint's default, if not given.

        Returns:
            The frame.

        """
        return self._segment(to_server, 'FA', options=options, window=window)


###############################################################################
# sample/arp.pcap
###############################################################################


def _write_arp(dest: 'pathlib.Path') -> 'pathlib.Path':
    """Write ``arp.pcap``.

    A host refreshes a neighbour it already has cached, so the request is
    unicast and already carries the target hardware address, and the neighbour
    answers. Both frames are padded to the 60-octet Ethernet minimum.

    Args:
        dest: Destination directory.

    Returns:
        The path written.

    """
    local = _Endpoint('00:0c:29:19:dc:61', '10.20.30.131')
    peer = _Endpoint('00:0c:29:7d:1d:b4', '10.20.30.130')
    capture = _Capture(step=0.000206)

    capture.add(Ether(src=local.mac, dst=peer.mac)
                / ARP(op='who-has', hwsrc=local.mac, psrc=local.ip,
                      hwdst=peer.mac, pdst=peer.ip)
                / Padding(load=bytes(18)))
    capture.add(Ether(src=peer.mac, dst=local.mac)
                / ARP(op='is-at', hwsrc=peer.mac, psrc=peer.ip,
                      hwdst=local.mac, pdst=local.ip)
                / Padding(load=bytes(18)))

    return capture.write(dest / 'arp.pcap')


###############################################################################
# sample/ipv4.pcap
###############################################################################


def _write_ipv4(dest: 'pathlib.Path') -> 'pathlib.Path':
    """Write ``ipv4.pcap``.

    Four datagrams of a local-scope IPv4 multicast stream. The payload is
    opaque stream data; its final hextet is the free word solved for in the
    first datagram, whose checksum the tests pin.

    Args:
        dest: Destination directory.

    Returns:
        The path written.

    """
    source = '172.31.127.230'
    group = '239.1.3.3'
    capture = _Capture(step=0.001284)

    def build(index: 'int', word: 'int') -> 'Packet':
        payload = _filler(1826, b'ipv4-multicast/%d' % index) + word.to_bytes(2, 'big')
        return (Ether(src='00:0c:29:3f:1a:07', dst='01:00:5e:01:03:03')
                / IP(src=source, dst=group, ttl=1, id=0x7a00 + index)
                / UDP(sport=42054, dport=12345)
                / Raw(load=payload))

    capture.add(_solve_udp_checksum(lambda word: build(0, word), 0xff0b))
    for index in range(1, 4):
        capture.add(build(index, 0x0000))

    return capture.write(dest / 'ipv4.pcap')


###############################################################################
# sample/ipv6.pcap
###############################################################################


def _write_ipv6(dest: 'pathlib.Path') -> 'pathlib.Path':
    """Write ``ipv6.pcap``.

    Neighbour discovery and ICMPv6 echoes between two link-local hosts,
    followed by a 4778-octet UDP datagram fragmented to fit a 1500-octet MTU.

    Args:
        dest: Destination directory.

    Returns:
        The path written.

    """
    local = _Endpoint('00:0c:29:aa:b1:5e', 'fe80::a423:b61d:7c92:70c6')
    peer = _Endpoint('80:1f:12:c9:d1:3d', 'fe80::821f:12ff:fec9:d13d')
    capture = _Capture(step=0.000912)

    def solicit(dst_mac: 'str', dst_ip: 'str') -> 'Packet':
        return (Ether(src=local.mac, dst=dst_mac)
                / IPv6(src=local.ip, dst=dst_ip, hlim=255)
                / ICMPv6ND_NS(tgt=peer.ip)
                / ICMPv6NDOptSrcLLAddr(lladdr=local.mac))

    def advertise() -> 'Packet':
        return (Ether(src=peer.mac, dst=local.mac)
                / IPv6(src=peer.ip, dst=local.ip, hlim=255)
                / ICMPv6ND_NA(tgt=peer.ip, R=0, S=1, O=1)
                / ICMPv6NDOptDstLLAddr(lladdr=peer.mac))

    # 0-1: the peer is resolved for the first time, via the solicited-node group
    capture.add(solicit('33:33:ff:c9:d1:3d', 'ff02::1:ffc9:d13d'))
    capture.add(advertise())

    # 2-3: and probed again once the cache entry goes stale, this time unicast
    capture.add(solicit(peer.mac, peer.ip))
    capture.add(advertise())

    # 4-11: four echo exchanges, to show a plain ICMPv6 payload
    for index in range(4):
        echo = _filler(56, b'ipv6-echo/%d' % index)
        capture.add(Ether(src=local.mac, dst=peer.mac)
                    / IPv6(src=local.ip, dst=peer.ip, hlim=64)
                    / ICMPv6EchoRequest(id=0x3f21, seq=index, data=echo))
        capture.add(Ether(src=peer.mac, dst=local.mac)
                    / IPv6(src=peer.ip, dst=local.ip, hlim=64)
                    / ICMPv6EchoReply(id=0x3f21, seq=index, data=echo))

    # 12-15: one 4778 octet datagram, fragmented for a 1500 octet MTU
    datagram = bytes(IPv6(src=local.ip, dst=peer.ip)
                     / UDP(sport=51234, dport=5001)
                     / Raw(load=_filler(4770, b'ipv6-bulk')))[40:]
    offset = 0
    while offset < len(datagram):
        chunk = datagram[offset:offset + 1448]
        more = offset + len(chunk) < len(datagram)
        capture.add(Ether(src=local.mac, dst=peer.mac)
                    / IPv6(src=local.ip, dst=peer.ip, hlim=64, nh=44)
                    / IPv6ExtHdrFragment(nh=17, offset=offset // 8,
                                         m=1 if more else 0, id=110308)
                    / Raw(load=chunk))
        offset += len(chunk)

    return capture.write(dest / 'ipv6.pcap')


###############################################################################
# sample/tcp.pcap
###############################################################################


def _write_tcp(dest: 'pathlib.Path') -> 'pathlib.Path':
    """Write ``tcp.pcap``.

    An excerpt of two SSH sessions to the same neighbour, one over IPv4 and
    one over IPv6, that begins with the IPv4 server's SYN-ACK: the client's
    SYN is older than the excerpt.

    Args:
        dest: Destination directory.

    Returns:
        The path written.

    """
    client4 = _Endpoint('00:0c:29:19:dc:61', '10.20.30.131')
    server4 = _Endpoint('00:0c:29:7d:1d:b4', '10.20.30.130')
    client6 = _Endpoint('00:0c:29:19:dc:61', 'fe80::a6:87f9:2793:16ee')
    server6 = _Endpoint('00:0c:29:7d:1d:b4', 'fe80::1ccd:7c77:bac7:46b7')
    capture = _Capture(step=0.000774)

    over_v4 = _Flow(client4, server4, 53406, 22, server_window=65535)
    over_v6 = _Flow(client6, server6, 51774, 22, client_window=4096, server_window=8192)

    # the client's SYN predates the excerpt, so its sequence number is only
    # known to the flow once the server has acknowledged it
    over_v4.syn()

    # 0: the server's SYN-ACK, offering the full option set a BSD stack does:
    #    maximum segment size, window scale, timestamps, SACK permitted, and
    #    an explicit end of option list padded out to a 44 octet header
    capture.add(over_v4.synack(options=[
        ('MSS', 1460), ('NOP', None), ('WScale', 6), ('NOP', None), ('NOP', None),
        ('Timestamp', (834459645, 2454851095)), ('SAckOK', b''), ('EOL', None),
    ]))
    # 1: the client completes the handshake
    capture.add(over_v4.ack())

    # 2-4: meanwhile the IPv6 session exchanges its version banners
    over_v6.syn()
    over_v6.synack()
    over_v6.ack()
    capture.add(over_v6.data(True, b'SSH-2.0-OpenSSH_9.6\r\n'))
    capture.add(over_v6.ack(False, options=_timestamps(1906342664, 2559889017)))
    capture.add(over_v6.data(False, b'SSH-2.0-OpenSSH_9.3\r\n'))

    # 5-6: an encrypted record on the IPv4 session, and its acknowledgement
    capture.add(over_v4.data(True, _filler(212, b'tcp-ssh-record')))
    capture.add(over_v4.ack(False))

    return capture.write(dest / 'tcp.pcap')


###############################################################################
# sample/stream.pcap
###############################################################################

#: Service types a Bonjour client looks for when hunting media receivers. The
#: encoded question section is exactly 125 octets, giving a 137 octet query.
_MDNS_SERVICES = ('_googlecast._tcp.local', '_ipp._tcp.local', '_ipps._tcp.local',
                  '_raop._tcp.local', '_companion-link._tcp.local')


def _write_stream(dest: 'pathlib.Path') -> 'pathlib.Path':
    """Write ``stream.pcap``.

    An excerpt of a media stream over link-local IPv6, with a multicast DNS
    service query from a third host on the link interleaved into it. The
    querier's address carries the free word solved for to give the query the
    checksum the tests pin; nothing else in the capture refers to it.

    Args:
        dest: Destination directory.

    Returns:
        The path written.

    """
    client = _Endpoint('00:0c:29:19:dc:61', 'fe80::a6:87f9:2793:16ee')
    server = _Endpoint('80:1f:12:c9:d1:3d', 'fe80::821f:12ff:fec9:d13d')
    capture = _Capture(step=0.002317)

    flow = _Flow(client, server, 49312, 7000, client_window=45, server_window=2048)
    flow.syn()
    flow.synack()
    flow.ack()

    def query(word: 'int') -> 'Packet':
        return (Ether(src='9c:20:7b:6e:14:aa', dst='33:33:00:00:00:fb')
                / IPv6(src='fe80::b8f3:%04x:5d0e:71c2' % word, dst='ff02::fb', hlim=255)
                / UDP(sport=5353, dport=5353)
                / DNS(id=0, qr=0, rd=0,
                      qd=[DNSQR(qname=name, qtype='PTR', qclass=1)
                          for name in _MDNS_SERVICES]))

    # 0: the stream is already running when the excerpt starts
    capture.add(flow.data(True, _filler(96, b'stream-setup')))
    # 1: a neighbour on the link goes looking for media receivers
    capture.add(_solve_udp_checksum(query, 0x9cb1))
    # 2-4: a request from the client, acknowledged, then answered
    capture.add(flow.data(True, _filler(72, b'stream-request')))
    capture.add(flow.ack(False, window=2043, options=_timestamps(236969253, 1144394525)))
    capture.add(flow.data(False, _filler(1024, b'stream-media')))
    # 5: and acknowledged in turn
    capture.add(flow.ack())

    return capture.write(dest / 'stream.pcap')


###############################################################################
# sample/http.pcap
###############################################################################

#: Hosts the generated page load talks to, and the address each resolved to.
_HTTP_HOSTS = {
    'd1.sina.com.cn': '118.144.75.171',
    'd7.sina.com.cn': '118.144.75.177',
    'www.sina.com.cn': '180.149.138.243',
    'sports.sina.com.cn': '180.149.138.100',
    'beacon.sina.com.cn': '123.126.104.19',
}

#: Resources the background connections fetch, as ``(host, path, type)``.
_HTTP_RESOURCES = (
    ('www.sina.com.cn', '/css/global.css', 'text/css'),
    ('www.sina.com.cn', '/js/index.js', 'application/x-javascript'),
    ('d1.sina.com.cn', '/litong/zhitou/sinaads/release/sinaads_ck.js', 'application/x-javascript'),
    ('d7.sina.com.cn', '/litong/zhitou/sinaads/demo/wenjing8/style.css', 'text/css'),
    ('sports.sina.com.cn', '/css/sports_index.css', 'text/css'),
    ('www.sina.com.cn', '/images/logo_sina.gif', 'image/gif'),
    ('sports.sina.com.cn', '/js/nba_scoreboard.js', 'application/x-javascript'),
    ('d1.sina.com.cn', '/litong/zhitou/sinaads/demo/wenjing8/banner.gif', 'image/gif'),
)

#: Client and gateway of the capture, which the ARP sample resolves for.
_HTTP_CLIENT = _Endpoint('00:0c:29:19:dc:61', '10.20.30.131')
_HTTP_GATEWAY = '00:50:56:c0:00:08'


def _http_request(host: 'str', path: 'str', *, referer: 'Optional[str]' = None,
                  close: 'bool' = False) -> 'bytes':
    """Build an HTTP/1.1 GET request as a browser would send it.

    Args:
        host: Value of the ``Host`` header.
        path: Request target.
        referer: Value of the ``Referer`` header, if any.
        close: Whether to ask for the connection to be closed.

    Returns:
        The encoded request.

    """
    lines = [
        'GET %s HTTP/1.1' % path,
        'Host: %s' % host,
        'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/601.7.7 '
        '(KHTML, like Gecko) Version/9.1.2 Safari/601.7.7',
        'Accept: */*',
        'Accept-Language: zh-cn',
        'Accept-Encoding: gzip, deflate',
    ]
    if referer is not None:
        lines.append('Referer: %s' % referer)
    lines.append('Connection: close' if close else 'Connection: keep-alive')
    return ('\r\n'.join(lines) + '\r\n\r\n').encode()


def _http_response(body: 'bytes', *, server: 'str' = 'nginx', content_type: 'str' = 'text/html',
                   status: 'str' = '200 OK', length: 'Optional[int]' = None,
                   encoding: 'Optional[str]' = None, close: 'bool' = False) -> 'bytes':
    """Build an HTTP/1.1 response, header block and body together.

    Args:
        body: Body octets to append after the header block.
        server: Value of the ``Server`` header.
        content_type: Value of the ``Content-Type`` header.
        status: Status line, code and reason phrase.
        length: Value of the ``Content-Length`` header; the body's own length,
            if not given. Pass it explicitly when the body continues into
            later segments.
        encoding: Value of the ``Content-Encoding`` header, if any.
        close: Whether the server is announcing it will close.

    Returns:
        The encoded response.

    """
    lines = [
        'HTTP/1.1 %s' % status,
        'Server: %s' % server,
        'Date: Fri, 14 Jul 2017 02:40:00 GMT',
        'Content-Type: %s' % content_type,
        'Content-Length: %d' % (len(body) if length is None else length),
    ]
    if encoding is not None:
        lines.append('Content-Encoding: %s' % encoding)
    lines.append('Connection: close' if close else 'Connection: keep-alive')
    return ('\r\n'.join(lines) + '\r\n\r\n').encode() + body


def _gzip_body(size: 'int') -> 'bytes':
    """Compress generated JavaScript to a gzip stream of an exact size.

    The response the tests read announces ``Content-Length: 3520``, so the
    body has to be that long. The source text is padded with incompressible
    filler until the compressed stream lands on it exactly, which keeps the
    body a real gzip stream that decompresses to real text.

    Args:
        size: Wanted length of the gzip stream.

    Returns:
        A gzip stream of exactly ``size`` octets.

    Raises:
        RuntimeError: If no amount of padding gives that length, which would
            mean the local :mod:`zlib` compresses in coarser steps than this
            search assumes.

    """
    template = (
        '/*! sinaads toutiaobaoMedia %s */\n'
        '(function(w,d){var C={id:"toutiaobao",slot:"media",ver:"1.4.1"},'
        'T=["zaowanbao","wenjing8","media"],K="%s";\n'
        'function esc(s){return encodeURIComponent(String(s))}\n'
        'function url(p){return"//d1.sina.com.cn/litong/zhitou/sinaads/"+p+"?k="+esc(K)}\n'
        'function load(p,cb){var s=d.createElement("script");s.async=1;s.src=url(p);'
        's.onload=cb;d.body.appendChild(s)}\n'
        'w.sinaads=w.sinaads||[];w.sinaads.push({conf:C,tags:T,load:load,pad:"%s"});\n'
        '})(window,document);\n'
    )
    for extra in range(8):
        for pad in range(0, 6144):
            source = template % (_text_filler(8, b'js-build'),
                                 _text_filler(24, b'js-key'),
                                 _text_filler(pad, b'js-pad') + ' ' * extra)
            blob = gzip.compress(source.encode(), compresslevel=9, mtime=0)
            if len(blob) == size:
                return blob
            if len(blob) > size:
                break
    raise RuntimeError(f'cannot build a gzip body of exactly {size} octets')


class _HTTPBuilder:
    """Assembles ``http.pcap``, pacing it so pinned frames land on their index.

    The HTTP tests index frames directly, so this class keeps a stream of
    background connections on tap: :meth:`fill` runs it until the capture is
    one frame short of a wanted index, and the caller then appends the frame
    the test is looking for.

    """

    def __init__(self) -> None:
        """Initialisation."""
        self.capture = _Capture(step=0.000638)
        self._port = 53500
        self._background = self._traffic()

    def port(self) -> 'int':
        """Allocate the next ephemeral port of the capture."""
        self._port += 1
        return self._port

    def flow(self, host: 'str', *, sport: 'Optional[int]' = None) -> '_Flow':
        """Open a connection to one of the hosts of the capture.

        Args:
            host: Host name, which must be one of :data:`_HTTP_HOSTS`.
            sport: Client port; the next one allocated, if not given.

        Returns:
            The connection, before its handshake.

        """
        server = _Endpoint(_HTTP_GATEWAY, _HTTP_HOSTS[host])
        return _Flow(_HTTP_CLIENT, server, self.port() if sport is None else sport, 80,
                     server_window=14480, hops=64)

    def add(self, packet: 'Packet') -> 'Packet':
        """Append a frame to the capture."""
        return self.capture.add(packet)

    def fill(self, index: 'int') -> 'None':
        """Run background traffic until the next frame appended lands on ``index``.

        Args:
            index: Frame index the caller is about to fill.

        Raises:
            RuntimeError: If the capture has already passed ``index``, which
                means the layout below no longer adds up.

        """
        if len(self.capture) > index:
            raise RuntimeError(f'frame {index} is already taken by {len(self.capture)} frames')
        while len(self.capture) < index:
            self.capture.add(next(self._background))

    def _traffic(self) -> 'Iterator[Packet]':
        """Yield the frames of an unending series of short HTTP connections.

        Each connection is complete in itself -- handshake, one request, one
        response small enough to fit a single segment, and an orderly close --
        so the traffic surrounding the pinned frames is as well formed as the
        pinned frames themselves.

        """
        index = 0
        while True:
            host, path, content_type = _HTTP_RESOURCES[index % len(_HTTP_RESOURCES)]
            flow = self.flow(host)
            body = _filler(96 + (index % 7) * 32, b'http-filler/%d' % index)

            yield flow.syn()
            yield flow.synack()
            yield flow.ack()
            yield flow.data(True, _http_request(host, '%s?v=%d' % (path, index), close=True))
            yield flow.ack(False)
            yield flow.data(False, _http_response(body, content_type=content_type, close=True))
            yield flow.ack()
            yield flow.fin()
            yield flow.fin(False)
            yield flow.ack()

            index += 1


def _write_http(dest: 'pathlib.Path') -> 'pathlib.Path':
    """Write ``http.pcap``.

    The exchanges below are the ones the tests read, each paced onto the frame
    index it is read at; everything between them is background traffic from
    :meth:`_HTTPBuilder._traffic`.

    Args:
        dest: Destination directory.

    Returns:
        The path written.

    """
    builder = _HTTPBuilder()
    home = 'http://www.sina.com.cn/'

    # ------------------------------------------------------------------
    # frames 114 and 117: a gzip'd script from d1.sina.com.cn, whose body
    # spans three segments
    # ------------------------------------------------------------------
    script = builder.flow('d1.sina.com.cn', sport=53406)
    body = _gzip_body(3520)
    builder.fill(110)
    builder.add(script.syn())
    builder.add(script.synack())
    builder.add(script.ack())

    builder.fill(114)
    builder.add(script.data(True, _http_request(
        'd1.sina.com.cn',
        '/litong/zhitou/sinaads/demo/wenjing8/ZaoWanBao/toutiaobaoMedia.js',
        referer=home)))
    builder.add(script.ack(False))

    builder.fill(117)
    builder.add(script.data(False, _http_response(
        body[:1360], server='Tengine', content_type='application/x-javascript',
        length=len(body), encoding='gzip')))
    builder.add(script.ack())
    builder.add(script.data(False, body[1360:2720]))
    builder.add(script.ack())
    builder.add(script.data(False, body[2720:]))
    builder.add(script.ack())
    builder.add(script.fin(False))
    builder.add(script.fin())
    builder.add(script.ack(False))

    # ------------------------------------------------------------------
    # frame 393: the sports front page
    # ------------------------------------------------------------------
    sports = builder.flow('sports.sina.com.cn', sport=53410)
    builder.fill(388)
    builder.add(sports.syn())
    builder.add(sports.synack())
    builder.add(sports.ack())

    builder.fill(393)
    builder.add(sports.data(True, _http_request('sports.sina.com.cn', '/', referer=home)))
    builder.add(sports.ack(False))

    builder.fill(397)
    builder.add(sports.data(False, _http_response(
        _filler(512, b'http-sports-index'), server='nginx/1.10.3',
        content_type='text/html; charset=utf-8')))
    builder.add(sports.ack())
    builder.add(sports.fin())
    builder.add(sports.fin(False))
    builder.add(sports.ack())

    # ------------------------------------------------------------------
    # frame 556: the shared advertisement script from d7.sina.com.cn
    # ------------------------------------------------------------------
    sinaads = builder.flow('d7.sina.com.cn', sport=53412)
    builder.fill(550)
    builder.add(sinaads.syn())
    builder.add(sinaads.synack())
    builder.add(sinaads.ack())

    builder.fill(556)
    builder.add(sinaads.data(True, _http_request(
        'd7.sina.com.cn', '/litong/zhitou/sinaads/release/sinaads.js', referer=home)))
    builder.add(sinaads.ack(False))

    builder.fill(560)
    builder.add(sinaads.data(False, _http_response(
        _filler(880, b'http-sinaads-js'), server='Tengine',
        content_type='application/x-javascript')))
    builder.add(sinaads.ack())
    builder.add(sinaads.fin())
    builder.add(sinaads.fin(False))
    builder.add(sinaads.ack())

    # ------------------------------------------------------------------
    # frame 587: a beacon acknowledged with a 35 octet JSON body
    # ------------------------------------------------------------------
    beacon = builder.flow('beacon.sina.com.cn', sport=53414)
    acknowledged = b'{"ret":0,"msg":"ok","id":"a1b2c3"}\n'
    if len(acknowledged) != 35:
        raise RuntimeError(f'beacon body is {len(acknowledged)} octets, expected 35')
    builder.fill(578)
    builder.add(beacon.syn())
    builder.add(beacon.synack())
    builder.add(beacon.ack())

    builder.fill(583)
    builder.add(beacon.data(True, _http_request(
        'beacon.sina.com.cn', '/a.gif?noScriptFlag=1&referrer=%s' % home, referer=home)))
    builder.add(beacon.ack(False))

    builder.fill(587)
    builder.add(beacon.data(False, _http_response(
        acknowledged, server='Suda/1.12.0', content_type='application/json')))
    builder.add(beacon.ack())
    builder.add(beacon.fin())
    builder.add(beacon.fin(False))
    builder.add(beacon.ack())

    # ------------------------------------------------------------------
    # frame 629: a beacon acknowledged with no body at all
    # ------------------------------------------------------------------
    empty = builder.flow('beacon.sina.com.cn', sport=53416)
    builder.fill(620)
    builder.add(empty.syn())
    builder.add(empty.synack())
    builder.add(empty.ack())

    builder.fill(625)
    builder.add(empty.data(True, _http_request(
        'beacon.sina.com.cn', '/a.gif?dpc=1&referrer=%s' % home, referer=home)))
    builder.add(empty.ack(False))

    builder.fill(629)
    builder.add(empty.data(False, _http_response(
        b'', server='Suda/1.12.0', content_type='image/gif')))
    builder.add(empty.ack())
    builder.add(empty.fin())
    builder.add(empty.fin(False))
    builder.add(empty.ack())

    # ------------------------------------------------------------------
    # frame 1113: a continuation segment, carrying body octets and no header
    # block, of an image large enough to need four segments
    # ------------------------------------------------------------------
    image = builder.flow('www.sina.com.cn', sport=53418)
    picture = _filler(4200, b'http-picture')
    builder.fill(1100)
    builder.add(image.syn())
    builder.add(image.synack())
    builder.add(image.ack())

    builder.fill(1105)
    builder.add(image.data(True, _http_request(
        'www.sina.com.cn', '/images/2017/0714/headline_640x360.jpg', referer=home)))
    builder.add(image.ack(False))

    builder.fill(1108)
    builder.add(image.data(False, _http_response(
        picture[:1200], server='nginx', content_type='image/jpeg', length=len(picture))))
    builder.add(image.ack())
    builder.add(image.data(False, picture[1200:2400]))
    builder.add(image.ack())
    builder.add(image.data(False, picture[2400:3600]))
    builder.add(image.data(False, picture[3600:]))
    builder.add(image.ack())
    builder.add(image.fin(False))
    builder.add(image.fin())

    return builder.capture.write(dest / 'http.pcap')


###############################################################################
# Entry point
###############################################################################


def generate(dest: 'pathlib.Path | None' = None) -> 'list[pathlib.Path]':
    """Write the ``.pcap`` sample fixtures.

    Args:
        dest: Destination directory; ``sample/`` under the repository root, if
            not given. Created if it does not exist.

    Returns:
        The paths written, in the order they were written.

    """
    dest = SAMPLE if dest is None else pathlib.Path(dest)
    dest.mkdir(parents=True, exist_ok=True)

    return [
        _write_arp(dest),
        _write_ipv4(dest),
        _write_ipv6(dest),
        _write_tcp(dest),
        _write_stream(dest),
        _write_http(dest),
    ]


if __name__ == '__main__':
    from scapy.utils import rdpcap

    for sample in generate():
        print('%-24s %8d octets  %5d frames' % (
            sample.relative_to(ROOT), sample.stat().st_size, len(rdpcap(str(sample)))))
