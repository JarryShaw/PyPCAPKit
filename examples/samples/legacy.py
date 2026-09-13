# -*- coding: utf-8 -*-
"""Generate the extra sample captures the legacy smoke scripts read.

The demonstration scripts under ``examples/legacy_smoke/`` predate the test
suite and read their captures out of ``examples/sample/`` by relative path.
Most of them read fixtures the sibling generators in this directory already
write, but two read captures that exist nowhere in the repository, so those two
scripts cannot run at all on a fresh checkout. This module writes them, with
:mod:`scapy`, deterministically and without network access.

``test.pcap`` (34 frames)
    Read by ``examples/legacy_smoke/test_reassembly.py``, which extracts it
    with ``tcp=True``, ``reasm_strict=True`` and ``reassembly=True`` and prints
    every reassembled TCP datagram. Two connections to port 80, one over IPv4
    and one over IPv6 -- the script formats the two address families
    differently, so it needs both -- fronted by the DNS lookup that resolves
    the IPv4 server. The IPv4 response body is spread over four segments
    delivered out of order, with one of them retransmitted; the IPv6 request
    body is spread over three segments delivered in order. The IPv4 connection
    closes with a FIN from each end, the IPv6 one with a FIN from the server
    and an abortive RST from the client, so the capture covers both of the
    events that make :mod:`pcapkit` submit a datagram.

``http6.cap`` (26 frames)
    Read by ``examples/legacy_smoke/test_analyse.py``, which pretty-prints the
    application layer :mod:`pcapkit` finds in each reassembled datagram. Two
    HTTP/1.1 connections over IPv6 to port 80: a page fetch whose response body
    spans three segments, and a conditional request for a stylesheet answered
    ``304 Not Modified`` with no body at all. All four datagrams -- two
    requests, two responses -- analyse as HTTP.

    That script does not run to completion even with this fixture in place, and
    the reason is the script rather than the capture: it asks for ``tcp=True``
    and ``reasm_strict=True`` but never for ``reassembly=True``, so reading
    ``extraction.reassembly`` raises ``UnsupportedCall: 'Extractor(reassembly=
    False)' object has no attribute 'reassembly'``. It extracts all 26 frames
    first, and adding that one keyword makes the rest of it work; the fixture
    is built for the script as it will read once repaired.

Every packet is built from protocol semantics: real handshakes, sequence and
acknowledgement arithmetic that adds up, and checksums computed by
:mod:`scapy` from the finished packet. Payload text is generated from a fixed
seed rather than randomly, so a second run rewrites byte-identical files.

How pcapkit's TCP reassembly shapes these captures
--------------------------------------------------

The layouts above are not arbitrary. Four properties of
:class:`pcapkit.foundation.reassembly.tcp.TCP` decide what a capture has to
look like for a datagram to come out of it at all:

1. A buffer is keyed by the connection's four-tuple *including direction*, and
   :meth:`~pcapkit.foundation.reassembly.tcp.TCP.submit` runs only when that
   direction sends FIN or RST. A half-closed connection yields one datagram,
   not two, so both ends of every connection here close.
2. Inside a buffer, fragments are keyed by the segment's *acknowledgement*
   number, so consecutive data segments merge only while the peer sends no
   data of its own. Both fixtures therefore keep each direction of each
   connection to a single HTTP message, and let the peer answer only with pure
   acknowledgements until that message is complete.
3. A datagram counts as complete when the hole descriptor list is down to two
   entries or fewer, which an ordered run of segments plus a FIN or RST
   achieves; an out-of-order segment adds a third entry that the missing
   segment's arrival then removes.
4. The payload of a complete datagram goes to
   :meth:`pcapkit.protocols.transport.transport.Transport.analyze`, which
   picks the application protocol from the two port numbers. Port 80 is what
   maps to HTTP/1.*, so every connection in both fixtures runs on port 80.

One absence is deliberate and worth flagging, because it looks like an
oversight and is not: neither fixture contains a datagram that reassembles
*incompletely*, even though ``test_reassembly.py`` and ``test_analyse.py`` both
have a branch for one -- a payload that is a tuple of received fragments, and a
``packet`` of :data:`None`. That branch cannot be reached from a realistic
capture. ``submit`` slices the payload buffer with the bounds of each hole, but
those bounds are absolute TCP sequence numbers (``first=tcp_info.seq`` in
``pcapkit/toolkit/pcap.py``) while the buffer is indexed from the start of the
direction's data, so with any real initial sequence number every slice starts
far beyond the end of the buffer, every fragment comes out empty, and ``if
data:`` discards the datagram without a word. Measured on a probe capture with
one segment permanently missing: a realistic initial sequence number yields no
datagram for that direction at all, and only an initial sequence number of zero
produces the tuple these scripts print. A fixture cannot have both a real
handshake and that branch, so it has the real handshake.

"""

from __future__ import annotations

import hashlib
import pathlib
from typing import TYPE_CHECKING, NamedTuple

from scapy.all import (DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether,  # pylint: disable=no-name-in-module
                       IPv6, Raw, wrpcap)

if TYPE_CHECKING:
    from typing import Optional

    from scapy.packet import Packet

    #: A TCP option list, spelled the way :mod:`scapy` takes it.
    Options = list[tuple[str, object]]

__all__ = ['generate']

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]
#: Default destination directory for the generated captures.
SAMPLE = ROOT / 'examples' / 'sample'

#: Capture start time, fixed so that regenerating gives identical files.
EPOCH = 1500000000.0

#: Largest payload an IPv4 segment carries here: a 1500 octet MTU, less the
#: 20 octet IPv4 header and the 32 octet TCP header the timestamp option gives.
MSS4 = 1448
#: The same for IPv6, whose header is 40 octets rather than 20.
MSS6 = 1428


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
    """Deterministic printable filler, for use inside generated document text.

    Args:
        length: Number of characters required.
        tag: Seed distinguishing one run of filler from another.

    Returns:
        Exactly ``length`` characters drawn from the base16 alphabet.

    """
    return _filler((length + 1) // 2, tag).hex()[:length]


def _padded(prefix: 'str', suffix: 'str', size: 'int', tag: 'bytes') -> 'str':
    """Build a document of an exact length by padding between two fixed parts.

    The segment counts below are pinned -- a body has to need four segments,
    not three or five -- which is easier to guarantee by choosing the body
    length outright than by hoping generated text lands near it.

    Args:
        prefix: Text before the filler.
        suffix: Text after the filler.
        size: Wanted length of the whole document, in characters.
        tag: Seed for the filler run.

    Returns:
        ``prefix`` and ``suffix`` with exactly enough filler between them to
        make the result ``size`` characters long.

    Raises:
        RuntimeError: If ``prefix`` and ``suffix`` are already longer than
            ``size``, so no amount of filler can give that length.

    """
    filler = size - len(prefix) - len(suffix)
    if filler < 0:
        raise RuntimeError(f'cannot fit {len(prefix) + len(suffix)} characters into {size}')
    return prefix + _text_filler(filler, tag) + suffix


def _page(title: 'str', size: 'int', tag: 'bytes') -> 'bytes':
    """An HTML document of an exact length.

    Args:
        title: Contents of the ``<title>`` and ``<h1>`` elements.
        size: Wanted length of the document, in octets.
        tag: Seed for the filler paragraph.

    Returns:
        The encoded document, exactly ``size`` octets long.

    """
    prefix = ('<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
              '<title>%s</title>\n</head>\n<body>\n<h1>%s</h1>\n<p>' % (title, title))
    return _padded(prefix, '</p>\n</body>\n</html>\n', size, tag).encode()


def _telemetry(size: 'int', tag: 'bytes') -> 'bytes':
    """A JSON telemetry document of an exact length, as a browser would upload.

    Args:
        size: Wanted length of the document, in octets.
        tag: Seed for the samples and for the padding field.

    Returns:
        The encoded document, exactly ``size`` octets long.

    """
    samples = ','.join(
        '{"t":%d,"seq":%d,"v":"%s"}' % (int(EPOCH) + index * 5, index,
                                        _text_filler(48, b'%s/sample/%d' % (tag, index)))
        for index in range(6)
    )
    prefix = '{"schema":"pcapkit.example/telemetry/1","samples":[%s],"pad":"' % samples
    return _padded(prefix, '"}\n', size, tag + b'/pad').encode()


###############################################################################
# HTTP messages
###############################################################################


def _http_request(method: 'str', host: 'str', path: 'str', *, body: 'bytes' = b'',
                  content_type: 'Optional[str]' = None, referer: 'Optional[str]' = None,
                  match: 'Optional[str]' = None, close: 'bool' = False) -> 'bytes':
    """Build an HTTP/1.1 request as a browser would send it.

    Args:
        method: Request method.
        host: Value of the ``Host`` header.
        path: Request target.
        body: Request body, for a ``POST``; the ``Content-Length`` header is
            emitted whenever this is non-empty.
        content_type: Value of the ``Content-Type`` header, if any.
        referer: Value of the ``Referer`` header, if any.
        match: Value of the ``If-None-Match`` header, if any.
        close: Whether to ask for the connection to be closed.

    Returns:
        The encoded request, header block and body together.

    """
    lines = [
        '%s %s HTTP/1.1' % (method, path),
        'Host: %s' % host,
        'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        'Accept: */*',
        'Accept-Encoding: gzip, deflate',
    ]
    if referer is not None:
        lines.append('Referer: %s' % referer)
    if match is not None:
        lines.append('If-None-Match: %s' % match)
    if content_type is not None:
        lines.append('Content-Type: %s' % content_type)
    if body:
        lines.append('Content-Length: %d' % len(body))
    lines.append('Connection: close' if close else 'Connection: keep-alive')
    return ('\r\n'.join(lines) + '\r\n\r\n').encode() + body


def _http_response(body: 'bytes', *, status: 'str' = '200 OK', server: 'str' = 'nginx/1.24.0',
                   content_type: 'Optional[str]' = 'text/html; charset=utf-8',
                   etag: 'Optional[str]' = None, length: 'bool' = True,
                   close: 'bool' = False) -> 'bytes':
    """Build an HTTP/1.1 response, header block and body together.

    Args:
        body: Body octets to append after the header block.
        status: Status line, code and reason phrase.
        server: Value of the ``Server`` header.
        content_type: Value of the ``Content-Type`` header, if any.
        etag: Value of the ``ETag`` header, if any.
        length: Whether to emit a ``Content-Length`` header. A ``304`` carries
            neither a body nor a length, which is why this can be turned off.
        close: Whether the server is announcing it will close.

    Returns:
        The encoded response.

    """
    lines = [
        'HTTP/1.1 %s' % status,
        'Server: %s' % server,
        'Date: Fri, 14 Jul 2017 02:40:00 GMT',
    ]
    if content_type is not None:
        lines.append('Content-Type: %s' % content_type)
    if length:
        lines.append('Content-Length: %d' % len(body))
    if etag is not None:
        lines.append('ETag: %s' % etag)
    lines.append('Connection: close' if close else 'Connection: keep-alive')
    return ('\r\n'.join(lines) + '\r\n\r\n').encode() + body


def _segments(message: 'bytes', mss: 'int', count: 'int') -> 'list[bytes]':
    """Cut a message into maximum-sized segments, checking how many it takes.

    Args:
        message: The octets to cut up.
        mss: Largest segment the path carries.
        count: Number of segments the layout expects.

    Returns:
        The segments, in sequence-number order.

    Raises:
        RuntimeError: If the message does not need exactly ``count`` segments,
            which would mean the frame layout below no longer holds.

    """
    chunks = [message[start:start + mss] for start in range(0, len(message), mss)]
    if len(chunks) != count:
        raise RuntimeError(f'{len(message)} octets need {len(chunks)} segments, not {count}')
    return chunks


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

    def __init__(self, start: 'float' = EPOCH, step: 'float' = 0.000509) -> None:
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

    def add(self, packet: 'Packet', *, delay: 'float' = 0.0) -> 'Packet':
        """Timestamp a packet and append it to the capture.

        Args:
            packet: Frame to append.
            delay: Extra delay before this frame, on top of the nominal step.
                A retransmission arrives a retransmission timeout later, not a
                fraction of a millisecond later.

        Returns:
            The packet, as appended.

        """
        index = len(self._frames)
        self._clock += self._step + (index % 13) * 0.000041 + delay
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


def _timestamps(value: 'int', echo: 'int') -> 'Options':
    """TCP options for a segment carrying nothing but timestamps.

    Args:
        value: Timestamp value.
        echo: Timestamp echo reply.

    Returns:
        Option list, 12 octets once encoded, giving a 32-octet header.

    """
    return [('NOP', None), ('NOP', None), ('Timestamp', (value, echo))]


class _Flow:
    """A TCP connection whose sequence space the caller can address directly.

    The reassembly fixtures need segments that arrive out of order and
    segments that arrive twice, so a caller has to be able to say *where* in
    the byte stream a segment belongs rather than only "next". Every method
    therefore takes an optional ``offset``, counted in payload octets from the
    start of that direction's data, and defaults it to the first octet not yet
    sent. Sequence numbers, acknowledgement numbers, IPv4 identifications and
    TCP timestamps all follow from that.

    """

    def __init__(self, client: '_Endpoint', server: '_Endpoint', sport: 'int',
                 dport: 'int', *, client_window: 'int' = 64240,
                 server_window: 'int' = 65535, hops: 'int' = 64) -> None:
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
        self._isn = {True: 0x3c1f0a00 + sport * 4409, False: 0xa74e2600 + sport * 6151}
        self._ts = {True: 1274318895 + sport * 29, False: 3591204773 + sport * 13}
        self._ident = {True: 0x2000 + sport % 0x2000, False: 0x6000 + sport % 0x2000}
        #: Payload octets handed to each direction so far, i.e. the offset the
        #: next in-order segment starts at.
        self._sent = {True: 0, False: 0}
        #: Payload octets of the *peer* each direction has acknowledged.
        self._seen = {True: 0, False: 0}
        #: Whether each direction has sent its FIN, which the peer's
        #: acknowledgement number has to account for once it has.
        self._fin = {True: False, False: False}

    def _segment(self, to_server: 'bool', flags: 'str', *, payload: 'bytes' = b'',
                 offset: 'Optional[int]' = None, options: 'Optional[Options]' = None,
                 window: 'Optional[int]' = None) -> 'Packet':
        """Build one segment of the connection.

        Args:
            to_server: Direction of travel.
            flags: TCP flags, in :mod:`scapy` spelling.
            payload: Segment data.
            offset: Where this segment's data belongs in the byte stream; the
                first octet not yet sent, if not given.
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

        start = self._sent[to_server] if offset is None else offset
        syn = 'S' in flags
        # the SYN occupies the initial sequence number, so data starts one later
        seq = self._isn[to_server] + (0 if syn else 1) + start
        ack = 0
        if 'A' in flags:
            ack = (self._isn[not to_server] + 1 + self._seen[to_server]
                   + (1 if self._fin[not to_server] else 0))

        self._ident[to_server] = (self._ident[to_server] + 1) & 0xffff
        segment = TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack,
                      window=window, options=options)

        # a retransmission does not push the stream forward, but an
        # out-of-order segment does: the octets before it are still outstanding
        self._sent[to_server] = max(self._sent[to_server], start + len(payload))
        if 'F' in flags:
            self._fin[to_server] = True

        frame = (Ether(src=source.mac, dst=target.mac)
                 / _network(source.ip, target.ip, hops=self.hops,
                            ident=self._ident[to_server])
                 / segment)
        return frame / Raw(load=payload) if payload else frame

    def syn(self) -> 'Packet':
        """Client SYN opening the connection, with the option set Linux sends."""
        return self._segment(True, 'S', options=[
            ('MSS', 1460), ('SAckOK', b''), ('Timestamp', (self._ts[True], 0)),
            ('NOP', None), ('WScale', 7),
        ])

    def synack(self) -> 'Packet':
        """Server SYN-ACK answering the client's SYN."""
        return self._segment(False, 'SA', options=[
            ('MSS', 1460), ('SAckOK', b''),
            ('Timestamp', (self._ts[False], self._ts[True])), ('NOP', None), ('WScale', 7),
        ])

    def ack(self, to_server: 'bool' = True, *, upto: 'Optional[int]' = None,
            window: 'Optional[int]' = None) -> 'Packet':
        """A pure acknowledgement, carrying no data.

        Args:
            to_server: Direction of travel.
            upto: Payload octets of the peer being acknowledged; everything the
                peer has sent, if not given. Pass it explicitly to acknowledge
                only a contiguous prefix, which is what a receiver does while
                it is holding an out-of-order segment.
            window: Advertised window; the endpoint's default, if not given.

        Returns:
            The frame.

        """
        self._seen[to_server] = self._sent[not to_server] if upto is None else upto
        return self._segment(to_server, 'A', window=window)

    def data(self, to_server: 'bool', payload: 'bytes', *, offset: 'Optional[int]' = None,
             window: 'Optional[int]' = None) -> 'Packet':
        """A segment carrying data, with the push flag set.

        Args:
            to_server: Direction of travel.
            payload: Segment data.
            offset: Where the data belongs in the byte stream; the first octet
                not yet sent, if not given.
            window: Advertised window; the endpoint's default, if not given.

        Returns:
            The frame.

        """
        return self._segment(to_server, 'PA', payload=payload, offset=offset, window=window)

    def fin(self, to_server: 'bool' = True) -> 'Packet':
        """A FIN-ACK, closing one direction of the connection.

        Args:
            to_server: Direction of travel.

        Returns:
            The frame.

        """
        return self._segment(to_server, 'FA')

    def rst(self, to_server: 'bool' = True) -> 'Packet':
        """A RST-ACK, tearing the connection down without a handshake.

        Args:
            to_server: Direction of travel.

        Returns:
            The frame.

        """
        return self._segment(to_server, 'RA', window=0)


###############################################################################
# examples/sample/test.pcap
###############################################################################

#: Client of both connections in ``test.pcap``, and of ``http6.cap``.
_CLIENT4 = _Endpoint('00:0c:29:19:dc:61', '10.20.30.131')
#: Ethernet address of the gateway, which every off-link server sits behind.
_GATEWAY = '00:50:56:c0:00:08'
#: The recursive resolver the client asks, on the local subnet.
_RESOLVER = _Endpoint(_GATEWAY, '10.20.30.1')
#: Documentation addresses (:rfc:`5737`, :rfc:`3849`) for the two servers.
_SERVER4 = _Endpoint(_GATEWAY, '203.0.113.42')
_CLIENT6 = _Endpoint('00:0c:29:19:dc:61', '2001:db8:2f10::131')
_SERVER6 = _Endpoint(_GATEWAY, '2001:db8:9c::7a')


def _write_test(dest: 'pathlib.Path') -> 'pathlib.Path':
    """Write ``test.pcap``.

    Frames 0-1 resolve ``web.example.com``. Frames 2-20 are an IPv4 page
    fetch: the response takes four segments, the first is retransmitted
    because its acknowledgement went missing, and the third is lost and
    retransmitted after the fourth has already arrived -- so the receiver
    holds an out-of-order segment for two frames and answers a duplicate
    acknowledgement in the meantime. Frames 21-33 are an IPv6 telemetry upload
    whose request body takes three segments, answered ``204 No Content`` and
    torn down by the client with a RST, the way a browser drops an idle
    keep-alive socket.

    Args:
        dest: Destination directory.

    Returns:
        The path written.

    """
    capture = _Capture(step=0.000509)
    host4, host6 = 'web.example.com', 'api.example.com'

    # ------------------------------------------------------------------
    # 0-1: the client resolves the IPv4 server
    # ------------------------------------------------------------------
    query = DNS(id=0x2f31, rd=1, qd=[DNSQR(qname=host4, qtype='A', qclass='IN')])
    capture.add(Ether(src=_CLIENT4.mac, dst=_RESOLVER.mac)
                / IP(src=_CLIENT4.ip, dst=_RESOLVER.ip, ttl=64, id=0x1a01)
                / UDP(sport=54329, dport=53)
                / query)
    capture.add(Ether(src=_RESOLVER.mac, dst=_CLIENT4.mac)
                / IP(src=_RESOLVER.ip, dst=_CLIENT4.ip, ttl=63, id=0x1a02)
                / UDP(sport=53, dport=54329)
                / DNS(id=0x2f31, qr=1, rd=1, ra=1, qd=query.qd,
                      an=[DNSRR(rrname=host4, type='A', rclass='IN', ttl=283,
                                rdata=_SERVER4.ip)]),
                delay=0.014772)

    # ------------------------------------------------------------------
    # 2-16: the IPv4 page fetch
    # ------------------------------------------------------------------
    page = _Flow(_CLIENT4, _SERVER4, 49812, 80)
    request = _http_request('GET', host4, '/index.html',
                            referer='http://%s/' % host4)
    response = _http_response(_page('pcapkit reassembly sample', 4400, b'test/page'),
                              etag='"1a2b3c4d-1130"')
    parts = _segments(response, MSS4, 4)

    capture.add(page.syn())
    capture.add(page.synack())
    capture.add(page.ack())
    capture.add(page.data(True, request))
    capture.add(page.ack(False))

    # the first segment of the response, and the acknowledgement that never
    # reaches the server, so the server retransmits it a whole timeout later
    capture.add(page.data(False, parts[0]))
    capture.add(page.ack())
    capture.add(page.data(False, parts[0], offset=0), delay=0.203114)
    capture.add(page.ack())

    capture.add(page.data(False, parts[1]))
    capture.add(page.ack())

    # the third segment is lost, so the fourth arrives out of order and the
    # client can only repeat the acknowledgement it has already sent
    offset = len(parts[0]) + len(parts[1])
    capture.add(page.data(False, parts[3], offset=offset + len(parts[2])))
    capture.add(page.ack(upto=offset))
    capture.add(page.data(False, parts[2], offset=offset), delay=0.198365)
    capture.add(page.ack())

    # and the connection closes from both ends, which is what makes pcapkit
    # submit the two datagrams
    capture.add(page.fin(False))
    capture.add(page.ack())
    capture.add(page.fin())
    capture.add(page.ack(False))

    # ------------------------------------------------------------------
    # 17-22: the IPv6 telemetry upload
    # ------------------------------------------------------------------
    upload = _Flow(_CLIENT6, _SERVER6, 49814, 80, client_window=32768)
    report = _http_request('POST', host6, '/v1/telemetry',
                           body=_telemetry(3350, b'test/telemetry'),
                           content_type='application/json')
    chunks = _segments(report, MSS6, 3)

    capture.add(upload.syn())
    capture.add(upload.synack())
    capture.add(upload.ack())
    for chunk in chunks:
        capture.add(upload.data(True, chunk))
        capture.add(upload.ack(False))
    capture.add(upload.data(False, _http_response(b'', status='204 No Content',
                                                  content_type=None, length=False)))
    capture.add(upload.ack())
    capture.add(upload.fin(False))
    capture.add(upload.rst(), delay=0.001947)

    return capture.write(dest / 'test.pcap')


###############################################################################
# examples/sample/http6.cap
###############################################################################

#: The IPv6 web server of ``http6.cap``, and the name it answers to.
_WEB6 = _Endpoint(_GATEWAY, '2001:db8:9c::50')
_WEB6_HOST = 'www6.example.com'


def _write_http6(dest: 'pathlib.Path') -> 'pathlib.Path':
    """Write ``http6.cap``.

    Two HTTP/1.1 connections over IPv6, both to port 80 so that
    :mod:`pcapkit` analyses the reassembled payloads as HTTP. The first
    fetches a page whose response body takes three segments; the second is the
    conditional request the browser makes for the stylesheet the page
    references, which the server answers ``304 Not Modified`` -- a response
    with a header block, no body and no ``Content-Length``. Both connections
    close from both ends, so all four datagrams are submitted.

    Args:
        dest: Destination directory.

    Returns:
        The path written.

    """
    capture = _Capture(step=0.000672)
    home = 'http://%s/' % _WEB6_HOST
    etag = '"5f2e1c08-b74"'

    # ------------------------------------------------------------------
    # 0-14: the page itself, its body spread over three segments
    # ------------------------------------------------------------------
    page = _Flow(_CLIENT6, _WEB6, 49820, 80)
    response = _http_response(_page('pcapkit over IPv6', 2800, b'http6/page'),
                              etag='"5f2e1bd4-af0"')
    parts = _segments(response, MSS6, 3)

    capture.add(page.syn())
    capture.add(page.synack())
    capture.add(page.ack())
    capture.add(page.data(True, _http_request('GET', _WEB6_HOST, '/')))
    capture.add(page.ack(False))
    for part in parts:
        capture.add(page.data(False, part))
        capture.add(page.ack())
    capture.add(page.fin(False))
    capture.add(page.ack())
    capture.add(page.fin())
    capture.add(page.ack(False))

    # ------------------------------------------------------------------
    # 15-25: the stylesheet the page references, already in cache
    # ------------------------------------------------------------------
    style = _Flow(_CLIENT6, _WEB6, 49822, 80)
    capture.add(style.syn())
    capture.add(style.synack())
    capture.add(style.ack())
    capture.add(style.data(True, _http_request('GET', _WEB6_HOST, '/assets/site.css',
                                               referer=home, match=etag, close=True)))
    capture.add(style.ack(False))
    capture.add(style.data(False, _http_response(b'', status='304 Not Modified',
                                                 content_type=None, length=False,
                                                 etag=etag, close=True)))
    capture.add(style.ack())
    capture.add(style.fin(False))
    capture.add(style.ack())
    capture.add(style.fin())
    capture.add(style.ack(False))

    return capture.write(dest / 'http6.cap')


###############################################################################
# Entry point
###############################################################################


def generate(dest: 'pathlib.Path | None' = None) -> 'list[pathlib.Path]':
    """Write the legacy-smoke sample fixtures.

    Args:
        dest: Destination directory; ``examples/sample/`` under the repository
            root, if not given. Created if it does not exist.

    Returns:
        The paths written, in the order they were written.

    """
    dest = SAMPLE if dest is None else pathlib.Path(dest)
    dest.mkdir(parents=True, exist_ok=True)

    return [
        _write_test(dest),
        _write_http6(dest),
    ]


if __name__ == '__main__':
    from scapy.utils import rdpcap

    for sample in generate():
        print('%-24s %8d octets  %5d frames' % (
            sample.relative_to(ROOT), sample.stat().st_size, len(rdpcap(str(sample)))))
