# -*- coding: utf-8 -*-
"""TCP's HTTP ports dispatch through the version-identifying proxy. C.f. #682.

:attr:`TCP.__proto__ <pcapkit.protocols.transport.tcp.TCP.__proto__>` bound
:class:`pcapkit.protocols.application.httpv1.HTTP` directly for ports 80 and
8080, so a segment on either port was HTTP/1 by assertion of the port number:
an HTTP/2 payload there was refused by the HTTP/1 parser and reported as
:class:`~pcapkit.protocols.misc.raw.Raw`. Both versions share those ports on the
wire -- :rfc:`9113#section-3.1` keeps the cleartext form on ``http`` -- so the
port cannot decide the version and the payload has to, which is what
:class:`pcapkit.protocols.application.http.HTTP` does.

Nothing is parsed from :file:`examples/captures/`, so this is unit tier. The
segments below are built in memory, and the HTTP/2 payload is the *verbatim*
nine octets that :file:`examples/captures/options-transport.pcap` frame 34
carries -- a fixture this library's own ``httpv2.HTTP.make`` produced -- rather
than a hand-rolled frame, because HTTP/2's declared length is whole-frame here
and a synthetic frame written to the payload-only convention would fail for a
reason that has nothing to do with dispatch.

"""

from __future__ import annotations

import importlib.util
import unittest
import warnings

from tests._support import purge_modules, time_limit

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: A 20-octet TCP header, data offset 5, ACK set, from port 50000 to port 80.
_TCP_TO_80 = bytes.fromhex('c350005000000001000000015010ffff00000000')
#: The same, to port 8080.
_TCP_TO_8080 = bytes.fromhex('c3501f9000000001000000015010ffff00000000')

#: A nine-octet HTTP/2 ``DATA`` frame: declared length 9, type 0, no flags,
#: stream 0. Copied verbatim from ``options-transport.pcap`` frame 34.
_HTTP2_FRAME = bytes.fromhex('000009000000000000')
#: A minimal HTTP/1.1 request, which must keep decoding as HTTP/1.1.
_HTTP1_REQUEST = b'GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n'


class TCPHTTPDispatchTests(unittest.TestCase):
    """TCP's port-80/8080 entries point at the proxy, and behave like it."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_tcp_binds_the_http_proxy_on_both_http_ports(self) -> None:
        """Ports 80 and 8080 resolve to ``application.http``, not ``application.httpv1``.

        The descriptor is checked rather than the imported class because all three
        HTTP classes are named ``HTTP`` (c.f. #682's own subject, the registry key
        collision), so the module name is the only thing that tells them apart.

        """
        from pcapkit.protocols.transport.tcp import TCP

        for port in (80, 8080):
            with self.subTest(port=port):
                descriptor = TCP.__proto__[port]
                self.assertEqual(descriptor.module, 'pcapkit.protocols.application.http')
                self.assertEqual(descriptor.name, 'HTTP')

    def test_tcp_and_udp_agree_on_the_http_ports(self) -> None:
        """The TCP/UDP asymmetry #682 closed stays closed.

        UDP already bound the proxy for both ports; TCP bound ``httpv1`` for the
        same two. Pinning the equality rather than each table separately is what
        makes a future one-sided edit fail here.

        """
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.protocols.transport.udp import UDP

        for port in (80, 8080):
            with self.subTest(port=port):
                tcp, udp = TCP.__proto__[port], UDP.__proto__[port]
                self.assertEqual((tcp.module, tcp.name), (udp.module, udp.name))

    @unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
    def test_http2_on_the_http_ports_decodes_as_http2_and_http1_still_as_http1(self) -> None:
        """Both versions reach their own parser from a port-80/8080 segment.

        The HTTP/2 half is what the repoint buys: before it, these nine octets
        decoded as ``TCP:Raw``, because ``httpv1.HTTP`` refused them and
        :func:`~pcapkit.protocols.misc.raw.beholder` turned the refusal into
        ``Raw``. The HTTP/1.1 half is the guard on the 231 HTTP/1.1 frames in the
        fixture corpus that this change routes through
        :meth:`HTTP._guess_version
        <pcapkit.protocols.application.http.HTTP._guess_version>` for the first
        time: they have to come back HTTP/1.1, and both halves are asserted here
        so neither can be satisfied at the other's expense.

        """
        from pcapkit.protocols.transport.tcp import TCP

        cases = (
            (_TCP_TO_80, _HTTP2_FRAME, 'TCP:HTTP/2'),
            (_TCP_TO_8080, _HTTP2_FRAME, 'TCP:HTTP/2'),
            (_TCP_TO_80, _HTTP1_REQUEST, 'TCP:HTTP/1.1'),
            (_TCP_TO_8080, _HTTP1_REQUEST, 'TCP:HTTP/1.1'),
        )
        for header, payload, expected in cases:
            with self.subTest(port=int.from_bytes(header[2:4], 'big'), chain=expected):
                raw = header + payload
                with warnings.catch_warnings():
                    # An in-memory segment carries no checksum, which the parser
                    # is entitled to complain about; the chain is what is under
                    # test.
                    warnings.simplefilter('ignore')
                    with time_limit(5):
                        proto = TCP(raw, len(raw))

                self.assertEqual(str(proto.protochain), expected)
                self.assertEqual(type(proto.payload).__module__,
                                 'pcapkit.protocols.application.http')


if __name__ == '__main__':
    unittest.main()
