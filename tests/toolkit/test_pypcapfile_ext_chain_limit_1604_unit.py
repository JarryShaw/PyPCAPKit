""":mod:`pcapkit.toolkit.pypcapfile` stops a chain of IPv6 extension headers where the default engine does.

GitHub issue #1604: the default engine dissects at most
:data:`~pcapkit.protocols.internet.internet.EXTENSION_HEADER_LIMIT` extension
headers in a row and leaves the rest raw, so the TCP behind a longer chain is
not found. :func:`~pcapkit.toolkit.pypcapfile._past_extension_headers` (inside
IPv4) and :func:`~pcapkit.toolkit.pypcapfile._upper_layer` (over IPv6) walk such
a chain in a loop, and stop at the same depth, so the TCP the toolkit reads and
the TCP it warns of leaving out are the TCP the default engine finds.

These tests use stand-ins for `pypcapfile`_'s decoders, so run without it; the
comparison of the two engines over a capture is in
:mod:`tests.foundation.engines.test_ext_chain_limit_agreement_1604_unit`.

.. _pypcapfile: https://github.com/kisom/pypcapfile

"""
from __future__ import annotations

import unittest
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire
from tests.toolkit import test_pypcapfile_unit as base

#: Chain lengths either side of the limit, and one far past it.
AT_LIMIT, PAST_LIMIT = (32,), (33, 1000)


def chain(count: int, last: int, *, mixed: bool = False) -> bytes:
    """``count`` extension headers, the last naming ``last``.

    Destination Options headers only, or alternately Destination Options and
    AH when ``mixed``; the first is always Destination Options (protocol 60).

    """
    kinds = ['ah' if mixed and index % 2 else 'opts' for index in range(count)]
    codes = [51 if kind == 'ah' else 60 for kind in kinds] + [last]
    return b''.join(base.ah(nxt, 1) if kind == 'ah' else base.options_header(nxt)
                    for kind, nxt in zip(kinds, codes[1:]))


@unittest.skipUnless(base.HAS_RUNTIME, 'runtime dependencies not installed')
class PyPCAPFileExtensionHeaderChainLimitTests(unittest.TestCase):
    """C.f. #1604."""

    decline = base.PyPCAPFileTCPOverIPv6Tests.decline

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_transport_reads_tcp_behind_a_chain_of_32_inside_ipv4(self) -> None:
        from pcapkit.toolkit.pypcapfile import _transport

        segment = base.make_tcp(b'data')
        for count in AT_LIMIT:
            for mixed in (False, True):
                with self.subTest(count=count, mixed=mixed):
                    layer = base.FakeIP(chain(count, 6, mixed=mixed) + segment, p=60)
                    self.assertEqual(_transport(layer), segment)

    def test_no_tcp_behind_a_longer_chain_inside_ipv4(self) -> None:
        from pcapkit.toolkit import pypcapfile

        segment = base.make_tcp(b'data')
        for count in PAST_LIMIT:
            for mixed in (False, True):
                with self.subTest(count=count, mixed=mixed):
                    layer = base.FakeIP(chain(count, 6, mixed=mixed) + segment, p=60)
                    with mock.patch.object(pypcapfile, '_default_extension_header',
                                           wraps=pypcapfile._default_extension_header) as parse:
                        self.assertIsNone(pypcapfile._transport(layer))
                    # the walk stops at the limit, rather than reading the rest
                    self.assertLessEqual(parse.call_count, 32)
                    self.assertEqual(self.decline(base.make_packet(base.FakeEthernet(layer))), [])

    def test_tcp_over_ipv6_behind_a_chain_of_32_warns(self) -> None:
        for count in AT_LIMIT:
            for mixed in (False, True):
                with self.subTest(count=count, mixed=mixed):
                    packet = wire.ipv6(chain(count, 6, mixed=mixed) + base.TCP_SEGMENT, nxt=60)
                    messages = self.decline(base.make_packet(base.ipv6_frame(packet)))
                    self.assertEqual(len(messages), 1, messages)
                    self.assertIn('TCP over IPv6', messages[0])

    def test_tcp_over_ipv6_behind_a_longer_chain_does_not_warn(self) -> None:
        # The default engine finds no TCP there, so none is left out.
        for count in PAST_LIMIT:
            for mixed in (False, True):
                with self.subTest(count=count, mixed=mixed):
                    packet = wire.ipv6(chain(count, 6, mixed=mixed) + base.TCP_SEGMENT, nxt=60)
                    self.assertEqual(self.decline(base.make_packet(base.ipv6_frame(packet))), [])

    def test_a_tunnel_behind_the_chain_is_entered_only_within_the_limit(self) -> None:
        # C.f. #1581: the TCP in a 4in4 tunnel is read from the inner IPv4, but
        # only if the chain in front of the tunnel is within the limit.
        from pcapkit.toolkit.pypcapfile import _innermost, _transport

        tcp4 = wire.ipv4(base.TCP_SEGMENT, proto=6)
        for count, entered in ((32, True), (33, False), (1000, False)):
            with self.subTest(count=count), \
                    mock.patch.dict('sys.modules', base.fake_ip_decoder()) as modules:
                IP = modules['pcapfile.protocols.network.ip'].IP
                packet = base.make_packet(base.tunnel(chain(count, 4) + tcp4, 60))
                ipv4, upper = _innermost(packet)
                self.assertIsNone(upper)
                self.assertEqual(IP.calls, [(tcp4, 0)] if entered else [])
                self.assertEqual(_transport(ipv4), base.TCP_SEGMENT if entered else None)
                if not entered:  # no TCP, and none left out either
                    self.assertEqual(self.decline(packet), [])

    def test_a_new_chain_inside_a_tunnel_is_counted_afresh(self) -> None:
        # 20 headers, a tunnel, then 20 more: 40 in the packet, but never more
        # than 20 in a row, so the TCP is found. 33 behind the tunnel are not
        # read past, wherever the count starts.
        tcp4 = base.TCP_SEGMENT
        for count, found in ((20, True), (33, False)):
            with self.subTest(tunnel='6in6', count=count), \
                    mock.patch.dict('sys.modules', base.fake_ip_decoder()):
                inner = wire.ipv6(chain(count, 6) + base.TCP_SEGMENT, nxt=60)
                packet = wire.ipv6(chain(20, 41) + inner, nxt=60)
                messages = self.decline(base.make_packet(base.ipv6_frame(packet)))
                self.assertEqual(len(messages), int(found), messages)
                if found:
                    self.assertTrue(messages[0].startswith('Frame 1: TCP over IPv6 is left out'),
                                    messages)
            with self.subTest(tunnel='4in4', count=count), \
                    mock.patch.dict('sys.modules', base.fake_ip_decoder()):
                from pcapkit.toolkit.pypcapfile import _innermost, _transport

                inner = wire.ipv4(chain(count, 6) + tcp4, proto=60)
                ipv4, _ = _innermost(base.make_packet(base.tunnel(chain(20, 4) + inner, 60)))
                self.assertEqual(_transport(ipv4), tcp4 if found else None)

    def test_ipv4_in_ipv6_is_found_only_within_the_limit(self) -> None:
        from pcapkit.toolkit.pypcapfile import _ipv4_in_ipv6

        inner = base.udp_fragment()
        for count, found in ((32, True), (33, False), (1000, False)):
            with self.subTest(count=count), \
                    mock.patch.dict('sys.modules', base.fake_ip_decoder()) as modules:
                IP = modules['pcapfile.protocols.network.ip'].IP
                frame = base.ipv6_frame(wire.ipv6(chain(count, 4) + inner, nxt=60))
                self.assertEqual(isinstance(_ipv4_in_ipv6(base.make_packet(frame)), IP), found)


if __name__ == '__main__':
    unittest.main()
