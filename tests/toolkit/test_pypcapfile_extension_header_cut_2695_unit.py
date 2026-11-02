# -*- coding: utf-8 -*-
"""GitHub issue #2695: pypcapfile's extension-header reader keeps a header cut short of its length.

:func:`~pcapkit.toolkit.pypcapfile._default_extension_header` answers
:data:`None` for a header captured shorter than its parser's
``__length_hint__``. A header captured at least that long is kept with the
length it declares, cut short of that length or not, as pcapkit's own IPv4
dissection keeps it. The length then runs past the octets, so
:func:`~pcapkit.toolkit.pypcapfile._walk_extension_headers` steps over the cut
header and leaves no octets after it.

Each header is cut at every offset short of its declared length. The answers
are cached by octets, so each case clears the cache before it asks. Every
value is built here, so the module is in the unit tier.

"""

import struct
import unittest
import warnings

#: IP protocol numbers of the IPv6 Routing Header and the Mobility Header.
IPV6_ROUTE, MOBILITY_HEADER = 43, 135
#: The Next Header fields the headers below carry: TCP and UDP.
TCP, UDP = 6, 17
#: The shortest header each parser reads, its ``__length_hint__``.
HINT = 8
#: Each header below declares 24 octets, as a Hdr Ext Len or Header Len of 2
#: gives (RFC 8200 section 4.4, RFC 6275 section 6.1.1).
DECLARED = 24
#: A Mobility Header carrying a Binding Error message, then an IPv6 Routing
#: Header of type 2 carrying one address, each with its protocol number and
#: Next Header field.
HEADERS = {
    'MH': (MOBILITY_HEADER, UDP, bytes.fromhex('11020742d5bd297b') + bytes(range(1, 17))),
    'IPv6-Route': (IPV6_ROUTE, TCP, bytes([TCP, 2, 2, 1, 0, 0, 0, 0]) + bytes(range(1, 17))),
}


def _ipv4(protocol: 'int', payload: 'bytes') -> 'bytes':
    """An IPv4 packet of 20 octets of header carrying ``payload`` as ``protocol``."""
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, protocol, 0,
                       bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])) + payload


class TestCutExtensionHeader(unittest.TestCase):
    """Pin what the reader and the walker answer for a header cut short."""

    def _ask(self, protocol: 'int', data: 'bytes') -> 'object':
        """Ask the uncached reader about ``data``, with its warnings ignored."""
        from pcapkit.toolkit.pypcapfile import \
            _default_extension_header  # pylint: disable=import-outside-toplevel

        _default_extension_header.cache_clear()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return _default_extension_header(protocol, data)

    def _walk(self, protocol: 'int', data: 'bytes') -> 'object':
        """Walk ``data`` with the reader uncached, with its warnings ignored."""
        from pcapkit.toolkit.pypcapfile import \
            _default_extension_header  # pylint: disable=import-outside-toplevel
        from pcapkit.toolkit.pypcapfile import \
            _walk_extension_headers  # pylint: disable=import-outside-toplevel

        _default_extension_header.cache_clear()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return _walk_extension_headers(protocol, data)

    def _dissected(self, protocol: 'int', data: 'bytes') -> 'object':
        """The layer pcapkit's own IPv4 dissection makes of ``data``."""
        from pcapkit.protocols.internet.ipv4 import IPv4  # pylint: disable=import-outside-toplevel

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return IPv4(_ipv4(protocol, data)).payload

    def test_header_short_of_its_hint_answers_none(self) -> None:
        """A header captured shorter than its hint answers ``None``, and the walk stops on it."""
        for name, (protocol, _, whole) in HEADERS.items():
            for cut in range(HINT):
                with self.subTest(header=name, octets=cut):
                    self.assertIsNone(self._ask(protocol, whole[:cut]))
                    self.assertIsNone(self._walk(protocol, whole[:cut]))

    def test_header_cut_short_of_its_length_is_kept(self) -> None:
        """A header captured from its hint up is kept, with the length it declares."""
        for name, (protocol, nxt, whole) in HEADERS.items():
            self.assertEqual(len(whole), DECLARED)
            for cut in range(HINT, DECLARED + 1):
                with self.subTest(header=name, octets=cut):
                    self.assertEqual(self._ask(protocol, whole[:cut]), (nxt, DECLARED))

    def test_walk_steps_over_a_cut_header_to_no_octets(self) -> None:
        """The walk steps over a kept header by its declared length, so no octets follow it."""
        for name, (protocol, nxt, whole) in HEADERS.items():
            for cut in range(HINT, DECLARED):
                with self.subTest(header=name, octets=cut):
                    self.assertEqual(self._walk(protocol, whole[:cut]), (nxt, b'', 1))
            with self.subTest(header=name, octets='whole, then a payload'):
                self.assertEqual(self._walk(protocol, whole + b'payload'), (nxt, b'payload', 1))

    def test_ipv4_dissection_agrees(self) -> None:
        """pcapkit's own IPv4 dissection keeps the same cut headers, with the same length."""
        from pcapkit.protocols.misc.raw import Raw  # pylint: disable=import-outside-toplevel

        for name, (protocol, _, whole) in HEADERS.items():
            for cut in range(1, DECLARED):
                with self.subTest(header=name, octets=cut):
                    layer = self._dissected(protocol, whole[:cut])
                    answer = self._ask(protocol, whole[:cut])
                    self.assertEqual(isinstance(layer, Raw), answer is None)
                    if answer is not None:
                        self.assertEqual(layer.length, answer[1])


if __name__ == '__main__':
    unittest.main()
