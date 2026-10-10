# -*- coding: utf-8 -*-
"""An IPv6 extension header behind a first fragment dissects as without it.

GitHub issue #1539: :class:`~pcapkit.protocols.internet.ipv6.IPv6` ended its
extension header walk at every Fragment header, and handed what followed to the
upper-layer dispatch. That dispatch neither passes ``extension=True`` nor
``version=6``, so Shim6 failed :class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext`'s
version gate, and a zero-filled HIP header or a Routing header of type 3 raised
with no :class:`IPv6_Ext` to stand in. Each became a plain
:class:`~pcapkit.protocols.misc.raw.Raw` leaf, so the TCP behind it was never
dissected, though it was without the Fragment header.

:rfc:`8200#section-4.5` puts every header through the upper-layer one in the
first fragment, at offset zero, so the walk now goes on past its Fragment
header. A later fragment starts with no header at all, and still ends the walk.
The packet split at the Fragment header, which reassembly takes, is unchanged.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import unittest
import warnings

from tests._support import reimport_once_per_class

#: Source and destination addresses.
ADDRS = (bytes.fromhex('20010db8000000000000000000000001')
         + bytes.fromhex('20010db8000000000000000000000002'))

#: A 20-octet TCP header and one octet of payload.
TCP = bytes.fromhex('9c40000900000001000000005000ffff0000000078')

#: Extension headers that :class:`IPv6_Ext` ends up parsing, by name: Next
#: Header code, and the 8-octet header with TCP as its Next Header.
HEADERS = {
    'Shim6': (140, bytes.fromhex('0600000112345678')),
    'HIP (zero-filled)': (139, bytes.fromhex('0600000000000000')),
    'Routing type 3': (43, bytes.fromhex('0600030000000000')),
}

#: The two frames of the issue, as IPv6 datagrams: a Shim6 header behind a
#: first fragment, and the same Shim6 header with no Fragment header.
ISSUE_FRAGMENTED = bytes.fromhex(
    '6000000000252c40' + ADDRS.hex() + '8c00000112345678' + '0600000000000000' + TCP.hex())
ISSUE_DIRECT = bytes.fromhex('60000000001d8c40' + ADDRS.hex() + '0600000000000000' + TCP.hex())


def datagram(code: int, payload: bytes) -> bytes:
    """An IPv6 datagram with Next Header ``code`` and ``payload``."""
    return (bytes.fromhex('60000000') + len(payload).to_bytes(2, 'big')
            + bytes((code, 64)) + ADDRS + payload)


def fragment(code: int, offset: int, more: bool = False) -> bytes:
    """A Fragment header: Next Header ``code``, at ``offset`` 8-octet units."""
    return bytes((code, 0)) + (offset * 8 + more).to_bytes(2, 'big') + bytes.fromhex('9c400009')


class TestIPv6ExtAfterFragment(unittest.TestCase):
    """Pin the walk past a first fragment, and its end at a later one."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        # the zero-filled HIP header warns as it is parsed and rebuilt
        quiet = warnings.catch_warnings()
        quiet.__enter__()  # pylint: disable=unnecessary-dunder-call
        self.addCleanup(quiet.__exit__, None, None, None)
        warnings.filterwarnings('ignore', message='packet length < 0')

    def _parse(self, data: bytes) -> 'object':
        from pcapkit.protocols.internet.ipv6 import IPv6

        ipv6 = IPv6(data)
        self.assertEqual(ipv6.data, data)
        return ipv6

    def assert_rebuilds(self, ipv6: 'object') -> None:
        """``ipv6`` rebuilds byte for byte from its info and its info as a dict."""
        from pcapkit.protocols.internet.ipv6 import IPv6

        self.assertEqual(IPv6.from_data(ipv6.info).data, ipv6.data)
        self.assertEqual(IPv6.from_data(ipv6.info.to_dict()).data, ipv6.data)

    def test_issue_frames(self) -> None:
        direct = self._parse(ISSUE_DIRECT)
        self.assertEqual(str(direct.protochain), 'IPv6:IPv6-Ext:TCP:Raw')

        fragmented = self._parse(ISSUE_FRAGMENTED)
        self.assertIn('TCP', fragmented)
        self.assertEqual(str(fragmented.protochain), 'IPv6:IPv6-Frag:IPv6-Ext:TCP:Raw')
        self.assert_rebuilds(fragmented)

    def test_direct_forms_reach_tcp(self) -> None:
        from pcapkit.const.reg.transtype import TransType

        for name, (code, header) in HEADERS.items():
            with self.subTest(header=name):
                ipv6 = self._parse(datagram(code, header + TCP))
                self.assertIn('TCP', ipv6)
                self.assertEqual(ipv6.info.protocol, TransType.TCP)
                self.assert_rebuilds(ipv6)

    def test_first_fragment_dissects_as_without_it(self) -> None:
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext
        from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag

        for name, (code, header) in HEADERS.items():
            direct = self._parse(datagram(code, header + TCP))
            for more in (False, True):
                with self.subTest(header=name, more=more):
                    ipv6 = self._parse(datagram(44, fragment(code, 0, more) + header + TCP))
                    self.assertIn('TCP', ipv6)
                    exthdr = list(ipv6.extension_headers.values())
                    self.assertEqual([type(ext) for ext in exthdr], [IPv6_Frag, IPv6_Ext])
                    # ``error`` holds an exception, which compares by identity
                    self.assertEqual(repr(exthdr[1].info),
                                     repr(next(iter(direct.extension_headers.values())).info))
                    self.assertEqual(ipv6.info.protocol, direct.info.protocol)
                    self.assertEqual(ipv6.payload.info, direct.payload.info)
                    self.assert_rebuilds(ipv6)

    def test_first_fragment_walks_a_dedicated_header(self) -> None:
        # Destination Options reached TCP behind a first fragment before, but as
        # an upper layer holding it, not as an extension header beside it
        from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        opts = bytes.fromhex('0600010400000000')
        direct = self._parse(datagram(60, opts + TCP))
        ipv6 = self._parse(datagram(44, fragment(60, 0) + opts + TCP))
        self.assertEqual([type(ext) for ext in ipv6.extension_headers.values()],
                         [IPv6_Frag, IPv6_Opts])
        self.assertEqual(ipv6.info.protocol, direct.info.protocol)
        self.assertEqual(ipv6.payload.info, direct.payload.info)
        self.assert_rebuilds(ipv6)

    def test_first_fragment_keeps_the_split(self) -> None:
        # reassembly takes the split at the Fragment header, c.f.
        # ``pcapkit.toolkit.pcap.ipv6_reassembly``
        code, header = HEADERS['Shim6']
        data = datagram(44, fragment(code, 0, True) + header + TCP)
        ipv6 = self._parse(data)
        self.assertEqual(ipv6.info.hdr_len, 48)
        self.assertEqual(ipv6.info.raw_len, len(header + TCP))
        self.assertEqual(ipv6.info.fragment.header, data[:48])
        self.assertEqual(ipv6.info.fragment.payload, header + TCP)

    def test_later_fragment_ends_the_walk(self) -> None:
        from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag

        for name, (code, header) in HEADERS.items():
            with self.subTest(header=name):
                data = datagram(44, fragment(code, 1) + header + TCP)
                ipv6 = self._parse(data)
                self.assertNotIn('TCP', ipv6)
                exthdr = list(ipv6.extension_headers.values())
                self.assertEqual([type(ext) for ext in exthdr], [IPv6_Frag])
                self.assertEqual(int(ipv6.info.protocol), code)
                self.assertEqual(ipv6.info.fragment.payload, header + TCP)
                self.assert_rebuilds(ipv6)


if __name__ == '__main__':
    unittest.main()
