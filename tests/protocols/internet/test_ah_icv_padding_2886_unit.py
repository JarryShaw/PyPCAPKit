# -*- coding: utf-8 -*-
"""GitHub issue #2886: ``AH.make`` pads the ICV rather than cutting it.

RFC 4302 section 2.6 has the ICV field carry the padding that makes the header
a multiple of 32 bits under IPv4 or 64 bits under IPv6, section 3.3.3.2.1 allows
only the minimum, and section 2.2 counts it in Payload Length. ``make`` cut the
octets past a multiple of four instead, and wrapped Payload Length past 255. An
IPv6 extension header, ``extension=True``, is aligned for IPv6, and ``IPv6.make``
refuses one in its chain that is not a multiple of 8 octets (RFC 8200 section 4).

The expected lengths are derived here from the RFC, not from ``make``. Every case
builds its own octets in memory and reads no capture.

"""

from __future__ import annotations

import io
import struct
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Octets of the fixed fields ahead of the ICV (RFC 4302 section 2).
FIXED = 12

#: Construction keywords, and the header alignment in octets they ask for
#: (RFC 4302 section 2.6): an extension header is IPv6's, whatever ``version``.
MODES = (
    ({'version': 4}, 4),
    ({'version': 6}, 8),
    ({'extension': True}, 8),
    ({'version': 4, 'extension': True}, 8),
)


def aligned(size: int, align: int) -> int:
    """The smallest multiple of ``align`` not below ``size``."""
    return (size + align - 1) // align * align


def ah_header(size: int, nxt: int = 59) -> bytes:
    """A captured AH header of ``size`` octets, its ICV field patterned."""
    icv = bytes(index % 251 + 1 for index in range(size - FIXED))
    return struct.pack('!BBHII', nxt, size // 4 - 2, 0, 0x1234, 1) + icv


def ipv6_packet(body: bytes, first: int = 51) -> bytes:
    """An IPv6 header carrying ``body``, its first Next Header ``first``."""
    return struct.pack('!IHBB', 6 << 28, len(body), first, 64) + bytes(32) + body


class AHICVPaddingTests(unittest.TestCase):
    """ICVs of every length to 17 octets, in every alignment mode."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def make(self, icv: bytes, **kwargs: object) -> bytes:
        from pcapkit.protocols.internet.ah.protocol import AH

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return AH.from_fields(next=59, spi=0x1234, seq=7, icv=icv, **kwargs).data

    def test_icv_is_kept_whole_and_padded_to_the_minimum(self) -> None:
        for kwargs, align in MODES:
            for size in range(18):
                icv = bytes(range(1, size + 1))
                total = aligned(FIXED + size, align)
                with self.subTest(**kwargs, icv=size):
                    made = self.make(icv, **kwargs)
                    self.assertEqual(len(made), total)
                    self.assertEqual(made[1], total // 4 - 2)  # section 2.2: 32-bit words, minus 2
                    self.assertEqual(made[FIXED:], icv + bytes(total - FIXED - size))
                    self.assertLess(total - FIXED - size, align)

    def test_make_parse_and_from_data_are_byte_exact(self) -> None:
        from pcapkit.protocols.internet.ah.protocol import AH

        for kwargs, align in MODES:
            parse = {'version': 6, 'extension': True} if align == 8 else {}
            for size in range(18):
                icv = bytes(range(1, size + 1))
                with self.subTest(**kwargs, icv=size), warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    made = self.make(icv, **kwargs)
                    parsed = AH(io.BytesIO(made), len(made), **parse)
                    self.assertEqual(parsed.data, made)
                    self.assertEqual(parsed.info.length, len(made))
                    self.assertEqual(parsed.info.icv[:size], icv)
                    self.assertEqual(parsed.info.icv, made[FIXED:])
                    self.assertEqual(AH.from_data(parsed.info).data, made)

    def test_a_96_bit_icv_needs_no_padding(self) -> None:
        # Section 2.2's example, which section 3.3.3.2.1 says pads under neither version.
        for kwargs, _ in MODES:
            with self.subTest(**kwargs):
                made = self.make(b'\xab' * 12, **kwargs)
                self.assertEqual((len(made), made[1]), (24, 4))

    def test_padding_already_given_is_kept(self) -> None:
        icv = b'\x11' * 12 + b'\xee' * 4
        self.assertEqual(self.make(icv, version=4)[FIXED:], icv)

    def test_payload_length_limit(self) -> None:
        from pcapkit.protocols.internet.ah.protocol import AH
        from pcapkit.utilities.exceptions import ProtocolError

        # Payload Length's 8 bits count at most 257 words, 1028 octets; 1024 under IPv6.
        for kwargs, most, ip in (({'version': 4}, 1016, 4), ({'version': 6}, 1012, 6),
                                 ({'extension': True}, 1012, 6)):
            with self.subTest(**kwargs):
                self.assertEqual(len(self.make(bytes(most), **kwargs)), most + FIXED)
                with self.assertRaises(ProtocolError) as caught:
                    AH.from_fields(icv=bytes(most + 1), **kwargs)
                self.assertEqual(str(caught.exception), f'AH: invalid ICV length: must be at most {most} '
                                                        f'octets under IPv{ip}, not {most + 1}')

    def test_version_other_than_4_or_6_is_refused(self) -> None:
        from pcapkit.protocols.internet.ah.protocol import AH
        from pcapkit.utilities.exceptions import ProtocolError

        for version in (5, True, None):
            with self.subTest(version=version):
                with self.assertRaises(ProtocolError) as caught:
                    AH.from_fields(icv=bytes(2), version=version)
                self.assertEqual(str(caught.exception), f'AH: invalid version: must be 4 or 6, not {version!r}')


class AHPayloadLengthTests(unittest.TestCase):
    """A given Payload Length describes ``icv`` exactly, so a captured header rebuilds as captured."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_an_exact_payload_length_is_written_as_given(self) -> None:
        from pcapkit.protocols.internet.ah.protocol import AH

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            # 28 octets as an extension header: not aligned for IPv6, but asked for.
            made = AH.from_fields(next=59, icv=b'\x01' * 16, payload_length=5, extension=True).data
        self.assertEqual((len(made), made[1], made[FIXED:]), (28, 5, b'\x01' * 16))

    def test_a_payload_length_not_describing_the_icv_is_refused(self) -> None:
        from pcapkit.protocols.internet.ah.protocol import AH
        from pcapkit.utilities.exceptions import ProtocolError

        # Section 3.3.3.2.1 prohibits padding past the minimum, so none is added to fit.
        exact = 'AH: invalid payload length: must describe the {}-octet ICV exactly, not {}'
        for icv, length, message in ((4, 9, exact.format(4, 9)),     # 44 octets: 28 past the ICV
                                     (1, 4, exact.format(1, 4)),     # 24 octets: 11 past it
                                     (16, 4, exact.format(16, 4)),
                                     (16, 0, exact.format(16, 0)),
                                     (16, 256, 'AH: invalid payload length: 256')):
            with self.subTest(icv=icv, payload_length=length):
                with self.assertRaises(ProtocolError) as caught:
                    AH.from_fields(icv=bytes(icv), payload_length=length)
                self.assertEqual(str(caught.exception), message)

    def test_a_captured_extension_header_rebuilds_as_captured(self) -> None:
        from pcapkit.protocols.internet.ah.protocol import AH

        # Parsed as IPv6 walks a chain; from_data then rebuilds with extension=True.
        for size in (12, 16, 20, 24, 28, 1028):
            header = ah_header(size)
            with self.subTest(size=size), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                parsed = AH(io.BytesIO(header), len(header), version=6, extension=True)
                self.assertEqual(AH.from_data(parsed.info).data, header)


class AHInIPv6Tests(unittest.TestCase):
    """IPv6 refuses a chained header that is not a multiple of 8 octets (RFC 8200 section 4)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_an_extension_header_is_aligned_and_rebuilds(self) -> None:
        from pcapkit.protocols.internet.ah.protocol import AH
        from pcapkit.protocols.internet.ipv6.protocol import IPv6

        for kwargs in ({'version': 6}, {'extension': True}):
            with self.subTest(**kwargs), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                # A 128-bit ICV leaves 28 octets, so IPv6 pads it to 32.
                made = IPv6.from_fields(next=51, payload=AH.from_fields(next=59, icv=b'\xcd' * 16, **kwargs)).data
                parsed = IPv6(io.BytesIO(made), len(made))
                (ah,) = [ext for ext in parsed.extension_headers.values() if isinstance(ext, AH)]
                self.assertEqual(ah.info.length, 32)
                self.assertEqual(ah.info.icv, b'\xcd' * 16 + bytes(4))
                self.assertEqual(IPv6.from_data(parsed.info).data, made)

    def test_a_misaligned_header_in_the_chain_is_refused(self) -> None:
        from pcapkit.protocols.internet.ah.protocol import AH
        from pcapkit.protocols.internet.hopopt.protocol import HOPOPT
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.utilities.exceptions import ProtocolError

        cases = {
            'plain AH': (51, lambda: AH.from_fields(next=59, icv=bytes(16))),
            'behind HOPOPT': (0, lambda: HOPOPT.from_fields(next=51, payload=AH.from_fields(next=59, icv=bytes(16)))),
            'given payload length': (51, lambda: AH.from_fields(next=59, icv=bytes(16), payload_length=5, extension=True)),
        }
        for label, (first, build) in cases.items():
            with self.subTest(case=label), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                payload = build()
                with self.assertRaises(ProtocolError) as caught:
                    IPv6.from_fields(next=first, payload=payload)
                self.assertEqual(str(caught.exception),
                                 'IPv6: invalid AH header length: must be a multiple of 8 octets, not 28')

    def test_what_a_receiver_does_not_walk_is_not_checked(self) -> None:
        from pcapkit.protocols.internet.ah.protocol import AH
        from pcapkit.protocols.internet.esp.protocol import ESP
        from pcapkit.protocols.internet.ipv6.protocol import IPv6

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            # ESP runs to the end of the packet, padded to 4 octets (RFC 4303 section 2.4).
            esp = IPv6.from_fields(next=50, payload=ESP.from_fields(spi=1, seq=1, payload=b'abcd')).data
            # A 20-octet AH given as octets, as IPv6._make_data rebuilds a captured chain.
            raw = IPv6.from_fields(next=51, payload=ah_header(20)).data
            # Next Header 17 names UDP, so a receiver reads no extension header there.
            udp = IPv6.from_fields(next=17, payload=AH.from_fields(next=59, icv=bytes(16))).data
        self.assertEqual(len(esp), 40 + 12)
        self.assertEqual(raw[40:], ah_header(20))
        self.assertEqual(len(udp), 40 + 28)

    def test_a_captured_header_is_not_padded_again(self) -> None:
        from pcapkit.protocols.internet.ipv6.protocol import IPv6

        # 20 and 28 octets: multiples of 32 bits but not of 64, kept as captured.
        for size in (20, 28):
            packet = ipv6_packet(ah_header(size))
            with self.subTest(size=size), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                parsed = IPv6(io.BytesIO(packet), len(packet))
                self.assertEqual(IPv6.from_data(parsed.info).data, packet)


if __name__ == '__main__':
    unittest.main()
