from __future__ import annotations

import importlib.util
import io
import struct
import unittest
import warnings

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


def _udp_bytes(payload: bytes = b'') -> bytes:
    """A minimal, structurally valid UDP datagram (checksum not enforced on read)."""
    return struct.pack('>HHHH', 12345, 53, 8 + len(payload), 0) + payload


def _ipv6_bytes(next_code: int, ext_and_payload: bytes) -> bytes:
    """A minimal IPv6 header (version 6, ``::1`` -> ``::1``) wrapping ``ext_and_payload``."""
    header = struct.pack('>IHBB', 6 << 28, len(ext_and_payload), next_code, 64)
    header += (b'\x00' * 15 + b'\x01') * 2  # src = dst = ::1
    return header + ext_and_payload


def _ipv4_bytes(proto_byte: int, payload: bytes = b'') -> bytes:
    """A minimal, valid IPv4 header (``127.0.0.1`` -> ``127.0.0.1``, no options)."""
    header = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 0, 0, 64, proto_byte, 0,
                         b'\x7f\x00\x00\x01', b'\x7f\x00\x00\x01')
    return header + payload


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPv6GenericExtUnitTests(unittest.TestCase):
    """Tests for GitHub issue #891: a generic RFC 6564 parser for IPv6
    extension headers, so a failed or unimplemented one costs only itself
    rather than the whole packet.
    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    # -- direct construction: the per-protocol length rules -----------------

    def test_generic_rule_applies_to_hopopt_route_opts_mh_hip(self) -> None:
        """RFC 6564 §4: ``(octet[1] + 1) * 8``, for every conformer except
        ``IPv6-Frag`` and ``AH``, which have their own rule (tested below).
        """
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6_generic_ext import IPv6_GenericExt

        for code in (ExtensionHeader.HOPOPT, ExtensionHeader.IPv6_Route,
                     ExtensionHeader.IPv6_Opts, ExtensionHeader.Mobility_Header,
                     ExtensionHeader.HIP):
            with self.subTest(code=code):
                raw = bytes([int(TransType.UDP), 1]) + b'\x00' * 14  # (1+1)*8 == 16
                inst = IPv6_GenericExt(io.BytesIO(raw), len(raw), extension=True,
                                       alias=int(code))
                self.assertEqual(inst.next, TransType.UDP)
                self.assertEqual(inst.length, 16)
                self.assertEqual(inst.protocol, code)

    def test_ah_rule_is_four_octet_units_with_bias_two(self) -> None:
        """RFC 4302 §2.2: ``(octet[1] + 2) * 4``, not RFC 6564's 8-octet units."""
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6_generic_ext import IPv6_GenericExt

        raw = bytes([int(TransType.TCP), 2]) + b'\x00' * 14  # (2+2)*4 == 16
        inst = IPv6_GenericExt(io.BytesIO(raw), len(raw), extension=True,
                               alias=int(ExtensionHeader.AH))
        self.assertEqual(inst.next, TransType.TCP)
        self.assertEqual(inst.length, 16)
        self.assertEqual(inst.protocol, ExtensionHeader.AH)

    def test_frag_rule_is_a_constant_eight_octets(self) -> None:
        """RFC 8200 §4.5: octet[1] is Reserved for IPv6-Frag, not a length --
        the header is always exactly 8 octets regardless of its value.
        """
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6_generic_ext import IPv6_GenericExt

        raw = bytes([int(TransType.UDP), 200]) + b'\x00' * 14  # 200 must be ignored
        inst = IPv6_GenericExt(io.BytesIO(raw), len(raw), extension=True,
                               alias=int(ExtensionHeader.IPv6_Frag))
        self.assertEqual(inst.next, TransType.UDP)
        self.assertEqual(inst.length, 8)
        self.assertEqual(inst.protocol, ExtensionHeader.IPv6_Frag)

    def test_overrun_warns_and_stops_instead_of_clipping(self) -> None:
        """The owner's ruling: warn in the house convention's wording, then
        stop the walk (absorb what remains, report no next header) rather
        than clip-and-continue -- a clipped skip distance would point at
        trailing buffer bytes, not at a header.
        """
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6_generic_ext import IPv6_GenericExt
        from pcapkit.utilities.warnings import SchemaWarning

        # (250 + 1) * 8 == 2008, but only 8 octets are actually available.
        raw = bytes([int(TransType.UDP), 250]) + b'\x00' * 6
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            inst = IPv6_GenericExt(io.BytesIO(raw), len(raw), extension=True,
                                   alias=int(ExtensionHeader.HOPOPT))

        self.assertIsNone(inst.next)
        self.assertEqual(inst.length, len(raw))  # absorbed everything, nothing skipped past
        schema_warnings = [w for w in caught if issubclass(w.category, SchemaWarning)]
        self.assertEqual(len(schema_warnings), 1)
        message = str(schema_warnings[0].message)
        self.assertIn('declares a length of 2008 octet(s)', message)
        self.assertIn('8 octet(s) left in the chain', message)
        self.assertIn('stopping the walk', message)

    # -- __index__ and the guarded extension-mode accessors ------------------

    def test_index_raises_because_no_class_level_identity_exists(self) -> None:
        from pcapkit.protocols.internet.ipv6_generic_ext import IPv6_GenericExt
        from pcapkit.utilities.exceptions import UnsupportedCall

        with self.assertRaises(UnsupportedCall):
            IPv6_GenericExt.__index__()

    def test_extension_mode_blocks_payload_and_protochain_but_not_protocol(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6_generic_ext import IPv6_GenericExt
        from pcapkit.utilities.exceptions import UnsupportedCall

        raw = bytes([int(TransType.UDP), 1]) + b'\x00' * 14
        inst = IPv6_GenericExt(io.BytesIO(raw), len(raw), extension=True,
                               alias=int(ExtensionHeader.HOPOPT))

        with self.assertRaises(UnsupportedCall):
            _ = inst.payload
        with self.assertRaises(UnsupportedCall):
            _ = inst.protochain

        # unlike the base ``Protocol.protocol`` meaning, this is the
        # instance's own identity and stays readable regardless of ``_extf``.
        self.assertEqual(inst.protocol, ExtensionHeader.HOPOPT)
        self.assertEqual(inst.next, TransType.UDP)
        self.assertEqual(inst.length, 16)

    # -- round trip: make()/_make_data() invert the same rule ----------------

    def test_make_and_make_data_round_trip_the_generic_and_ah_rules(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6_generic_ext import IPv6_GenericExt

        for code, len_octet, total in (
            (ExtensionHeader.HOPOPT, 1, 16),
            (ExtensionHeader.AH, 2, 16),
            (ExtensionHeader.IPv6_Frag, 0, 8),
        ):
            with self.subTest(code=code):
                raw = bytes([int(TransType.UDP), len_octet]) + b'\x00' * (total - 2)
                inst = IPv6_GenericExt(io.BytesIO(raw), len(raw), extension=True,
                                       alias=int(code))
                values = IPv6_GenericExt._make_data(inst.info)
                self.assertEqual(values['next'], TransType.UDP)
                self.assertEqual(values['len'], len_octet)

    # -- entry path 2: a recognised header's own parser raises ---------------

    def test_mh_own_parser_failure_falls_back_and_chain_reaches_real_udp(self) -> None:
        """The actual #891 defect, with real bytes after the bad header this
        time: proves the walk does not merely avoid crashing but genuinely
        resumes at the real next layer.
        """
        from pcapkit.const.mh.packet import Packet
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.internet.ipv6_generic_ext import IPv6_GenericExt
        from pcapkit.protocols.internet.mh import MH, FastBindingAcknowledgmentStatus
        from pcapkit.protocols.transport.udp import UDP

        mh_raw = bytearray(bytes(MH(
            next=TransType.UDP, chksum=b'\x12\x34', type=Packet.Fast_Binding_Acknowledgment,
            data={'status': FastBindingAcknowledgmentStatus.Insufficient_resources,
                  'key_mngt': True, 'seq': 0x1234, 'lifetime': 40, 'options': []})))
        mh_raw[6] = 50  # unassigned FastBindingAcknowledgmentStatus byte -- MH.read raises

        udp_payload = _udp_bytes(b'hello')
        raw = _ipv6_bytes(int(TransType.Mobility_Header), bytes(mh_raw) + udp_payload)
        ipv6 = IPv6(io.BytesIO(raw), len(raw))

        exthdrs = list(ipv6.extension_headers.items(multi=True))
        self.assertEqual(len(exthdrs), 1)
        genext = exthdrs[0][1]
        self.assertIsInstance(genext, IPv6_GenericExt)
        self.assertEqual(genext.next, TransType.UDP)
        self.assertEqual(genext.length, len(mh_raw))
        self.assertIsInstance(genext.info.error, Exception)

        self.assertIsInstance(ipv6.payload, UDP)
        self.assertEqual(bytes(ipv6.payload.payload), b'hello')
        self.assertEqual(str(ipv6.protochain), 'IPv6:IPv6-GenericExt:UDP:Raw')

    def test_overrun_inside_a_real_chain_stops_the_walk_honestly(self) -> None:
        """Same failing MH message, but its own ``Header Len`` octet is also
        corrupted to a value the generic fallback cannot trust either --
        the walk must warn and stop, not invent a layer from trailing bytes.
        """
        from pcapkit.const.mh.packet import Packet
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.internet.ipv6_generic_ext import IPv6_GenericExt
        from pcapkit.protocols.internet.mh import MH, FastBindingAcknowledgmentStatus
        from pcapkit.utilities.warnings import SchemaWarning

        mh_raw = bytearray(bytes(MH(
            next=TransType.UDP, chksum=b'\x12\x34', type=Packet.Fast_Binding_Acknowledgment,
            data={'status': FastBindingAcknowledgmentStatus.Insufficient_resources,
                  'key_mngt': True, 'seq': 0x1234, 'lifetime': 40, 'options': []})))
        mh_raw[6] = 50    # MH.read raises
        mh_raw[1] = 250   # and the generic fallback's own length would overrun

        trailing = _udp_bytes(b'should-not-be-reached')
        raw = _ipv6_bytes(int(TransType.Mobility_Header), bytes(mh_raw) + trailing)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            ipv6 = IPv6(io.BytesIO(raw), len(raw))

        self.assertTrue(any(issubclass(w.category, SchemaWarning) for w in caught))

        exthdrs = list(ipv6.extension_headers.items(multi=True))
        self.assertEqual(len(exthdrs), 1)
        genext = exthdrs[0][1]
        self.assertIsInstance(genext, IPv6_GenericExt)
        self.assertIsNone(genext.next)
        # absorbed everything, including the bytes that would have been a
        # perfectly good UDP datagram -- the point is that it is not trusted
        self.assertEqual(genext.length, len(mh_raw) + len(trailing))
        self.assertEqual(str(ipv6.protochain), 'IPv6:IPv6-GenericExt')

    # -- entry path 1: an unrecognised protocol number (Shim6) ---------------

    def test_shim6_has_no_dedicated_parser_and_dispatches_directly(self) -> None:
        """``Shim6`` (140) is a real IANA extension header this package has
        never implemented, so it used to default to plain ``Raw`` via
        ``Internet.__proto__``'s defaultdict -- registered here directly
        instead, so no exception is even involved.
        """
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.internet.ipv6_generic_ext import IPv6_GenericExt

        self.assertIs(Internet.__proto__[TransType.Shim6], IPv6_GenericExt)

    def test_shim6_packet_parses_generically_and_chain_reaches_real_udp(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.internet.ipv6_generic_ext import IPv6_GenericExt
        from pcapkit.protocols.transport.udp import UDP

        shim6_ext = bytes([int(TransType.UDP), 1]) + b'\x00' * 14  # 16 octets, generic rule
        udp_payload = _udp_bytes(b'shim6-ok')
        raw = _ipv6_bytes(int(ExtensionHeader.Shim6), shim6_ext + udp_payload)
        ipv6 = IPv6(io.BytesIO(raw), len(raw))

        exthdrs = list(ipv6.extension_headers.items(multi=True))
        self.assertEqual(len(exthdrs), 1)
        code, genext = exthdrs[0]
        self.assertEqual(code, ExtensionHeader.Shim6)
        self.assertIsInstance(genext, IPv6_GenericExt)
        self.assertIsNone(genext.info.error)  # direct dispatch, not a beholder fallback
        self.assertIsInstance(ipv6.payload, UDP)
        self.assertEqual(bytes(ipv6.payload.payload), b'shim6-ok')
        self.assertEqual(str(ipv6.protochain), 'IPv6:IPv6-GenericExt:UDP:Raw')

    # -- alias, so the packet dict and the chain segment are not '_genericext' --

    def test_alias_is_hyphenated_like_its_siblings(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6_generic_ext import IPv6_GenericExt

        raw = bytes([int(TransType.UDP), 1]) + b'\x00' * 14
        inst = IPv6_GenericExt(io.BytesIO(raw), len(raw), extension=True,
                               alias=int(ExtensionHeader.HOPOPT))
        self.assertEqual(inst.alias, 'IPv6-GenericExt')
        # this is exactly the computation ``IPv6._decode_next_layer`` performs
        # to key its packet dict -- ``str.lstrip`` strips a character *set*,
        # so the hyphen matters, not just the dash-free text either side of it.
        self.assertEqual(inst.alias.lstrip('IPv6-').lower(), 'genericext')

    # -- the version gate: this class only ever activates for IPv6 ----------

    def test_version_gate_rejects_non_ipv6_construction(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6_generic_ext import IPv6_GenericExt
        from pcapkit.utilities.exceptions import ProtocolError

        raw = bytes([int(TransType.UDP), 1]) + b'\x00' * 14
        with self.assertRaises(ProtocolError):
            IPv6_GenericExt(io.BytesIO(raw), len(raw), version=4, extension=True,
                            alias=int(ExtensionHeader.HOPOPT))

    def test_shim6_registration_does_not_leak_into_ipv4_parsing(self) -> None:
        """GitHub issue #891 cross-review: registering ``IPv6_GenericExt``
        into the shared ``Internet.__proto__`` for Shim6 must not make an
        IPv4 packet whose protocol byte happens to be 140 walk an IPv6-style
        extension-header chain. The version gate on ``__post_init__`` sends
        construction back through the caller's own ``@beholder``, which
        restores exactly the pre-existing ``Raw`` fallback -- verified
        against a real :class:`~pcapkit.protocols.internet.ipv4.IPv4` packet,
        not just the class in isolation.
        """
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.misc.raw import Raw

        raw = _ipv4_bytes(int(TransType.Shim6), b'\x11\x01' + b'\x00' * 14)
        ipv4 = IPv4(io.BytesIO(raw), len(raw))

        self.assertIsInstance(ipv4.payload, Raw)
        # the enum member's own name, not a chain walked out of an IPv4
        # payload -- this is the exact pre-#891-registration rendering.
        self.assertEqual(str(ipv4.protochain), 'IPv4:Shim6')

    # -- item 1 (cross-review): an unimplemented terminal code must not ------
    # -- collapse the whole packet -------------------------------------------

    def test_unimplemented_terminal_code_stops_the_walk_not_the_packet(self) -> None:
        """``BIT-EMU`` (147) has no dedicated parser and is not one of the
        RFC 6564 conformers, so it resolves to plain :class:`Raw`, whose
        info carries no ``next`` -- the exact #891 signature if the walk
        read ``info.next`` on it unconditionally. The structural check in
        :meth:`IPv6._decode_next_layer
        <pcapkit.protocols.internet.ipv6.IPv6._decode_next_layer>` must stop
        there instead, keeping this packet's own header (source, destination,
        hop limit) intact rather than losing it to a further-out
        ``@beholder``. ``253``/``254`` are the same code path (also
        unregistered, also resolve to ``Raw``); this file covers one to keep
        the test proportionate, per the review's own framing.
        """
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.misc.raw import Raw

        raw = _ipv6_bytes(int(TransType.BIT_EMU), b'\x11\x01' + b'\x00' * 14)
        ipv6 = IPv6(io.BytesIO(raw), len(raw))

        # the header this class exists to protect -- lost entirely under the
        # pre-#891 defect, since the whole IPv6 layer became a bare ``Raw``.
        self.assertEqual(str(ipv6.src), '::1')
        self.assertEqual(str(ipv6.dst), '::1')

        exthdrs = list(ipv6.extension_headers.items(multi=True))
        self.assertEqual(len(exthdrs), 1)
        code, terminal = exthdrs[0]
        self.assertEqual(code, ExtensionHeader.BIT_EMU)
        self.assertIsInstance(terminal, Raw)

        self.assertIsInstance(ipv6.payload, Raw)
        self.assertEqual(str(ipv6.protochain), 'IPv6:Raw:Raw')
