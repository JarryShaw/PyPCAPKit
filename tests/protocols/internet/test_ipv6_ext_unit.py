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
class IPv6ExtUnitTests(unittest.TestCase):
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
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext

        for code in (ExtensionHeader.HOPOPT, ExtensionHeader.IPv6_Route,
                     ExtensionHeader.IPv6_Opts, ExtensionHeader.Mobility_Header,
                     ExtensionHeader.HIP):
            with self.subTest(code=code):
                raw = bytes([int(TransType.UDP), 1]) + b'\x00' * 14  # (1+1)*8 == 16
                inst = IPv6_Ext(io.BytesIO(raw), len(raw), extension=True,
                                alias=int(code))
                self.assertEqual(inst.next, TransType.UDP)
                self.assertEqual(inst.length, 16)
                self.assertEqual(inst.protocol, code)

    def test_ah_rule_is_four_octet_units_with_bias_two(self) -> None:
        """RFC 4302 §2.2: ``(octet[1] + 2) * 4``, not RFC 6564's 8-octet units."""
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext

        raw = bytes([int(TransType.TCP), 2]) + b'\x00' * 14  # (2+2)*4 == 16
        inst = IPv6_Ext(io.BytesIO(raw), len(raw), extension=True,
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
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext

        raw = bytes([int(TransType.UDP), 200]) + b'\x00' * 14  # 200 must be ignored
        inst = IPv6_Ext(io.BytesIO(raw), len(raw), extension=True,
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
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext
        from pcapkit.utilities.warnings import SchemaWarning

        # (250 + 1) * 8 == 2008, but only 8 octets are actually available.
        raw = bytes([int(TransType.UDP), 250]) + b'\x00' * 6
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            inst = IPv6_Ext(io.BytesIO(raw), len(raw), extension=True,
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
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext
        from pcapkit.utilities.exceptions import UnsupportedCall

        with self.assertRaises(UnsupportedCall):
            IPv6_Ext.__index__()

    def test_extension_mode_blocks_payload_and_protochain_but_not_protocol(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext
        from pcapkit.utilities.exceptions import UnsupportedCall

        raw = bytes([int(TransType.UDP), 1]) + b'\x00' * 14
        inst = IPv6_Ext(io.BytesIO(raw), len(raw), extension=True,
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
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext

        for code, len_octet, total in (
            (ExtensionHeader.HOPOPT, 1, 16),
            (ExtensionHeader.AH, 2, 16),
            (ExtensionHeader.IPv6_Frag, 0, 8),
        ):
            with self.subTest(code=code):
                raw = bytes([int(TransType.UDP), len_octet]) + b'\x00' * (total - 2)
                inst = IPv6_Ext(io.BytesIO(raw), len(raw), extension=True,
                                alias=int(code))
                values = IPv6_Ext._make_data(inst.info)
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
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext
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
        self.assertIsInstance(genext, IPv6_Ext)
        self.assertEqual(genext.next, TransType.UDP)
        self.assertEqual(genext.length, len(mh_raw))
        self.assertIsInstance(genext.info.error, Exception)

        self.assertIsInstance(ipv6.payload, UDP)
        self.assertEqual(bytes(ipv6.payload.payload), b'hello')
        self.assertEqual(str(ipv6.protochain), 'IPv6:IPv6-Ext:UDP:Raw')

    def test_overrun_inside_a_real_chain_stops_the_walk_honestly(self) -> None:
        """Same failing MH message, but its own ``Header Len`` octet is also
        corrupted to a value the generic fallback cannot trust either --
        the walk must warn and stop, not invent a layer from trailing bytes.
        """
        from pcapkit.const.mh.packet import Packet
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext
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
        self.assertIsInstance(genext, IPv6_Ext)
        self.assertIsNone(genext.next)
        # absorbed everything, including the bytes that would have been a
        # perfectly good UDP datagram -- the point is that it is not trusted
        self.assertEqual(genext.length, len(mh_raw) + len(trailing))
        self.assertEqual(str(ipv6.protochain), 'IPv6:IPv6-Ext')

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
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext

        self.assertIs(Internet.__proto__[TransType.Shim6], IPv6_Ext)

    def test_shim6_packet_parses_generically_and_chain_reaches_real_udp(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext
        from pcapkit.protocols.transport.udp import UDP

        shim6_ext = bytes([int(TransType.UDP), 1]) + b'\x00' * 14  # 16 octets, generic rule
        udp_payload = _udp_bytes(b'shim6-ok')
        raw = _ipv6_bytes(int(ExtensionHeader.Shim6), shim6_ext + udp_payload)
        ipv6 = IPv6(io.BytesIO(raw), len(raw))

        exthdrs = list(ipv6.extension_headers.items(multi=True))
        self.assertEqual(len(exthdrs), 1)
        code, genext = exthdrs[0]
        self.assertEqual(code, ExtensionHeader.Shim6)
        self.assertIsInstance(genext, IPv6_Ext)
        self.assertIsNone(genext.info.error)  # direct dispatch, not a beholder fallback
        self.assertIsInstance(ipv6.payload, UDP)
        self.assertEqual(bytes(ipv6.payload.payload), b'shim6-ok')
        self.assertEqual(str(ipv6.protochain), 'IPv6:IPv6-Ext:UDP:Raw')

    # -- alias, so the packet dict and the chain segment are not '_ext' -------

    def test_alias_is_hyphenated_like_its_siblings(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext

        raw = bytes([int(TransType.UDP), 1]) + b'\x00' * 14
        inst = IPv6_Ext(io.BytesIO(raw), len(raw), extension=True,
                        alias=int(ExtensionHeader.HOPOPT))
        self.assertEqual(inst.alias, 'IPv6-Ext')
        # this is exactly the computation ``IPv6._decode_next_layer`` performs
        # to key its packet dict -- ``str.lstrip`` strips a character *set*,
        # so the hyphen matters, not just the dash-free text either side of it.
        self.assertEqual(inst.alias.lstrip('IPv6-').lower(), 'ext')

    # -- the version gate: this class only ever activates for IPv6 ----------

    def test_version_gate_rejects_non_ipv6_construction(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext
        from pcapkit.utilities.exceptions import ProtocolError

        raw = bytes([int(TransType.UDP), 1]) + b'\x00' * 14
        with self.assertRaises(ProtocolError):
            IPv6_Ext(io.BytesIO(raw), len(raw), version=4, extension=True,
                     alias=int(ExtensionHeader.HOPOPT))

    def test_shim6_registration_does_not_leak_into_ipv4_parsing(self) -> None:
        """GitHub issue #891 cross-review: registering ``IPv6_Ext``
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
        """``253`` (``Use for experimentation and testing``, :rfc:`3692`) has
        no dedicated parser in this package and is not one of the RFC 6564
        conformers, so it resolves to plain :class:`Raw`, whose info carries
        no ``next`` -- the exact #891 signature if the walk read
        ``info.next`` on it unconditionally. The structural check in
        :meth:`IPv6._decode_next_layer
        <pcapkit.protocols.internet.ipv6.IPv6._decode_next_layer>` must stop
        there instead, keeping this packet's own header (source, destination,
        hop limit) intact rather than losing it to a further-out
        ``@beholder``. ``254`` is the same code path (also has no dedicated
        parser, also resolves to ``Raw``); this file covers one to keep the
        test proportionate, per the review's own framing.

        GitHub issue #925: this used to pick ``BIT-EMU`` (147) for the
        example. Unlike 253/254, 147 turned out not to be in IANA's
        authoritative *IPv6 Extension Header Types* registry at all -- it
        leaked in from a stale cross-reference in the *Protocol Numbers*
        registry -- and :class:`~pcapkit.const.ipv6.extension_header.
        ExtensionHeader` no longer carries it. 253 exercises the identical
        code path (an extension-header code this package has not
        implemented a dedicated parser for) while remaining a code IANA
        actually recognises as one, which 147 no longer is.
        """
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.misc.raw import Raw

        code_253 = TransType.Use_for_experimentation_and_testing_253
        raw = _ipv6_bytes(int(code_253), b'\x11\x01' + b'\x00' * 14)
        ipv6 = IPv6(io.BytesIO(raw), len(raw))

        # the header this class exists to protect -- lost entirely under the
        # pre-#891 defect, since the whole IPv6 layer became a bare ``Raw``.
        self.assertEqual(str(ipv6.src), '::1')
        self.assertEqual(str(ipv6.dst), '::1')

        exthdrs = list(ipv6.extension_headers.items(multi=True))
        self.assertEqual(len(exthdrs), 1)
        code, terminal = exthdrs[0]
        self.assertEqual(code, ExtensionHeader.Use_for_experimentation_and_testing_253)
        self.assertIsInstance(terminal, Raw)

        self.assertIsInstance(ipv6.payload, Raw)
        self.assertEqual(str(ipv6.protochain), 'IPv6:Raw:Raw')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPv6ExtSharedBaseContractTests(unittest.TestCase):
    """Tests for GitHub issue #917: ``IPv6_Ext`` serves two roles at once --
    the shared base of every IPv6 extension header, *and* the concrete
    fallback parser for one this package does not implement.

    That merge removes a safety net. Before it, each of the eight implemented
    headers inherited :class:`~pcapkit.protocols.internet.internet.Internet`
    directly, whose ``name``/``alias``/``protocol``/``length`` are generic or
    abstract and whose ``__index__`` is :func:`abc.abstractmethod` -- so
    forgetting one was loud. After it, the same omission silently inherits this
    module's own *fallback-role* answers, which are wrong for a header that has
    an identity: it reports itself as ``IPv6 Extension Header`` / ``IPv6-Ext``,
    reads its length off a data model that is not its own, and ``__index__``
    raises instead of returning its IANA number.

    The eight are correct today only because all eight happen to shadow every
    one of those members. Nothing in the language enforces that, so this class
    does -- over every subclass discovered at runtime rather than a hard-coded
    list, so a ninth added later is held to the same contract without anyone
    remembering to come back here.
    """

    #: The members a subclass must define *itself*. Each carries a
    #: fallback-role answer on the base that is wrong for a real header, and
    #: each was measured to break concretely if inherited: ``alias`` renames the
    #: header in every :class:`~pcapkit.corekit.protochain.ProtoChain` string
    #: and in the packet dict key, ``protocol`` reads a field the subclass's
    #: data model does not have, ``length`` likewise (``IPv6_Frag``'s data model
    #: has no ``length`` field at all), and ``__index__`` raises.
    REQUIRED_OVERRIDES = ('name', 'alias', 'protocol', 'length', '__index__')

    #: The family as it stands, so a member silently *leaving* the base is
    #: caught as well as one joining without the overrides. Named rather than
    #: counted: a count alone cannot tell a swap from a no-op.
    KNOWN_MEMBERS = frozenset({
        'HOPOPT', 'IPv6_Route', 'IPv6_Frag', 'IPv6_Opts', 'HIP', 'MH', 'AH', 'ESP',
    })

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    @staticmethod
    def _subclasses(base: type) -> 'list[type]':
        """Every subclass of ``base``, transitively.

        :meth:`type.__subclasses__` is one level deep, so an indirect subclass
        -- which nothing forbids -- would otherwise escape this whole class.
        """
        found = {}  # type: dict[str, type]
        stack = list(base.__subclasses__())
        while stack:
            klass = stack.pop()
            if klass.__qualname__ in found:
                continue
            found[klass.__qualname__] = klass
            stack.extend(klass.__subclasses__())
        return [found[key] for key in sorted(found)]

    def _family(self) -> 'list[type]':
        """The discovered family, with every member module imported first."""
        import pcapkit.protocols.internet  # noqa: F401  # populates __subclasses__
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext

        return self._subclasses(IPv6_Ext)

    @staticmethod
    def _constant(klass: type, member: str) -> 'str | None':
        """What ``klass``'s ``member`` property answers with, given no instance
        state.

        Resolved through the MRO with :func:`getattr` rather than read out of
        ``klass.__dict__``, and called rather than having its ``Literal``
        annotation parsed. Both choices matter: the annotation is the
        *documented* value where this is the value the library actually
        answers with, and resolving through the MRO is what makes an
        *inherited* fallback-role answer visible -- looking only at
        ``__dict__`` would return :data:`None` for a class that failed to
        override, which is indistinguishable from a pass.

        :data:`None` for a property that genuinely needs an instance --
        ``HIP.alias`` is ``f'HIPv{self._info.version}'``, derived from the
        parsed header, so it has no constant to check.
        """
        try:
            return getattr(klass, member).fget(None)
        except Exception:  # pylint: disable=broad-exception-caught
            return None

    def test_the_family_is_exactly_the_eight_known_members(self) -> None:
        """Importing :mod:`pcapkit.protocols.internet` must turn up all eight,
        and only those eight. This is what keeps the per-subclass tests below
        from passing vacuously on a walk that discovered nothing.
        """
        self.assertEqual({klass.__qualname__ for klass in self._family()},
                         set(self.KNOWN_MEMBERS))

    #: Which family members are *also* standalone protocols, and so name a
    #: second base explicitly rather than only reaching one transitively.
    #:
    #: The maintainer's convention, from GitHub pull request #924: a header
    #: usable *only* as an extension header inherits ``IPv6_Ext`` alone; one
    #: usable as a standalone protocol names ``Internet`` (or ``IPsec``) as
    #: well. The three here each travel as an IPv4 payload on a primary
    #: source -- ``AH`` :rfc:`4302#section-3.1.1`, ``ESP``
    #: :rfc:`4303#section-3.1.1`, ``HIP`` :rfc:`7401#appendix-C.2`, whose
    #: worked example is an IPv4 header carrying ``Next Header: 139``.
    #:
    #: ``MH`` is deliberately absent. It is a protocol in its own right, but
    #: :rfc:`6275#section-6.1.1` defines its checksum over a pseudo-header of
    #: IPv6 header fields with no IPv4 variant, and Mobile IPv4 carries the
    #: equivalent messages over UDP port 434 (:rfc:`5944`) rather than as
    #: protocol 135 -- so it cannot appear under IPv4 and stays extension-only.
    STANDALONE_MEMBERS = frozenset({'AH', 'ESP', 'HIP'})

    def test_standalone_members_name_a_second_base_and_the_rest_do_not(self) -> None:
        """Pins the classification, which prose alone cannot keep honest.

        Asserted against ``__bases__`` rather than ``__mro__``, because every
        member reaches :class:`~pcapkit.protocols.internet.internet.Internet`
        transitively through ``IPv6_Ext`` -- so an ``__mro__`` check passes for
        all eight and tests nothing. What the convention encodes is the
        *declaration*: naming the base is how a deliberate standalone protocol
        is told apart from a header that merely inherits one.

        """
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext

        for klass in self._family():
            with self.subTest(cls=klass.__qualname__):
                named = {base for base in klass.__bases__
                         if base is not IPv6_Ext and issubclass(base, Internet)}
                if klass.__qualname__ in self.STANDALONE_MEMBERS:
                    self.assertTrue(
                        named,
                        f'{klass.__qualname__} is classified as also usable as a standalone '
                        f'protocol, so it must name Internet (or a subclass such as IPsec) '
                        f'as an explicit base; it names only '
                        f'{tuple(b.__name__ for b in klass.__bases__)}',
                    )
                else:
                    self.assertFalse(
                        named,
                        f'{klass.__qualname__} is classified as usable only as an extension '
                        f'header, so IPv6_Ext should be its sole Internet-derived base; it '
                        f'also names {tuple(b.__name__ for b in named)}',
                    )

    def test_every_standalone_member_is_in_the_family(self) -> None:
        """Guards the pin above from going vacuous if a name is misspelled."""
        self.assertLessEqual(self.STANDALONE_MEMBERS, frozenset(self.KNOWN_MEMBERS))

    def test_every_subclass_defines_the_required_members_itself(self) -> None:
        """Checked against ``__dict__``, not :func:`getattr`.

        :func:`getattr` cannot tell an override from an inherited fallback-role
        answer -- which is the entire failure mode -- so it would report all
        five present on a subclass that defines none of them.
        """
        for klass in self._family():
            for member in self.REQUIRED_OVERRIDES:
                with self.subTest(klass=klass.__qualname__, member=member):
                    # ``assertTrue`` rather than ``assertIn``: the latter dumps
                    # the whole class ``mappingproxy`` into the failure, which
                    # buries the message that says what to do about it.
                    self.assertTrue(
                        member in klass.__dict__,
                        f'{klass.__qualname__} inherits {member!r} from IPv6_Ext, whose '
                        f'value is the generic fallback parser\'s and is wrong for a '
                        f'header with an identity of its own; define it on '
                        f'{klass.__qualname__} itself',
                    )

    def test_every_subclass_index_returns_a_real_transtype(self) -> None:
        """The base's :meth:`__index__` raises ``UnsupportedCall`` -- one
        instance stands in for many codes, and a :func:`classmethod` has
        nowhere to put a per-instance value. A subclass has exactly one code,
        so it must return it.
        """
        from pcapkit.const.reg.transtype import TransType as Enum_TransType

        for klass in self._family():
            with self.subTest(klass=klass.__qualname__):
                index = klass.__index__()  # must not raise
                self.assertIsInstance(index, Enum_TransType)
                self.assertIs(index, Enum_TransType(int(index)))

    def test_every_subclass_alias_survives_the_packet_dict_key_computation(self) -> None:
        """:meth:`IPv6._decode_next_layer
        <pcapkit.protocols.internet.ipv6.IPv6._decode_next_layer>` keys its
        packet dict by ``alias.lstrip('IPv6-').lower()`` (``ipv6.py:391``).
        :meth:`str.lstrip` strips a character *set*, so the hyphen in
        ``IPv6-Route``/``IPv6-Frag``/``IPv6-Opts`` is what lets ``IPv6`` fall
        away cleanly, where the underscore of a class-name default like
        ``IPv6_Route`` leaves ``_route``.

        Asserted as "no underscore, and the key is usable" rather than as
        "contains a hyphen", because four of the eight legitimately carry none:
        ``HOPOPT``, ``MH``, ``AH`` and ``ESP`` have no ``IPv6`` prefix for the
        strip to bite on, so demanding a hyphen of them would be demanding a
        rename rather than testing an invariant.
        """
        for klass in self._family():
            alias = self._constant(klass, 'alias')
            if alias is None:  # HIP -- see ``_constant``
                continue
            with self.subTest(klass=klass.__qualname__, alias=alias):
                self.assertNotIn('_', alias)
                key = alias.lstrip('IPv6-').lower()
                self.assertTrue(key)
                self.assertFalse(key.startswith(('_', '-')))
                if alias.startswith('IPv6'):
                    self.assertTrue(alias.startswith('IPv6-'))

    def test_no_subclass_answers_with_the_fallback_identity(self) -> None:
        """The concrete failure the contract exists to prevent, asserted
        directly rather than only through the ``__dict__`` check: no real
        header may end up reporting the fallback parser's own identity.
        """
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext

        base_name = self._constant(IPv6_Ext, 'name')
        base_alias = self._constant(IPv6_Ext, 'alias')
        self.assertEqual(base_name, 'IPv6 Extension Header')
        self.assertEqual(base_alias, 'IPv6-Ext')

        for klass in self._family():
            with self.subTest(klass=klass.__qualname__):
                self.assertNotEqual(self._constant(klass, 'name'), base_name)
                self.assertNotEqual(self._constant(klass, 'alias'), base_alias)

    def test_the_base_itself_still_has_no_class_level_identity(self) -> None:
        """The other half of the contract: the fallback genuinely has none, so
        it must keep raising rather than be handed a placeholder index to
        satisfy the rule above.
        """
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext
        from pcapkit.utilities.exceptions import UnsupportedCall

        with self.assertRaises(UnsupportedCall):
            IPv6_Ext.__index__()

    def test_ah_and_esp_double_inherit_and_linearise(self) -> None:
        """Both are IPsec members *and* IPv6 extension headers -- IANA marks
        each ``Y`` in the *IPv6 Extension Header* column -- so each carries two
        identically-parameterised generic bases. The MRO is pinned because it
        is what makes the ``super()`` delegation in their ``protocol`` guards
        land on :class:`~pcapkit.protocols.protocol.ProtocolBase` rather than
        on the base's fallback-role ``protocol``.
        """
        from pcapkit.protocols.internet.ah import AH
        from pcapkit.protocols.internet.esp import ESP
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.internet.ipsec import IPsec
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext

        for klass in (AH, ESP):
            with self.subTest(klass=klass.__qualname__):
                self.assertEqual(
                    [base.__qualname__ for base in klass.__mro__[:5]],
                    [klass.__qualname__, 'IPsec', 'IPv6_Ext', 'Internet', 'ProtocolBase'])
                self.assertTrue(issubclass(klass, IPsec))
                self.assertTrue(issubclass(klass, IPv6_Ext))
                self.assertTrue(issubclass(klass, Internet))

    def test_esp_extension_mode_is_no_longer_dead(self) -> None:
        """GitHub issue #895: ``ESP`` accepted ``extension=``, stored it in
        ``_extf`` and never read it. Subclassing the base makes ``_extf``
        load-bearing for
        :attr:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext.payload` and
        :attr:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext.protochain`, which
        ``ESP`` inherits, and ``ESP.protocol`` supplies the third guard by hand.
        """
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.esp import ESP
        from pcapkit.utilities.exceptions import UnsupportedCall

        wire = struct.pack('>II', 0x66, 1) + b'\x00' * 16
        inst = ESP(io.BytesIO(wire), len(wire), version=6, extension=True)
        for attr in ('payload', 'protocol', 'protochain'):
            with self.subTest(attr=attr, extension=True):
                with self.assertRaises(UnsupportedCall):
                    getattr(inst, attr)

        # ... and with ``extension=False`` the same three stay open, so the
        # guards read ``_extf`` rather than refusing unconditionally.
        plain = ESP(io.BytesIO(wire), len(wire), version=6)
        self.assertEqual(str(plain.protochain).split(':')[0], 'ESP')
        self.assertEqual(plain.alias, 'ESP')
        self.assertIs(ESP.__index__(), TransType.ESP)

    def test_base_role_protocol_delegates_past_the_fallback_answer(self) -> None:
        """The trap this change had to avoid, pinned directly.

        Every subclass implements ``protocol`` as ``return super().protocol``,
        and ``IPv6_Ext`` now sits between it and
        :class:`~pcapkit.protocols.protocol.ProtocolBase` in the MRO. Without
        the ``__data__`` discriminator in
        :attr:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext.protocol`, that
        ``super()`` lands on the *fallback-role* body, which reads
        ``self._info.protocol`` -- a field none of the eight data models has.
        Measured before the discriminator was added: ``AttributeError`` on all
        eight. Both parenting shapes are exercised, since ``AH``/``ESP`` reach
        the base through ``IPsec``.
        """
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ah import AH
        from pcapkit.protocols.internet.esp import ESP
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.mh import MH

        udp = _udp_bytes(b'hi')
        cases = [
            (HOPOPT, bytes([int(TransType.UDP), 0]) + b'\x01\x04\x00\x00\x00\x00' + udp),
            (MH, bytes([int(TransType.UDP), 0, 0, 0]) + b'\x00' * 4 + udp),
            (AH, bytes([int(TransType.UDP), 2, 0, 0]) + b'\x00' * 12 + udp),
            (ESP, struct.pack('>II', 0x66, 1) + b'\x00' * 16),
        ]
        for klass, wire in cases:
            with self.subTest(klass=klass.__qualname__):
                inst = klass(io.BytesIO(wire), len(wire), version=6)
                protocol = inst.protocol
                # the ``ProtocolBase`` meaning -- a chain entry name, i.e. a
                # ``str`` -- never the fallback's ``ExtensionHeader`` identity.
                self.assertNotIsInstance(protocol, ExtensionHeader)
                self.assertIsInstance(protocol, str)

    def test_standalone_fallback_decodes_its_payload_and_reports_its_chain(self) -> None:
        """With ``extension=False`` the fallback is an ordinary protocol: the
        two guards open up and :meth:`read` continues into the next layer
        instead of returning early.
        """
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext
        from pcapkit.protocols.transport.udp import UDP

        raw = bytes([int(TransType.UDP), 0]) + b'\x00' * 6 + _udp_bytes(b'hi')
        inst = IPv6_Ext(io.BytesIO(raw), len(raw), alias=int(ExtensionHeader.HOPOPT))

        self.assertIsInstance(inst.payload, UDP)
        self.assertEqual(str(inst.protochain), 'IPv6-Ext:UDP:Raw')
        self.assertEqual(inst.protocol, ExtensionHeader.HOPOPT)
        self.assertEqual(inst.length, 8)

    def test_make_emits_the_two_guaranteed_octets(self) -> None:
        """:meth:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext.make` reads
        ``next``/``len``/``payload`` out of ``**kwargs`` rather than declaring
        them (see its docstring), so exercise the construction path that
        actually supplies them.
        """
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext

        built = IPv6_Ext(next=TransType.TCP, len=0, payload=b'\x00' * 6, version=6)
        self.assertEqual(bytes(built)[:2], bytes([int(TransType.TCP), 0]))
        self.assertEqual(len(bytes(built)), 8)

        # the defaults, when the caller supplies nothing at all
        default = IPv6_Ext(version=6)
        self.assertEqual(bytes(default)[:2], bytes([int(TransType.UDP), 0]))

    def test_an_absent_or_unregistered_alias_uses_the_generic_rule(self) -> None:
        """``alias`` names the code this instance stands in for. When it is
        missing, or is a number IANA has not registered as an extension header,
        :rfc:`6564#section-4`'s ``(octet[1] + 1) * 8`` is the best available
        guess and ``protocol`` reports :data:`None` rather than inventing a
        member.
        """
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext

        raw = bytes([int(TransType.UDP), 1]) + b'\x00' * 14  # (1+1)*8 == 16
        for label, kwargs in (('absent', {}), ('unregistered', {'alias': 200})):
            with self.subTest(alias=label):
                inst = IPv6_Ext(io.BytesIO(raw), len(raw), extension=True, **kwargs)
                self.assertIsNone(inst.protocol)
                self.assertEqual(inst.length, 16)
                self.assertEqual(inst.next, TransType.UDP)
                # ``read`` with no explicit length falls back to ``len(self)``
                self.assertEqual(inst.read().length, 16)

    def test_length_hint_is_the_two_octets_rfc_6564_guarantees(self) -> None:
        """Two, not a real header length: those two octets are all
        :rfc:`6564#section-4` promises of a header this class has never seen.
        """
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext

        self.assertEqual(object.__new__(IPv6_Ext).__length_hint__(), 2)

    def test_next_is_now_shared_by_every_subclass(self) -> None:
        """None of the eight declared a ``next`` property before #917, so
        reading one raised :exc:`AttributeError`. They inherit the base's now,
        which is sound because :rfc:`8200#section-4.1` puts a Next Header octet
        first in every extension header and all eight record it under that name.
        """
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag

        hopopt_wire = bytes([int(TransType.UDP), 0]) + b'\x01\x04\x00\x00\x00\x00'
        self.assertEqual(
            HOPOPT(io.BytesIO(hopopt_wire), len(hopopt_wire), version=6,
                   extension=True).next, TransType.UDP)

        frag_wire = bytes([int(TransType.UDP), 0]) + struct.pack('>HI', 0, 0)
        self.assertEqual(
            IPv6_Frag(io.BytesIO(frag_wire), len(frag_wire), version=6,
                      extension=True).next, TransType.UDP)
