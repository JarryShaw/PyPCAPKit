# -*- coding: utf-8 -*-
"""``ExtensionHeader`` has no ``BIT_EMU``, per GitHub issue #925.

Issue #925's own diagnosis: IANA's authoritative *IPv6 Extension Header Types*
registry (``ipv6-parameters/extension-header.csv``) and the *Protocol Numbers*
registry's ``IPv6 Extension Header`` column disagree on header 147
(``BIT-EMU``), so a crawler sourced from the latter generates a
:mod:`pcapkit.const.ipv6.extension_header` member the authoritative registry
does not have. :mod:`tests.vendor.test_vendor_ipv6_extension_header_925_unit`
pins the crawler to the authoritative registry, and its
``test_context_matches_the_committed_const_file_byte_for_byte`` proves this
file is exactly what the crawler produces from the fixture the issue's
own investigation fetched.

:meth:`pcapkit.protocols.internet.ipv6.IPv6._decode_next_layer` resolves
``Enum_ExtensionHeader(proto)`` at the top of its extension-header walk loop,
wrapped in ``try/except ValueError: break``. ``tests.protocols.internet
.test_ipv6_ext_unit.IPv6ExtUnitTests
.test_unimplemented_terminal_code_stops_the_walk_not_the_packet`` builds its
packet around 253, not 147: the same code path, and unlike 147 a code the
authoritative extension-header registry holds.

This suite pins the const side of that boundary: the member count,
``BIT_EMU``'s absence, and that :meth:`pcapkit.protocols
.internet.ipv6.IPv6._decode_next_layer`'s walk handles a next-header code not
backed by any ``ExtensionHeader`` member -- 147 itself is a real
:class:`~pcapkit.const.reg.transtype.TransType` value (it legitimately belongs
there; that enum is sourced from the Protocol Numbers registry, which is
correct for it) -- without raising or losing the packet's own header fields.

"""
from __future__ import annotations

import io
import struct
import unittest


def _ipv6_bytes(next_code: 'int', ext_and_payload: 'bytes') -> 'bytes':
    """A minimal IPv6 header (version 6, ``::1`` -> ``::1``) wrapping ``ext_and_payload``.

    Same construction as ``tests.protocols.internet.test_ipv6_ext_unit._ipv6_bytes``,
    duplicated rather than imported so this suite does not depend on that
    module's private helpers.

    """
    header = struct.pack('>IHBB', 6 << 28, len(ext_and_payload), next_code, 64)
    header += (b'\x00' * 15 + b'\x01') * 2  # src = dst = ::1
    return header + ext_and_payload


class ExtensionHeaderHasNoBitEmuTests(unittest.TestCase):
    """There is no ``BIT_EMU``, and the ``ipv6.py`` walk handles 147 cleanly."""

    def test_extension_header_has_no_bit_emu_member(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        names = [member.name for member in ExtensionHeader]
        self.assertEqual(len(names), 11)
        self.assertNotIn('BIT_EMU', names)

    def test_bit_emu_value_does_not_resolve(self) -> None:
        # The exact call IPv6._decode_next_layer makes at the
        # top of its extension-header walk loop. With no BIT_EMU member and no
        # _missing_ defined on this generated file (neither EnumLookup nor
        # EnumRegistry in pcapkit.corekit.enum defines one either), 147
        # raises plain ValueError instead of resolving.
        from pcapkit.const.ipv6.extension_header import ExtensionHeader

        with self.assertRaises(ValueError):
            ExtensionHeader(147)

    def test_transtype_still_carries_bit_emu(self) -> None:
        # Confirms the scope of the fix: this is a different enumeration,
        # correctly sourced from the (still valid) Protocol Numbers registry,
        # and issue #925 never asked for it to change.
        from pcapkit.const.reg.transtype import TransType

        self.assertEqual(int(TransType.BIT_EMU), 147)

    def test_ipv6_walk_stops_cleanly_on_next_header_147(self) -> None:
        # The behaviour actually worth protecting, restated for 147, which is
        # not an ExtensionHeader member: IPv6._decode_next_layer
        # must not raise or lose the packet's own header just because a
        # next-header code does not resolve as an extension header at all.
        # ExtensionHeader(147) raising breaks the walk loop on its very
        # first iteration -- the same graceful termination an ordinary
        # upper-layer protocol code (UDP, TCP, ...) already takes -- so this
        # packet ends up dispatched by TransType instead of being walked as
        # an extension-header chain, and still parses without error.
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.misc.raw import Raw

        raw = _ipv6_bytes(int(TransType.BIT_EMU), b'\x11\x01' + b'\x00' * 14)
        ipv6 = IPv6(io.BytesIO(raw), len(raw))

        # the header this whole #891 lineage of fixes exists to protect.
        self.assertEqual(str(ipv6.src), '::1')
        self.assertEqual(str(ipv6.dst), '::1')

        # not recorded as an extension header at all -- 147 is not one, so
        # the walk loop's own top-of-loop check breaks
        # immediately rather than ever reaching self._exthdr.add(...).
        exthdrs = list(ipv6.extension_headers.items(multi=True))
        self.assertEqual(exthdrs, [])

        self.assertIsInstance(ipv6.payload, Raw)


if __name__ == '__main__':
    unittest.main()
