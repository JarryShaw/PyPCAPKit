# -*- coding: utf-8 -*-
"""A parsed Multipath TCP schema carries the same attributes as a built one, ``option`` included.

GitHub issue #2293. :meth:`_MPTCP.post_process
<pcapkit.protocols.schema.transport.tcp._MPTCP.post_process>` set ``ret.option =
Enum_Option.Multipath_TCP`` on the subtype schema it returns. No ``_make_mptcp_*`` maker, and
not :meth:`TCP._make_mode_mp <pcapkit.protocols.transport.tcp.TCP._make_mode_mp>` either, made
the matching assignment -- so the attribute existed on a schema unpacked from wire bytes and
not on the same schema built in memory.

Why the assignment had nothing to be symmetric about
----------------------------------------------------

``option`` was not a field. :class:`~pcapkit.protocols.schema.transport.tcp.MPTCP` declares
exactly ``kind`` and ``length`` (#541) and every concrete subtype adds its own on top; none of
them declares ``option``, under :data:`~typing.TYPE_CHECKING` or otherwise. So the assignment
created an attribute out of nothing at unpack time, and nothing in ``pcapkit`` read it back:
``kind``, a real :class:`~pcapkit.corekit.fields.numbers.EnumField`, already carries
:attr:`~pcapkit.const.tcp.option.Option.Multipath_TCP`, and it is ``kind`` that the schema
packs.

That is the difference from ``subtype``, the other attribute ``post_process`` assigns, which
*is* needed on both paths and stays. ``subtype`` cannot be a field -- every subtype schema
already packs those 4 bits inside its own ``test``
:class:`~pcapkit.corekit.fields.strings.BitField`, so a second field for them would either
double-pack or need a derive-don't-pack field this library has no equivalent of -- and every
``_read_mptcp_*`` reader reads it, which is why ``_make_mode_mp`` sets it for construction
(#566, #579, pinned in
:mod:`tests.protocols.transport.test_tcp_mptcp_subtype_unit`). ``option`` had neither
property: no reader wanted it and no maker set it. Dropping it is therefore the symmetric
fix, where adding a mirror assignment to ``_make_mode_mp`` would have propagated a value
with no purpose to the construction path as well.

Why the defect is invisible to a round trip
-------------------------------------------

Both schemas pack to the same octets, because ``option`` is not among the fields ``pack``
walks. Only the attribute *sets* differ, so a byte-level round trip stays closed over the
defect -- the blind spot
:mod:`tests.protocols.test_option_roundtrip_unit`'s docstring names. The assertion here is
accordingly on ``set(schema.to_dict())``, the attributes each path leaves behind, rather than
on packed bytes; the packed bytes are asserted equal as well, to pin that dropping the
assignment moved nothing on the wire.

Coverage
--------

Three subtypes, each reached by parsing hand-built spec-correct octets and then rebuilt from
the resulting data model through ``_make_mode_mp``: MP_CAPABLE and MP_FASTCLOSE for the
registered makers, and an unknown subtype for the ``MPTCPUnknown`` fallback, since
``post_process`` runs once per option regardless of which subtype schema it dispatched to.

MP_JOIN is deliberately absent. ``_make_mptcp_join`` picks between the three layouts of
:rfc:`8684` section 3.2 by reading ``self._flags``, which a bare ``TCP.__new__(TCP)`` has
not got, so reaching it would mean constructing a whole protocol instance and would test the
flag dispatch rather than the attribute symmetry this module is about -- that dispatch is
covered in :mod:`tests.protocols.transport.test_tcp_mptcp_join_flag_ordering_unit`.

:meth:`~TCPMPTCPOptionAttributeUnitTests.test_option_is_not_a_declared_field` is the positive
half: it derives from the schema classes themselves that ``option`` never was a field, so the
case for deleting the assignment rather than mirroring it does not rest on this docstring.

Every case builds its own octets in memory and reads no capture under
:file:`examples/captures/`, so this belongs to the unit tier.

"""
from __future__ import annotations

import unittest

#: Hand-built, spec-correct options, each starting at its ``kind`` octet and already a
#: multiple of 4 octets long, keyed by the subtype they carry.
#:
#: * ``MP_CAPABLE`` -- :rfc:`8684` section 3.1 figure 4, the 12-octet form: ``1e`` kind, ``0c``
#:   length, ``01`` the subtype nibble ``0`` beside version ``1``, ``81`` the ``A``..``H``
#:   flags, then the sender's key.
#: * ``MP_FASTCLOSE`` -- :rfc:`8684` section 3.5 figure 14: subtype nibble ``7`` with its 12
#:   reserved bits as ``0x70 0x00``, then the receiver's key.
#: * ``unknown`` -- the 3-octet minimum of section 3 with subtype nibble ``0xf``
#:   (``Reserved_for_Private_Use``) and a data nibble of ``5``, padded with one
#:   End-of-Option-List octet.
SPEC_OPTIONS = {
    'MP_CAPABLE': bytes([0x1E, 0x0C, 0x01, 0x81]) + b'\xAA' * 8,
    'MP_FASTCLOSE': bytes([0x1E, 0x0C, 0x70, 0x00]) + b'\xCC' * 8,
    'unknown': bytes([0x1E, 0x03, 0xF5, 0x00]),
}


def build_tcp_segment(option_octets: 'bytes') -> 'bytes':
    """Pack a whole SYN segment carrying ``option_octets`` verbatim as its only option.

    Goes through :class:`~pcapkit.protocols.schema.transport.tcp.TCP` (the schema, not the
    protocol) directly, so no ``_make_mptcp_*`` maker runs and the option bytes reach the
    wire exactly as given -- which is what makes the parsed side of each comparison below an
    independent starting point rather than something a maker produced.

    Args:
        option_octets: The whole option, header octets included, already padded to a multiple
            of 4 octets.

    Returns:
        The packed TCP segment.

    Note:
        ``pcapkit`` is imported here, inside the function, rather than at module level, for
        the reason
        :func:`tests.protocols.transport.test_tcp_mptcp_subtype_unit.build_mptcp_option`'s own
        docstring records: another module in this suite pops ``pcapkit``'s submodules out of
        :data:`sys.modules`, so a name bound at collection time can end up pointing at a
        schema class built from a stale ``Schema`` base.

    """
    from pcapkit.protocols.schema.transport.tcp import TCP as Schema_TCP

    if len(option_octets) % 4:
        raise ValueError('option_octets must already be a multiple of 4 octets long')

    schema = Schema_TCP(
        srcport=50000, dstport=80, seq=1, ack=0,
        offset={'offset': 5 + len(option_octets) // 4, 'reserved': 0, 'ns': 0},
        flags={'cwr': 0, 'ece': 0, 'urg': 0, 'ack': 0, 'psh': 0, 'rst': 0, 'syn': 1, 'fin': 0},
        window=8192, checksum=b'\x00\x00', urgent=0,
        options=option_octets,
        payload=b'',
    )
    return schema.pack()


def parse_and_rebuild(option_octets: 'bytes') -> 'tuple[object, object]':
    """Parse one MPTCP option off the wire, then rebuild it from the data model that produced.

    Args:
        option_octets: The whole option, as :func:`build_tcp_segment` wants it.

    Returns:
        The schema :meth:`_MPTCP.post_process
        <pcapkit.protocols.schema.transport.tcp._MPTCP.post_process>` returned for the parsed
        option, and the schema :meth:`TCP._make_mode_mp
        <pcapkit.protocols.transport.tcp.TCP._make_mode_mp>` builds from the parsed option's
        data model -- the two paths #2293 is about, starting from the same option.

    """
    from pcapkit.const.tcp.option import Option as Enum_Option
    from pcapkit.protocols.transport.tcp import TCP

    raw = build_tcp_segment(option_octets)
    protocol = TCP(raw, len(raw))

    parsed = protocol.schema.options[0]
    built = TCP.__new__(TCP)._make_mode_mp(  # pylint: disable=protected-access
        Enum_Option.Multipath_TCP, protocol.info.options[Enum_Option.Multipath_TCP])
    return parsed, built


class TCPMPTCPOptionAttributeUnitTests(unittest.TestCase):
    """Parsing and building an MPTCP option leave the same attributes on the schema."""

    def test_parsed_and_built_schemas_carry_the_same_attributes(self) -> None:
        """``set(schema.to_dict())`` agrees between the parse path and the build path.

        The assertion #2293 reports: on ``main`` the parsed side carries a surplus
        ``option``, so this reads ``{'option'}`` rather than the empty set.

        """
        for name, octets in SPEC_OPTIONS.items():
            with self.subTest(subtype=name):
                parsed, built = parse_and_rebuild(octets)

                self.assertEqual(set(parsed.to_dict()), set(built.to_dict()),
                                 'a parsed schema and a built schema must have the same keys')

    def test_parsed_schema_has_no_option_attribute(self) -> None:
        """The surplus attribute itself is gone, named rather than inferred from a set diff.

        Pinned separately so a regression says *which* attribute came back, and so that
        making ``option`` symmetric by also setting it on the construction path -- which
        would satisfy the test above -- does not pass here.

        """
        for name, octets in SPEC_OPTIONS.items():
            with self.subTest(subtype=name):
                parsed, built = parse_and_rebuild(octets)

                self.assertFalse(hasattr(parsed, 'option'))
                self.assertFalse(hasattr(built, 'option'))

    def test_kind_still_carries_multipath_tcp(self) -> None:
        """Dropping ``option`` loses no value: ``kind`` is where the option number lives.

        ``kind`` is a real field on :class:`~pcapkit.protocols.schema.transport.tcp.MPTCP`, so
        it is both set on every path and actually packed, which is the whole reason ``option``
        was redundant rather than merely asymmetric.

        """
        from pcapkit.const.tcp.option import Option as Enum_Option

        for name, octets in SPEC_OPTIONS.items():
            with self.subTest(subtype=name):
                parsed, built = parse_and_rebuild(octets)

                self.assertEqual(parsed.kind, Enum_Option.Multipath_TCP)
                self.assertEqual(built.kind, Enum_Option.Multipath_TCP)

    def test_subtype_is_still_set_on_both_paths(self) -> None:
        """``subtype``, the assignment that stays, is unaffected.

        ``post_process`` assigns both ``option`` and ``subtype``; only the first was surplus
        (#566, #579). Guards against a fix that reached for the whole block.

        """
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption

        expected = {
            'MP_CAPABLE': Enum_MPTCPOption.MP_CAPABLE,
            'MP_FASTCLOSE': Enum_MPTCPOption.MP_FASTCLOSE,
            'unknown': Enum_MPTCPOption.Reserved_for_Private_Use,
        }
        for name, octets in SPEC_OPTIONS.items():
            with self.subTest(subtype=name):
                parsed, built = parse_and_rebuild(octets)

                self.assertEqual(parsed.subtype, expected[name])
                self.assertEqual(built.subtype, expected[name])

    def test_packed_octets_are_unchanged(self) -> None:
        """Both schemas still pack the octets they were parsed from.

        ``option`` was never packed, so removing it must move nothing on the wire. This is
        also what makes the attribute-set assertion above necessary: a byte-level round trip
        passes either way.

        """
        for name, octets in SPEC_OPTIONS.items():
            with self.subTest(subtype=name):
                parsed, built = parse_and_rebuild(octets)
                expected = octets.rstrip(b'\x00') if name == 'unknown' else octets

                self.assertEqual(parsed.pack(), expected)
                self.assertEqual(built.pack(), expected)

    def test_option_is_not_a_declared_field(self) -> None:
        """No MPTCP schema declares an ``option`` field, so nothing could have depended on it.

        Derived from the schema classes the library ships rather than from a list written
        here, so the claim is rechecked whenever a subtype gains a field.

        """
        from pcapkit.protocols.schema.transport.tcp import MPTCP

        schemas = [MPTCP, *MPTCP.__enum__.values(),
                   MPTCP.__enum__.default_factory()]  # the ``MPTCPUnknown`` fallback
        self.assertGreater(len(schemas), 1, 'the subtype registry must not be empty')

        for schema in schemas:
            with self.subTest(schema=schema.__name__):
                self.assertNotIn('option', schema.__fields__)
                self.assertIn('kind', schema.__fields__)


if __name__ == '__main__':
    unittest.main()
