"""An unassigned enumeration value raised :mod:`aenum`'s own ``ValueError``.

GitHub issue #701. :meth:`EnumField.post_process
<pcapkit.corekit.fields.numbers.EnumField.post_process>` resolved a wire value
through the *constructor* of its registry::

    return self._namespace(value)

which raises for any value no member and no ``_missing_`` rule accounts for. The
raise is :mod:`aenum`'s own::

    ValueError: 28 is not a valid BlockType

and it is neither one of :mod:`pcapkit.utilities.exceptions`, so a caller cannot
tell it from a bug of its own, nor an :exc:`EOFError`, so
:meth:`Extractor.record_frames
<pcapkit.foundation.extraction.Extractor.record_frames>` does not catch it. One
unassigned code therefore cost the whole extraction.

It also made the "unknown" reader every one of these formats requires
unreachable. PCAP-NG's
:class:`~pcapkit.protocols.schema.misc.pcapng.UnknownBlock` exists, its
``__default__`` selects it, and
:meth:`PCAPNG._read_block_unknown <pcapkit.protocols.misc.pcapng.PCAPNG._read_block_unknown>`
reads it -- but the lookup failed several frames before the dispatch that would
have chosen it, so the default only ever fired for the ``Reserved_*`` ranges
:meth:`BlockType._missing_ <pcapkit.const.pcapng.block_type.BlockType._missing_>`
auto-extends. PCAP-NG repeats a block's total length at both ends precisely so a
reader can skip a block type it does not recognise; that skip is what the fix
restores.

Three things about this suite are deliberate.

**The field layer is tested separately from the extraction.** The defect has two
faces -- a foreign exception out of
:meth:`~pcapkit.corekit.fields.numbers.EnumField.post_process`, and an extraction
lost to it -- and a fix that addressed only the first would still leave a capture
unreadable. :class:`UnassignedEnumFieldTests` pins the field, and
:class:`UnassignedBlockTypeExtractionTests` pins the consequence the issue was
filed about.

**What must go on raising is asserted too.** The change is at the *field* layer,
so every registry's own guard has to be exactly as it was -- a registry that
declares a width and rejects outside it, as
:class:`pcapkit.const.tcp.flags.Flags` does over 16 bits, is making a decision
this layer is in no position to overrule.
:meth:`UnassignedEnumFieldTests.test_the_registry_own_guard_is_not_weakened` and
:meth:`UnassignedEnumFieldTests.test_an_in_library_rejection_is_not_absorbed`
are what distinguish the fix from a blanket ``except ValueError: pass``; the
second of them also says which registries the distinction is for, since it is
not the generated ones.

**The sweep is over whole value spaces, not over the reported value.** ``28`` is
one of thousands of unassigned codes and a fix special-casing it would pass a
test that used only it, so
:meth:`UnassignedEnumFieldTests.test_no_value_of_any_width_escapes_the_field_layer`
walks every value a one- and two-octet field can carry, for four registries, and
asserts that nothing foreign comes out.
"""

from __future__ import annotations

import enum
import importlib.util
import os
import struct
import tempfile
import unittest

from tests._support import close_extractor, purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: The value the issue reports, and its four-octet big-endian spelling. ``28``
#: is unassigned in :class:`~pcapkit.const.pcapng.block_type.BlockType` and sits
#: in none of the ``Reserved_*`` ranges its ``_missing_`` extends.
UNASSIGNED_BLOCK_TYPE = 28
UNASSIGNED_BLOCK_OCTETS = b'\x00\x00\x00\x1c'

#: A Section Header Block, an Interface Description Block declaring Ethernet, and
#: a well-formed block of the unassigned type above -- the issue's own repro,
#: verbatim.
_SHB = struct.pack('<IIIHHqI', 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
_IDB = struct.pack('<IIHHII', 0x00000001, 20, 1, 0, 0, 20)
_UNKNOWN = struct.pack('<III', UNASSIGNED_BLOCK_TYPE, 16, 0) + struct.pack('<I', 16)

#: An Ethernet frame carrying an experimental EtherType, so the packet block
#: below parses all the way down rather than warning about a payload too short
#: for the link type its interface declares.
_ETHERNET = (b'\x00\x11\x22\x33\x44\x55' + b'\x66\x77\x88\x99\xaa\xbb'
             + b'\x88\xb5' + b'\xde\xad\xbe\xef')

#: An Enhanced Packet Block carrying it. Appended behind the unknown block so
#: that "the extraction survived" can be told apart from "the extraction stopped
#: quietly at the unknown block" -- the two are indistinguishable in a capture
#: whose unknown block is last.
_EPB_BODY = (struct.pack('<IIIII', 0, 0, 0, len(_ETHERNET), len(_ETHERNET))
             + _ETHERNET + b'\x00' * (-len(_ETHERNET) % 4))
_EPB = (struct.pack('<II', 0x00000006, 12 + len(_EPB_BODY)) + _EPB_BODY
        + struct.pack('<I', 12 + len(_EPB_BODY)))


def _capture(*blocks: bytes) -> str:
    """Write the given blocks to a temporary file and return its path.

    A file rather than a :class:`io.BytesIO`, because
    :class:`~pcapkit.foundation.extraction.Extractor` names its input and peeks
    at its magic number, neither of which a bare buffer supports. Built here
    rather than read from :file:`examples/captures/`, so this module stays in the
    unit tier -- see :mod:`tests._tiers`.

    """
    handle, path = tempfile.mkstemp(suffix='.pcapng')
    with os.fdopen(handle, 'wb') as file:
        file.write(b''.join(blocks))
    return path


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class UnassignedEnumFieldTests(unittest.TestCase):
    """The field layer, in isolation from any protocol."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_an_unassigned_registry_value_resolves_instead_of_raising(self) -> None:
        """The reported lookup, as a field unpack.

        Measured on the unfixed tree, this raised ``ValueError: 28 is not a valid
        BlockType`` straight out of :mod:`aenum`. It now resolves, and the value
        it resolves to carries the octets it came from -- which is the whole
        point, since a pseudo-member that lost the code would be no more useful
        to the dispatch than the exception was.

        """
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.corekit.fields.numbers import EnumField

        field = EnumField(length=4, namespace=BlockType)
        resolved = field.unpack(UNASSIGNED_BLOCK_OCTETS, dict())

        self.assertEqual(int(resolved), UNASSIGNED_BLOCK_TYPE)
        self.assertIsInstance(resolved, enum.IntEnum)

    def test_the_resolved_value_repacks_to_the_octets_it_came_from(self) -> None:
        """The resolution is round-trip safe.

        A value that parses but cannot be written back is not a parse, and the
        option round-trip suite would say so. The pseudo-member is an
        :class:`int`, so ``pre_process`` handles it exactly as it handles a
        declared member.

        """
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.corekit.fields.numbers import EnumField

        field = EnumField(length=4, namespace=BlockType)
        resolved = field.unpack(UNASSIGNED_BLOCK_OCTETS, dict())

        self.assertEqual(field.pack(resolved, dict()), UNASSIGNED_BLOCK_OCTETS)

    def test_a_declared_member_still_resolves_to_the_registry_member(self) -> None:
        """The 99.99% path is untouched, and identity proves it.

        ``assertIs`` rather than ``assertEqual``: a pseudo-member with the same
        value compares equal to the real one, so equality would pass against a
        fix that had started minting pseudo-members for *declared* codes too.

        """
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.corekit.fields.numbers import EnumField

        field = EnumField(length=4, namespace=BlockType)

        self.assertIs(field.unpack(b'\x00\x00\x00\x06', dict()),
                      BlockType.Enhanced_Packet_Block)
        self.assertIs(field.unpack(b'\x0a\x0d\x0d\x0a', dict()),
                      BlockType.Section_Header_Block)

    def test_a_missing_rule_still_mints_its_own_member(self) -> None:
        """``_missing_`` keeps precedence over the fallback.

        ``0x0bad0bad`` is in one of the ``Reserved_*`` ranges
        :meth:`BlockType._missing_
        <pcapkit.const.pcapng.block_type.BlockType._missing_>` extends, so it has
        always resolved -- to a real ``BlockType`` member, named for its range.
        The fallback must not shadow that: if it did, a reserved code would come
        back nameless and lose the only thing the registry knows about it.

        """
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.corekit.fields.numbers import EnumField

        field = EnumField(length=4, namespace=BlockType)
        resolved = field.unpack(b'\x0b\xad\x0b\xad', dict())

        self.assertIsInstance(resolved, BlockType)
        self.assertEqual(resolved.name, 'Reserved_0bad0bad')

    def test_the_registry_own_guard_is_not_weakened(self) -> None:
        """The change is at the field layer and nowhere else.

        A registry rejecting a value is a statement about that registry, and
        callers -- including the generated ``get()`` -- rely on it. The fallback
        lives in the field, which knows the value arrived in a field of a fixed
        width; it does not reach into the registry, so both of these go on
        raising exactly as before.

        """
        from pcapkit.const.pcapng.block_type import BlockType

        with self.assertRaises(ValueError):
            BlockType(UNASSIGNED_BLOCK_TYPE)
        with self.assertRaises(ValueError):
            BlockType.get(UNASSIGNED_BLOCK_TYPE)

    def test_an_in_library_rejection_is_not_absorbed(self) -> None:
        """A blanket ``except ValueError`` would have swallowed this.

        A registry that bounds itself and rejects with one of
        :mod:`pcapkit.utilities.exceptions` has made a deliberate decision, and
        the field layer sees only that the value arrived in a field of *some*
        width. So that rejection propagates untouched, and it is only the
        enumeration library's own "no member has this value" that becomes a
        pseudo-member.

        The registries this matters for are the ones registered from outside
        :mod:`pcapkit.const`, which is why the stand-ins below are built here
        rather than borrowed. A *generated* guard raises a bare, unlogged
        :exc:`ValueError` on purpose -- ``tests/const/test_const_enum_builtin_parity.py``
        pins exactly that, because each generated ``get()``'s ``except
        ValueError`` fallback depends on it -- so no registry under
        :mod:`pcapkit.const` exercises this branch, and none needs to: the
        bit-flag registries that do bound themselves to a width, including
        :class:`pcapkit.const.tcp.flags.Flags`, are reached through neither a
        plain :class:`~pcapkit.corekit.fields.numbers.EnumField` nor this method.

        Asserted for both enumeration libraries, because the registries under
        :mod:`pcapkit.const` are a mixture of the two and ``_missing_`` is
        invoked by different machinery in each.

        """
        import aenum

        from pcapkit.corekit.fields.numbers import EnumField
        from pcapkit.utilities.exceptions import FieldValueError

        class StdlibBounded(enum.IntEnum):
            """A registry that rejects rather than declining to resolve."""

            ONLY = 1

            @classmethod
            def _missing_(cls, value: 'int') -> 'StdlibBounded':
                raise FieldValueError(f'{value!r} is out of range for {cls.__name__}')

        class AenumBounded(aenum.IntEnum):
            """The same, on the other enumeration library."""

            ONLY = 1

            @classmethod
            def _missing_(cls, value: 'int') -> 'AenumBounded':
                raise FieldValueError(f'{value!r} is out of range for {cls.__name__}')

        for namespace in (StdlibBounded, AenumBounded):
            with self.subTest(namespace=namespace.__name__):
                field = EnumField(length=1, namespace=namespace)
                with self.assertRaises(FieldValueError):
                    field.unpack(b'\x63', dict())

    def test_a_field_with_no_registry_at_all_is_unchanged(self) -> None:
        """The branch the fallback reuses still behaves as it did.

        A namespace-less :class:`~pcapkit.corekit.fields.numbers.EnumField` has
        always produced this nameless member; the fix reuses the same mechanism
        rather than inventing a second shape, so an unassigned code and a
        registry-less field now answer alike.

        """
        from pcapkit.corekit.fields.numbers import EnumField

        field = EnumField(length=4)
        resolved = field.unpack(UNASSIGNED_BLOCK_OCTETS, dict())

        self.assertEqual(int(resolved), UNASSIGNED_BLOCK_TYPE)
        self.assertEqual(resolved.name, '<unassigned>')

    def test_bit_length_masking_still_precedes_the_lookup(self) -> None:
        """``post_process`` masks before it resolves, and still does.

        A bit-field's value is the masked one, so the registry must be asked
        about the masked value rather than about the octet it was carved out of.
        ``0xF1`` masked to four bits is ``1``, which is declared; resolving the
        unmasked ``0xF1`` would have produced a pseudo-member instead and hidden
        a regression in the masking.

        """
        from pcapkit.corekit.fields.numbers import EnumField

        class Nibble(enum.IntEnum):
            """A registry addressed by the low four bits of an octet."""

            ONE = 1

        field = EnumField(length=1, namespace=Nibble, bit_length=4)

        self.assertIs(field.unpack(b'\xf1', dict()), Nibble.ONE)

    def test_no_value_of_any_width_escapes_the_field_layer(self) -> None:
        """The property, rather than the reported instance.

        ``28`` is one of thousands of unassigned codes, so a fix that special-cased
        it would pass a test written around it. This walks the *entire* value space
        a one- and two-octet field can carry, across four registries of different
        shapes, and asserts that nothing leaves the field layer except a member.

        Measured on the unfixed tree this raised for the overwhelming majority of
        values in each registry -- the registries declare a few hundred codes
        between them and the two-octet ones have 65,536 to answer for.

        """
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.reg.ethertype import EtherType
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.fields.numbers import EnumField

        summary = []  # type: list[str]
        for namespace, width in ((TransType, 1), (OptionNumber, 1),
                                 (EtherType, 2), (BlockType, 2)):
            field = EnumField(length=width, namespace=namespace)
            escaped = []  # type: list[tuple[int, str]]

            for value in range(1 << (8 * width)):
                try:
                    resolved = field.unpack(value.to_bytes(width, 'big'), dict())
                except Exception as exc:  # pylint: disable=broad-except
                    escaped.append((value, f'{type(exc).__name__}: {exc}'))
                else:
                    if int(resolved) != value:
                        escaped.append((value, f'resolved to {int(resolved)}'))

            if escaped:
                summary.append(
                    f'{namespace.__name__} ({width} octets): {len(escaped)} of '
                    f'{1 << (8 * width)} values did not resolve to themselves, '
                    f'first {escaped[:3]}'
                )

        # NOTE: All four registries are swept before anything is asserted, so a
        # report names every one that failed rather than only the first. A bare
        # ``assertEqual`` inside the loop would abort at the first failing
        # registry and leave the rest unmeasured, which is the difference between
        # "this registry regressed" and "the fallback is gone".
        self.assertEqual(summary, [], '; '.join(summary))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class UnassignedBlockTypeExtractionTests(unittest.TestCase):
    """The consequence the issue was filed about, end to end."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _protochains(self, path: str) -> 'list[str]':
        """Extract a capture and report each frame's protocol chain.

        The chain rather than the frame count, because a count alone cannot tell
        a frame that parsed from one that was downgraded to
        :class:`~pcapkit.protocols.misc.raw.Raw` on the way past.

        """
        from pcapkit.foundation.extraction import Extractor

        extractor = Extractor(path, nofile=True, store=True)
        try:
            return [str(frame.protochain) for frame in extractor.frame]
        finally:
            close_extractor(extractor)

    def test_an_unassigned_block_type_no_longer_costs_the_extraction(self) -> None:
        """The issue's repro, with a packet block behind the unknown one.

        Measured on the unfixed tree, ``Extractor`` raised ``ValueError: 28 is
        not a valid BlockType`` and produced nothing at all -- so the Enhanced
        Packet Block behind the unknown block was lost along with it, which is
        what "one unknown block costs the whole extraction" means.

        The control is the same capture without the unknown block, and the
        assertion is that the two agree. Asserting the pair is what tells a
        restored skip apart from an extraction that has merely stopped raising
        while still dropping the rest of the file, and comparing the protocol
        chains rather than the counts is what tells it apart from one that kept
        the frame but gave up on parsing it.

        """
        control = _capture(_SHB, _IDB, _EPB)
        reported = _capture(_SHB, _IDB, _UNKNOWN, _EPB)
        try:
            expected = self._protochains(control)
            self.assertEqual(len(expected), 1,
                             'control capture should yield its one packet block')
            self.assertEqual(self._protochains(reported), expected,
                             'the unknown block should be skipped, not fatal')
        finally:
            os.unlink(control)
            os.unlink(reported)

    def test_the_unknown_block_reader_is_reachable_for_an_unassigned_code(self) -> None:
        """``UnknownBlock`` was unreachable, and this is the dispatch that proves it.

        Both halves of the dispatch were always in place -- ``__block__`` falls
        back to ``'unknown'`` for a code it does not register, and the block-type
        schema registry's ``__default__`` selects
        :class:`~pcapkit.protocols.schema.misc.pcapng.UnknownBlock`. Neither was
        reachable for a genuinely unassigned code, because the enum lookup failed
        first. With the code resolving, both answer.

        """
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.corekit.fields.numbers import EnumField
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.protocols.schema.misc.pcapng import BlockType as Schema_BlockType
        from pcapkit.protocols.schema.misc.pcapng import UnknownBlock

        resolved = EnumField(length=4, namespace=BlockType).unpack(
            UNASSIGNED_BLOCK_OCTETS, dict())

        self.assertEqual(PCAPNG._lookup_registry(PCAPNG.__block__, resolved), 'unknown')
        self.assertIs(Schema_BlockType.registry.default_factory(), UnknownBlock)


if __name__ == '__main__':
    unittest.main()
