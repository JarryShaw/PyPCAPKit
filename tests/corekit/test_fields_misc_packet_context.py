from __future__ import annotations

import importlib.util
import sys
import unittest
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class NestedPacketContextTests(unittest.TestCase):
    """The packet context a nested schema's field callbacks see -- issue #445.

    ``SchemaField.pack``/``unpack`` used to hand a nested schema a nested
    context whose *only* content was ``{'__packet__': packet}``: a name the
    nested schema declares itself resolves normally, but a name it does not
    declare -- which every top-level schema writes as ``pkt['length']`` and
    which a nested one inherited unmodified -- raised :exc:`KeyError` instead
    of reaching the enclosing schema. ``pcapkit.corekit.fields.misc.
    nested_packet_context`` replaces that literal with a two-level
    :class:`collections.ChainMap`, so a name absent locally falls through to
    the enclosing schema, while ``__packet__`` keeps naming it explicitly.

    :meth:`test_nested_schema_reads_enclosing_field_by_name_and_does_not_leak_writes`
    is the load-bearing case: it fails with the recorded ``KeyError`` before
    the fix and passes after, and in the same pass checks that the mapping
    does not confuse a name the nested schema shadows with the enclosing
    schema's own, and that nothing the nested schema writes through the
    mapping is ever written back to the enclosing schema's own data.

    An intermediate version of this fix used a hand-written :class:`dict`
    subclass instead of :class:`collections.ChainMap`, adopted when a bare
    ``ChainMap`` was (wrongly) suspected of corrupting a shared
    :class:`~abc.ABCMeta` cache on CPython <= 3.10 (issue #439). Both the
    suspicion and the workaround it produced have since been retired: #439
    was fixed directly, and the hand-written subclass's own
    ``.setdefault()`` bypassed the fallback the same way :class:`dict`'s
    built-in one does, silently inserting a name locally instead of
    honouring what the enclosing schema already had for it --
    :meth:`test_nested_schema_reads_enclosing_field_by_name_and_does_not_leak_writes`
    pins the corrected behaviour (``setdefault`` on a name absent locally but
    present in the parent returns the parent's value rather than inserting a
    new one) precisely because that was the gap. See
    :func:`pcapkit.corekit.fields.misc.nested_packet_context` for the full
    history.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _make_schema_classes(self):
        """Outer/Inner pair mirroring ``CGAParametersOption``/``CGAParameter``.

        ``Inner`` declares its own ``tag`` (shadowing ``Outer.tag``, with a
        different value) and a ``body`` sized from ``pkt['length']`` -- a name
        only ``Outer`` declares. ``captured`` is filled in by ``Inner.
        post_process``, which runs after every one of ``Inner``'s own fields
        has been parsed and set, so it can inspect the fully populated packet
        context: the shadowed name, the name that had to fall through, an
        explicit ``__packet__`` lookup, ``in``, ``.get()`` and the mapping's
        own keys.

        """
        from pcapkit.corekit.fields.misc import SchemaField
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.corekit.fields.strings import BytesField
        from pcapkit.protocols.schema.schema import Schema, schema_final

        captured = {}

        @schema_final
        class Inner(Schema):
            """No 'length' of its own; 'tag' shadows the enclosing schema's."""

            tag: int = UInt8Field()
            body: bytes = BytesField(length=lambda pkt: pkt['length'] - 1)

            def post_process(self, packet):
                captured['own_tag'] = packet['tag']
                captured['fallback_length'] = packet['length']
                captured['explicit_outer_tag'] = packet['__packet__']['tag']
                captured['has_length'] = 'length' in packet
                captured['has_missing'] = 'no_such_name' in packet
                captured['get_length'] = packet.get('length', 'sentinel')
                captured['get_missing'] = packet.get('no_such_name', 'sentinel')
                captured['keys'] = set(packet.keys())
                captured['dict_star'] = dict(**packet)
                # setdefault on a name absent locally but present in the
                # parent must honour the fallback (return 42, not overwrite
                # it with 999) -- a plain dict subclass's own setdefault
                # bypasses __missing__ the same way get/__contains__ do, and
                # would insert 999 locally instead. ChainMap.setdefault
                # delegates through __contains__/__getitem__, so it does not.
                captured['setdefault_existing'] = packet.setdefault('length', 999)
                captured['setdefault_new'] = packet.setdefault('brand_new', 7)
                # A copy must keep seeing the parent, and writes to the copy
                # must stay local to the copy (never touch the original, and
                # never touch the shared parent either).
                snapshot = packet.copy()
                snapshot['tag'] = 0xFF
                captured['copy_sees_parent_length'] = snapshot['length']
                captured['copy_write_did_not_leak_to_original'] = packet['tag']
                # A live reference, not a copy: read again after ``Outer``
                # finishes, to prove this schema's writes never landed in it.
                captured['parent_ref'] = packet['__packet__']
                return self

        @schema_final
        class Outer(Schema):
            tag: int = UInt8Field()
            length: int = UInt8Field()
            inner: Inner = SchemaField(length=lambda pkt: pkt['length'], schema=Inner)

        return Inner, Outer, captured

    def test_nested_schema_reads_enclosing_field_by_name_and_does_not_leak_writes(self) -> None:
        _Inner, Outer, captured = self._make_schema_classes()

        # tag=0xAA, length=3 (Inner's own total size), then Inner's own
        # tag=0x22 (one octet) and a 2-octet body.
        raw = b'\xaa\x03\x22\xbb\xcc'
        outer = Outer.unpack(raw, len(raw), None)

        # The bug, fixed: 'length' is not Inner's own field, and resolves to
        # Outer's by falling through rather than raising KeyError.
        self.assertEqual(outer.inner.body, b'\xbb\xcc')
        self.assertEqual(captured['fallback_length'], 3)

        # Shadowing: Inner's own 'tag' (0x22) is not confused with Outer's
        # (0xAA), and the latter is still reachable explicitly.
        self.assertEqual(captured['own_tag'], 0x22)
        self.assertEqual(outer.tag, 0xAA)
        self.assertEqual(captured['explicit_outer_tag'], 0xAA)

        # ``in`` and ``.get()`` honour the same fallback as ``__getitem__``.
        self.assertTrue(captured['has_length'])
        self.assertFalse(captured['has_missing'])
        self.assertEqual(captured['get_length'], 3)
        self.assertEqual(captured['get_missing'], 'sentinel')

        # Iterating the mapping sees the union of both levels, however it is
        # asked for: .keys(), or plain dict(**pkt).
        expected_keys = {'__packet__', '__length__', 'tag', 'length', 'body'}
        self.assertEqual(captured['keys'], expected_keys)
        self.assertEqual(set(captured['dict_star']), expected_keys)

        # setdefault falls through to the parent for a name absent locally
        # (returning its existing value, 3, not inserting a new local 999),
        # and behaves like a normal dict.setdefault for a name absent
        # everywhere.
        self.assertEqual(captured['setdefault_existing'], 3)
        self.assertEqual(captured['setdefault_new'], 7)

        # A copy still sees the parent, and a write to the copy never
        # reaches the original it was copied from.
        self.assertEqual(captured['copy_sees_parent_length'], 3)
        self.assertEqual(captured['copy_write_did_not_leak_to_original'], 0x22)

        # The write path: nothing Inner set (its own 'tag', 'body', ...) is
        # visible on Outer's own packet data once Outer is done. Outer's own
        # 'tag' is exactly what it was, not clobbered by Inner's shadowing
        # write of the same name.
        parent = captured['parent_ref']
        self.assertEqual(parent['tag'], 0xAA)
        self.assertNotIn('body', parent)

    def test_pcapng_byteorder_consumer_still_works_with_both_shapes(self) -> None:
        """The one existing, hand-rolled ``__packet__`` fallback is unaffected.

        ``packet_byteorder`` (``pcapkit/protocols/schema/misc/pcapng.py:168``)
        is called both with a plain dict built by hand -- as several tests and
        :func:`~pcapkit.foundation.engines.pcapng` construct -- and with what
        ``SchemaField`` now actually builds. Both must keep working, and
        neither is expected to change: the site already implements the
        fallback itself and does not route through
        :func:`~pcapkit.corekit.fields.misc.nested_packet_context`.

        """
        from pcapkit.corekit.fields.misc import nested_packet_context
        from pcapkit.protocols.schema.misc.pcapng import packet_byteorder

        outer = {'byteorder': 'little'}

        # Hand-built, the shape every existing caller uses.
        self.assertEqual(packet_byteorder({'__packet__': outer}), 'little')
        # What SchemaField hands a real nested schema now.
        self.assertEqual(packet_byteorder(nested_packet_context(outer)), 'little')
        # No enclosing packet at all -- the top-level case.
        self.assertEqual(packet_byteorder({}), sys.byteorder)
        # The nested schema's own 'byteorder' takes precedence either way.
        self.assertEqual(packet_byteorder({'byteorder': 'big', '__packet__': outer}), 'big')
        local = nested_packet_context(outer)
        local['byteorder'] = 'big'
        self.assertEqual(packet_byteorder(local), 'big')

    @unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
    def test_pcapng_block_type_mismatch_consumer_still_works_with_both_shapes(self) -> None:
        """The other hand-rolled fallback, ``BlockType.post_process``.

        Mirrors ``tests/protocols/misc/test_pcapng_unit.py``'s own
        ``UnknownBlock(...).post_process({'__packet__': {...}})`` call, and
        additionally checks it still resolves the enclosing block's type when
        handed what ``SchemaField`` builds today.

        """
        from pcapkit.corekit.fields.misc import nested_packet_context
        from pcapkit.const.pcapng.block_type import BlockType
        import pcapkit.protocols.schema.misc.pcapng as schema_pcapng

        mismatch = schema_pcapng.UnknownBlock(length=16, body=b'abcd', length2=20)
        outer = {'type': BlockType.Reserved_0x00000000}

        # A found outer 'type' renders its code into the message; the
        # fallback default, 'N/A', is what a lookup miss would show instead.
        with mock.patch('pcapkit.protocols.schema.misc.pcapng.warn') as warn:
            mismatch.post_process({'__packet__': outer})
        warn.assert_called_once()
        self.assertNotIn('N/A', warn.call_args.args[0])

        with mock.patch('pcapkit.protocols.schema.misc.pcapng.warn') as warn:
            mismatch.post_process(nested_packet_context(outer))
        warn.assert_called_once()
        self.assertNotIn('N/A', warn.call_args.args[0])


class CGAParametersRegressionTests(unittest.TestCase):
    """The measured casualty from issue #445, end to end.

    A CGA Parameters option could not be parsed at all: sizing
    ``CGAParameter.extensions`` (``pcapkit/protocols/schema/internet/mh.py``,
    ``CGAParameter.extensions``) reads ``pkt['length']``, a name only the
    enclosing ``CGAParametersOption`` declares. No change to ``mh.py`` itself
    was needed -- the fallback in ``nested_packet_context`` resolves it.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_cga_parameters_option_now_parses_end_to_end(self) -> None:
        from pcapkit.const.mh.option import Option as Enum_Option
        from pcapkit.protocols.internet.mh import MH

        # The exact 40-octet reproduction from issue #445.
        raw = bytes.fromhex(
            '11040000123400000c1e'
            '0000000000000000000000000000086f'
            '0000000020010db8'
            '00'
            '3003010203'
        )
        self.assertEqual(len(raw), 40)

        # #446 (ForwardMatchField counted into Schema.__len__, fixed on
        # #456/main) was a second, separate defect blocking this exact
        # option: with #445 alone, this reached FieldValueError: Field
        # parameters has invalid length rather than parsing. With both
        # fixes applied, CGA Parameters parses end to end.
        m = MH(raw, len(raw), extension=True)
        option = m.info.options[Enum_Option.CGA_Parameters]
        parameter = option.parameters[0]
        self.assertEqual(parameter.prefix, 0x20010db8)
        self.assertEqual(parameter.collision_count, 0)
        self.assertEqual(parameter.public_key, b'\x30\x03\x01\x02\x03')
        self.assertEqual(len(parameter.extensions), 0)
