# -*- coding: utf-8 -*-
"""The byte-order callback the PCAP and PCAP-NG schemas share.

GitHub issue #1519. One helper serves both the PCAP frame header and the
PCAP-NG blocks, with the PCAP-NG body and its fallback to an enclosing
``__packet__``: a superset that gives the frame header the same answer on every
packet the
library hands it, since :meth:`Frame.pack
<pcapkit.protocols.misc.pcap.frame.Frame.pack>` and :meth:`Frame.unpack
<pcapkit.protocols.misc.pcap.frame.Frame.unpack>` always seed ``byteorder``.
This pins the helper, its ``__packet__`` fallback, and that both schemas use it.

Per GitHub issue #1711 the helper lives in
:mod:`pcapkit.corekit.fields.byteorder`, with no re-export at
``pcapkit.protocols.schema.misc.byteorder``. This also pins that importing it
fails, and that the module reaches no higher than
:mod:`pcapkit.corekit`.

"""

import ast
import importlib
import pathlib
import struct
import sys
import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): exercises integer, bytes and struct edge cases, whose limits
#: differ by interpreter.
__tier__ = 'ALL'

SHARED = 'pcapkit.corekit.fields.byteorder'

#: The path the helper moved from (#1711); nothing is left there, not even a re-export.
OLD_PATH = 'pcapkit.protocols.schema.misc.byteorder'

#: Source of :data:`SHARED`, read with :mod:`ast` rather than imported.
MODULE = pathlib.Path(__file__).resolve().parents[2] / 'pcapkit' / 'corekit' / 'fields' / 'byteorder.py'

#: The byte order that is not the host's, so a fallback to the host is visible.
OTHER = 'big' if sys.byteorder == 'little' else 'little'

#: ``(packet, expected byte order)``: its own key first, then the enclosing
#: packet's, then the host's.
CASES = (
    ({'byteorder': OTHER}, OTHER),
    ({'byteorder': sys.byteorder}, sys.byteorder),
    ({'__packet__': {'byteorder': OTHER}}, OTHER),
    ({'byteorder': OTHER, '__packet__': {'byteorder': sys.byteorder}}, OTHER),
    ({'byteorder': sys.byteorder, '__packet__': {'byteorder': OTHER}}, sys.byteorder),
    ({'__packet__': {}}, sys.byteorder),
    ({}, sys.byteorder),
)


class TestSchemaByteorder(unittest.TestCase):
    """Pin the shared byte-order helper and its use by both schemas."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _shared(self) -> 'object':
        return importlib.import_module(SHARED)

    def test_packet_byteorder_resolution(self) -> None:
        shared = self._shared()
        for packet, expected in CASES:
            with self.subTest(packet=packet):
                self.assertEqual(shared.packet_byteorder(packet), expected)

    def test_callback_sets_the_field_byte_order(self) -> None:
        from pcapkit.corekit.fields.numbers import UInt32Field

        shared = self._shared()
        for packet, expected in CASES:
            with self.subTest(packet=packet):
                field = UInt32Field()
                shared.byteorder_callback(field, packet)
                self.assertEqual(field._byteorder, expected)  # pylint: disable=protected-access

    def test_frame_and_pcapng_use_the_shared_helper(self) -> None:
        frame = importlib.import_module('pcapkit.protocols.schema.misc.pcap.frame')
        pcapng = importlib.import_module('pcapkit.protocols.schema.misc.pcapng')
        shared = self._shared()

        self.assertIs(frame.byteorder_callback, shared.byteorder_callback)
        self.assertIs(pcapng.byteorder_callback, shared.byteorder_callback)
        self.assertIs(pcapng.packet_byteorder, shared.packet_byteorder)
        for name in ('ts_sec', 'ts_usec', 'incl_len', 'orig_len'):
            with self.subTest(field=name):
                self.assertIs(frame.Frame.__fields__[name]._callback,  # pylint: disable=protected-access
                              shared.byteorder_callback)

    def test_frame_header_reads_the_byte_order_it_is_given(self) -> None:
        frame = importlib.import_module('pcapkit.protocols.schema.misc.pcap.frame')
        raw = struct.pack('>IIII' if OTHER == 'big' else '<IIII', 1, 2, 0, 0)
        for packet in ({'byteorder': OTHER}, {'__packet__': {'byteorder': OTHER}}):
            with self.subTest(packet=packet):
                header = frame.Frame.unpack(raw, len(raw), dict(packet))
                self.assertEqual((header.ts_sec, header.ts_usec), (1, 2))
                self.assertEqual(header.pack(dict(packet)), raw)

    def test_the_schema_misc_byteorder_path_does_not_import(self) -> None:
        """#1711: the move leaves no re-export at ``pcapkit.protocols.schema.misc.byteorder``."""
        with self.assertRaises(ModuleNotFoundError) as ctx:
            importlib.import_module(OLD_PATH)
        self.assertEqual(ctx.exception.name, OLD_PATH)

        package = importlib.import_module(OLD_PATH.rpartition('.')[0])
        self.assertFalse(hasattr(package, 'byteorder'))

    def test_the_module_imports_nothing_from_foundation_or_protocols(self) -> None:
        """``corekit`` sits below both, so the helper may not reach up to either."""
        tree = ast.parse(MODULE.read_text(encoding='utf-8'))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0, f'relative import at line {node.lineno}')
                imported.append(node.module or '')
        self.assertTrue(imported)
        for name in imported:
            with self.subTest(module=name):
                self.assertFalse(name.startswith(('pcapkit.foundation', 'pcapkit.protocols')), name)


if __name__ == '__main__':
    unittest.main()
