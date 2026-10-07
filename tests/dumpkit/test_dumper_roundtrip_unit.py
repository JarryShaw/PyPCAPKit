# -*- coding: utf-8 -*-
"""Every output writer keeps what the extracted packets carried.

- GitHub issue #1255: the ``pcap`` writer wrote version 2.4 whatever the input's
  global header carried.
- GitHub issue #1257: the ``plist`` writer skipped every :data:`None` value and
  list item.
- GitHub issue #1258: networks, :data:`~pcapkit.corekit.sentinels.NULL` and
  :data:`~pcapkit.corekit.sentinels.NO_VALUE` dumped as ``{}``, and a timezone
  as a bare string after an ``unsupported object type`` warning.
- GitHub issue #1261: the ``json`` writer escaped a character above ``U+FFFF``
  as five or six hex digits.
- GitHub issue #1262: the ``plist`` writer wrote control characters raw.
- GitHub issue #1263: an :class:`~pcapkit.corekit.multidict.OrderedMultiDict`
  dumped grouped by key, losing its order.

Every case builds its input in memory or in a temporary directory, and reads no
capture. :mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import datetime
import importlib.util
import ipaddress
import json
import os
import plistlib
import struct
import tempfile
import unittest
import warnings

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


def pcap_file(major: 'int', minor: 'int') -> 'bytes':
    """A little-endian PCAP file of the given version holding one Ethernet frame."""
    frame = bytes.fromhex('0123456789ab' 'fedcba987654' '88b5') + b'payload'
    header = struct.pack('<IHHiIII', 0xA1B2C3D4, major, minor, 0, 0, 0xFFFF, 1)
    record = struct.pack('<IIII', 1, 2, len(frame), len(frame))
    return header + record + frame


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestDumperRoundTrip(unittest.TestCase):
    """Pin what each writer puts in the file, by reading the file back."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        self.tmpdir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self.tmpdir.cleanup)

    def dump(self, kind: 'str', value: 'dict[str, object]') -> 'bytes':
        """Dump ``value`` through the customised ``dictdumper`` writer ``kind``."""
        import dictdumper

        from pcapkit.dumpkit.common import make_dumper

        path = os.path.join(self.tmpdir.name, f'out.{kind.lower()}')
        make_dumper(getattr(dictdumper, kind))(path)(value, name='x')
        with open(path, 'rb') as file:
            return file.read()

    def test_pcap_output_keeps_the_input_version(self) -> None:
        """#1255: the output global header carries the input's version."""
        from pcapkit import extract

        for version in ((2, 2), (2, 3), (2, 4)):
            with self.subTest(version=version):
                src = os.path.join(self.tmpdir.name, 'in.pcap')
                dst = os.path.join(self.tmpdir.name, 'out.pcap')
                with open(src, 'wb') as file:
                    file.write(pcap_file(*version))
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    extract(fin=src, fout=dst, format='pcap', store=False, extension=False)
                with open(dst, 'rb') as file:
                    self.assertEqual(file.read(), pcap_file(*version))

    def test_plist_keeps_none_values_and_items(self) -> None:
        """#1257: a :data:`None` value or item is written, not skipped."""
        none = {'type': 'NoneType', 'value': 'None'}
        got = plistlib.loads(self.dump('PLIST', {'error': None, 'items': [1, None, 2]}))['x']
        self.assertEqual(got, {'error': none, 'items': [1, none, 2]})

    def test_unhandled_value_types_get_an_explicit_rendering(self) -> None:
        """#1258: networks, sentinels and timezones no longer dump as ``{}``."""
        from pcapkit.corekit.sentinels import NO_VALUE, NULL

        value = {
            'net4': ipaddress.IPv4Network('10.0.0.0/8'),
            'net6': ipaddress.IPv6Network('::/0'),
            'nv': NO_VALUE,
            'nl': NULL,
            'tz': datetime.timezone(datetime.timedelta(hours=8)),
        }
        with self.assertNoLogs('pcapkit', level='WARNING'):
            got = json.loads(self.dump('JSON', value))['x']
        self.assertEqual(got, {'net4': '10.0.0.0/8', 'net6': '::/0', 'nv': '<NO_VALUE>',
                               'nl': '<NULL>', 'tz': 28800.0})

    def test_fallback_reads_the_slots_of_every_base_class(self) -> None:
        """#1258: a leaf ``__slots__ = ()`` no longer hides its bases' slots."""

        class Base:
            __slots__ = ('first', 'unset')

        class Middle(Base):
            __slots__ = 'second'

        class Leaf(Middle):
            __slots__ = ()

        obj = Leaf()
        obj.first, obj.second = 1, 'a<b'
        self.assertEqual(json.loads(self.dump('JSON', {'o': obj}))['x'], {'o': {'first': 1, 'second': 'a<b'}})
        self.assertEqual(plistlib.loads(self.dump('PLIST', {'o': obj}))['x'], {'o': {'first': 1, 'second': 'a<b'}})

    def test_json_writes_astral_characters_as_surrogate_pairs(self) -> None:
        """#1261: a character above ``U+FFFF`` round-trips through ``json``."""
        value = {'c': 'smile \U0001F600', 'bmp': 'a\x7f\x0bé"\\\n'}
        data = self.dump('JSON', value)
        self.assertIn(b'"smile \\ud83d\\ude00"', data)
        # Every other character is spelt exactly as the upstream writer does.
        self.assertIn(b'"a\\u007f\\u000b\\u00e9\\"\\\\\\n"', data)
        self.assertEqual(json.loads(data)['x'], value)

    def test_plist_writes_strings_xml_cannot_spell_as_data(self) -> None:
        """#1262: a control character no longer makes the document unparseable."""
        value = {'c': 'a\x01b\x1bc', 'ok': 'tab\there & <there>'}
        got = plistlib.loads(self.dump('PLIST', value))['x']
        self.assertEqual(got, {'c': 'a\x01b\x1bc'.encode(), 'ok': 'tab\there & <there>'})

    def test_ordered_multidict_dumps_in_insertion_order(self) -> None:
        """#1263: one single-key mapping per entry, in insertion order."""
        from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict

        ordered = OrderedMultiDict([('NOP', 1), ('M&S', 2), ('NOP', 3)])
        expected = [{'NOP': 1}, {'M&S': 2}, {'NOP': 3}]
        self.assertEqual(json.loads(self.dump('JSON', {'o': ordered}))['x']['o'], expected)
        self.assertEqual(plistlib.loads(self.dump('PLIST', {'o': ordered}))['x']['o'], expected)

        # A MultiDict keeps no order across keys, so it is still grouped.
        multi = MultiDict([('NOP', 1), ('MSS', 2), ('NOP', 3)])
        self.assertEqual(json.loads(self.dump('JSON', {'m': multi}))['x']['m'], {'NOP': [1, 3], 'MSS': [2]})


if __name__ == '__main__':
    unittest.main()
