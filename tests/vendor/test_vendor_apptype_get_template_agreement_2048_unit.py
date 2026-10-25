# -*- coding: utf-8 -*-
"""The AppType generator and its committed base module agree on #2048's rule.

GitHub issue #2048. Every in-range port answers with the asking registry's own
transport. That lives in ``get``'s ``unknown`` fallback for a port
``_missing_`` holds no span for, and in the span branches the generator renders
into ``_missing_``. Regenerating :mod:`pcapkit.const.reg.apptype.apptype` needs
IANA's live CSV, so an edit to the template in
:mod:`pcapkit.vendor.reg.apptype.apptype` is made to the committed module by
hand. These render the template offline and check it against the committed module.

"""
from __future__ import annotations

import importlib.util
import pathlib
import unittest

#: Test tier (#1958): checks the AppType generator's template against the
#: committed module, and imports the crawlers, whose extra is on ``latest`` alone.
__tier__ = 'LATEST'

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Every distribution importing :mod:`pcapkit.vendor` needs -- see
#: :mod:`tests.vendor.test_ipx_packet_unit` for why each is checked.
VENDOR_DEPS = ('requests', 'bs4', 'html5lib')

#: Whether the crawlers are importable at all.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: Where ``get`` starts and where the method after it starts, in both texts.
GET_START = "    @classmethod\n    def get(cls, key: 'int', *,"
GET_END = '    @classmethod\n    def get_all('


def _get_method(text: 'str') -> 'str':
    """The source text of ``get`` within a rendering of the base module."""
    start = text.index(GET_START)
    return text[start:text.index(GET_END, start)]


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class AppTypeGetTemplateAgreement2048Tests(unittest.TestCase):
    """The template's ``get`` renders to the committed one."""

    def test_rendered_get_matches_committed_get(self) -> None:
        from pcapkit.vendor.reg.apptype.apptype import BASE, AppType

        rendered = BASE('AppType', AppType.__doc__, AppType.FLAG, '', '',
                        'pcapkit.vendor.reg.apptype.apptype')
        committed = (ROOT / 'pcapkit' / 'const' / 'reg' / 'apptype' / 'apptype.py').read_text(
            encoding='utf-8')

        self.assertEqual(_get_method(rendered), _get_method(committed))

    def test_rendered_get_falls_back_to_unknown_on_the_registrys_transport(self) -> None:
        from pcapkit.vendor.reg.apptype.apptype import BASE, AppType

        method = _get_method(BASE('AppType', AppType.__doc__, AppType.FLAG, '', '',
                                  'pcapkit.vendor.reg.apptype.apptype'))

        self.assertIn("_unregistered_member(key, 'unknown', owner.__transport__)", method)
        self.assertNotIn("'unassigned'", method)

    def test_a_span_naming_no_transport_answers_with_the_registrys(self) -> None:
        """A span IANA lists for one transport keeps its claim and its transport."""
        from pcapkit.vendor.reg.apptype.apptype import AppType

        _, miss = AppType.__new__(AppType).records([
            'Service Name,Port Number,Transport Protocol,Description,Assignee,Contact,'
            'Registration Date,Modification Date,Reference,Service Code,'
            'Unauthorized Use Reported,Assignment Notes',
            ',8012-8014,,Unassigned,,,,,,,,',
            'x11,6000-6063,tcp,X Window System,,,,,,,,',
        ])

        self.assertEqual(miss[0], 'if 8012 <= value <= 8014:')
        self.assertEqual(miss[2], "    return cls._unregistered_member(value, 'unassigned', "
                                  'cls.__transport__)')
        self.assertEqual(miss[3], 'if 6000 <= value <= 6063 and cls.__transport__ is '
                                  'TransportProtocol.tcp:')
        self.assertEqual(miss[5], "    return cls._unregistered_member(value, 'x11', "
                                  'TransportProtocol.tcp)')

    def test_committed_spans_naming_no_transport_answer_with_the_registrys(self) -> None:
        source = (ROOT / 'pcapkit' / 'const' / 'reg' / 'apptype' / 'apptype.py').read_text(
            encoding='utf-8')
        method = source[source.index('    def _missing_(cls, value'):]

        self.assertNotIn('TransportProtocol.undefined)', method)
        self.assertIn("_unregistered_member(value, 'unassigned', cls.__transport__)", method)


if __name__ == '__main__':
    unittest.main()
