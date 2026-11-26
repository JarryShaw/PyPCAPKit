# -*- coding: utf-8 -*-
"""The AppType generator emits the short member form (#3055).

A member is ``key = port`` where its service name is its key, and
``key = port, 'svc'`` where the two differ; neither repeats the transport, which
``AppType.__new__`` takes from ``__transport__``. Rendered offline from rows built
here, and the template's ``__new__`` and ``_generate_next_value_`` checked against
the committed base module, which only a run against IANA's live CSV regenerates.

"""
from __future__ import annotations

import importlib.util
import pathlib
import unittest

#: Test tier (#1958): imports the crawlers, whose extra is on ``latest`` alone.
__tier__ = 'LATEST'

#: Repository root.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Every distribution importing :mod:`pcapkit.vendor` needs -- see
#: :mod:`tests.vendor.test_ipx_packet_unit` for why each is checked.
VENDOR_DEPS = ('requests', 'bs4', 'html5lib')

#: Whether the crawlers are importable at all.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: IANA's CSV header, then one row per member form.
ROWS = [
    'Service Name,Port Number,Transport Protocol,Description,Assignee,Contact,'
    'Registration Date,Modification Date,Reference,Service Code,'
    'Unauthorized Use Reported,Assignment Notes',
    'exp2,1022,tcp,RFC3692-style Experiment 2,,,,,,,,',
    'ltp-deepspace,1113,tcp,Licklider Transmission Protocol,,,,,,,,',
    'reserved,8282,tcp,Reserved,,,,,,,,',
    'exp2,1022,udp,RFC3692-style Experiment 2,,,,,,,,',
]

#: Where ``__new__`` starts, and the member after ``_generate_next_value_``.
NEW_START = "    def __new__(cls, value: 'int', name: 'str',"
NEW_END = '    @property\n    def aliases('


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class AppTypeMemberForm3055Tests(unittest.TestCase):
    """What the generator writes for a member, and the hooks that read it."""

    def test_a_member_gives_its_name_only_where_it_differs_from_its_key(self) -> None:
        from pcapkit.vendor.reg.apptype.tcp import TCP

        crawler = TCP.__new__(TCP)
        crawler.record = crawler.count(ROWS)
        enum, _ = crawler.process(ROWS)

        self.assertEqual([entry.splitlines()[-1].strip() for entry in enum],
                         ['exp2 = 1022', "ltp_deepspace = 1113, 'ltp-deepspace'",
                          "reserved_8282 = 8282, 'reserved'"])

    def test_rendered_hooks_match_the_committed_base_module(self) -> None:
        from pcapkit.vendor.reg.apptype.apptype import BASE, AppType

        rendered = BASE('AppType', AppType.__doc__, AppType.FLAG, '', '',
                        'pcapkit.vendor.reg.apptype.apptype')
        committed = (ROOT / 'pcapkit' / 'const' / 'reg' / 'apptype' / 'apptype.py').read_text(
            encoding='utf-8')

        def hooks(text: 'str') -> 'str':
            start = text.index(NEW_START)
            return text[start:text.index(NEW_END, start)]

        self.assertEqual(hooks(rendered), hooks(committed))
        self.assertIn('    def _generate_next_value_(', hooks(committed))


if __name__ == '__main__':
    unittest.main()
