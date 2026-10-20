# -*- coding: utf-8 -*-
"""The crawlers' comment wrappers emit text that renders as written.

Sphinx renders each ``#:`` comment in :mod:`pcapkit.const` as a reST paragraph,
with its continuation lines joined by a space, and an AppType ``list-table`` cell
the same way.

* GitHub issue #1846: ``[http://ele2.io][Damir Franusic]`` autolinked
  ``http://ele2.io][Damir``, since docutils reads ``]`` and ``[`` as URL
  characters, and ``(S) flag`` rendered as an enumerated list.
  :meth:`~pcapkit.vendor.default.Vendor.wrap_comment` now spaces a URL reference
  off the bracket after it and backslash-escapes a leading enumerator.
* GitHub issue #1847: :mod:`textwrap` broke lines at hyphens, so the docs read
  ``run- time``, and a URL split that way in a cell lost the rest of its
  autolink. Neither wrapper breaks at a hyphen now.

The committed :mod:`pcapkit.const` files were re-rendered offline with the
patched wrappers, so the last cases check the tree as well as the generators.
Nothing here makes a network call.

"""
from __future__ import annotations

import importlib.util
import pathlib
import re
import textwrap
import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): checks the vendor scripts' comment wrapper and the comments of
#: the committed constant modules.
__tier__ = 'LATEST'

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Every distribution importing :mod:`pcapkit.vendor` needs -- see
#: :mod:`tests.vendor.test_ipx_packet_unit` for why all three are checked.
VENDOR_DEPS = ('requests', 'bs4', 'html5lib')

#: Whether the crawlers are importable at all.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: Whether docutils, which Sphinx renders the comments with, is installed.
HAS_DOCUTILS = importlib.util.find_spec('docutils') is not None

#: ``pcapkit/const/http/status_code.py``'s ``CODE_104`` text, whose draft name
#: sits across the end of the second line.
RESUMABLE = ('Upload Resumption Supported (TEMPORARY - registered 2024-11-13, extension '
             'registered 2025-09-15, expires 2026-11-13) [draft-ietf-httpbis-resumable-upload-05]')

#: ``pcapkit/const/reg/apptype/tcp.py``'s ``rads`` text.
RADS = ('[TCP] Remote Administration Daemon (RAD) is a system service that offers secure, '
        'remote, programmatic access to Solaris system configuration and run-time state')

#: ``pcapkit/const/reg/apptype/tcp.py``'s ``boardgame`` cell.
BOARDGAME = ('[TCP] Two-player board game play '
             '[https://github.com/chentianren0/MiniXiangqi/blob/main/docs/boardgame-protocol.md]')

#: textwrap's own test for a break after a hyphen: two letters before it, and a
#: letter, an optional hyphen and a letter after it.
HYPHEN_BREAK = re.compile(r'(?:[^\d\W]{2}|[^\d\W]-[^\d\W])-\n *#:(?: - | +)?[^\d\W]-?[^\d\W]')


def _lines(wrapped: 'str') -> 'list[str]':
    """The text of each line of a wrapped comment, without its ``#:`` prefix."""
    return [re.sub(r'^ *#: *', '', line) for line in wrapped.split('\n')]


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class WrapCommentTests(unittest.TestCase):
    """:meth:`Vendor.wrap_comment` and AppType's wrappers."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

        import pcapkit.vendor.default as default

        resolved = pathlib.Path(default.__file__).resolve()
        if ROOT not in resolved.parents:
            self.skipTest(f'{default.__name__} was imported from {resolved}, which is '
                          f'outside {ROOT}; install this checkout with `pip install -e .`')

    def test_url_reference_is_spaced_off_the_next_bracket(self) -> None:
        from pcapkit.vendor.default import Vendor

        self.assertEqual(Vendor.wrap_comment('ELE2 Lawful Interception [http://ele2.io][Damir Franusic]'),
                         'ELE2 Lawful Interception [http://ele2.io] [Damir Franusic]')
        self.assertEqual(Vendor.wrap_comment('X [see https://example.com/a-b][RFC 1]'),
                         'X [see https://example.com/a-b] [RFC 1]')
        # Narrow: a bracket that holds no URL keeps its neighbour, and so does a
        # URL reference with no bracket after it.
        for text in ('REQUEST [:rfc:`826`][:rfc:`5227`]',
                     'ICTP [TR-352][Inter-Channel-Termination protocol]',
                     'NAME [http://ele2.io], [Damir Franusic]',
                     'NAME [http://ele2.io]'):
            with self.subTest(text=text):
                self.assertEqual(Vendor.wrap_comment(text), text)

    def test_leading_enumerator_is_escaped(self) -> None:
        from pcapkit.vendor.default import Vendor

        self.assertEqual(Vendor.wrap_comment('(S) flag [:rfc:`5844`]'), r'\(S) flag [:rfc:`5844`]')
        for text, expected in (('1. one', r'\1. one'), ('a) one', r'\a) one'),
                               ('(iv) one', r'\(iv) one'), ('#. one', r'\#. one'), ('(S)', r'\(S)')):
            with self.subTest(text=text):
                self.assertEqual(Vendor.wrap_comment(text), expected)
        # Only an enumerator, and only at the start of the text.
        for text in ('(S)flag', '(SS) flag', 'S flag', 'the (S) flag', 'Unassigned', '3GPP TS 38.463'):
            with self.subTest(text=text):
                self.assertEqual(Vendor.wrap_comment(text), text)

    def test_no_line_is_broken_at_a_hyphen(self) -> None:
        from pcapkit.vendor.default import Vendor

        # The width is unchanged, and the old wrap did split this one there.
        self.assertIn('[draft-ietf-httpbis-resumable-', textwrap.wrap(RESUMABLE, 76)[1])

        lines = _lines(Vendor.wrap_comment(RESUMABLE))
        self.assertEqual(lines, [
            'Upload Resumption Supported (TEMPORARY - registered 2024-11-13, extension',
            'registered 2025-09-15, expires 2026-11-13)',
            '[draft-ietf-httpbis-resumable-upload-05]',
        ])
        self.assertTrue(all(len(line) <= 76 for line in lines))

    def test_apptype_comment_is_broken_only_at_whitespace(self) -> None:
        from pcapkit.vendor.reg.apptype.apptype import AppType

        self.assertEqual(AppType.wrap_comment(RADS), (
            '[TCP] Remote Administration Daemon (RAD) is a system service that offers\n'
            '    #:   secure, remote, programmatic access to Solaris system configuration and\n'
            '    #:   run-time state'))
        # It escapes what the base escapes.
        self.assertEqual(AppType.wrap_comment('[TCP] X [http://a.example][B]'),
                         '[TCP] X [http://a.example] [B]')

    def test_apptype_cell_keeps_a_hyphenated_url_whole(self) -> None:
        from pcapkit.vendor.reg.apptype.apptype import AppType

        table = AppType.tabulate('Title', (30, 70), ('Service Name', 'Description'),
                                 [('``boardgame``', BOARDGAME)])
        # A continuation is indented by the docstring's four spaces and the
        # cell's seven.
        self.assertIn('\n' + ' ' * 11 +
                      '[https://github.com/chentianren0/MiniXiangqi/blob/main/docs/boardgame-protocol.md]\n',
                      table + '\n')
        self.assertNotRegex(table, r'-\n')

    @unittest.skipUnless(HAS_DOCUTILS, 'docutils not installed')
    def test_fixed_comments_render_as_plain_paragraphs(self) -> None:
        from docutils import nodes
        from docutils.core import publish_doctree

        from pcapkit.vendor.default import Vendor

        settings = {'report_level': 5, 'halt_level': 5}
        tree = publish_doctree(Vendor.wrap_comment('(S) flag [:rfc:`5844`]'), settings_overrides=settings)
        self.assertEqual([type(node) for node in tree.children], [nodes.paragraph])
        self.assertTrue(tree.astext().startswith('(S) flag'))

        tree = publish_doctree(Vendor.wrap_comment('ELE2 Lawful Interception [http://ele2.io][Damir Franusic]'),
                               settings_overrides=settings)
        self.assertEqual([type(node) for node in tree.children], [nodes.paragraph])
        self.assertEqual([node['refuri'] for node in tree.findall(nodes.reference)], ['http://ele2.io'])


class CommittedConstTests(unittest.TestCase):
    """The committed :mod:`pcapkit.const` files carry the re-rendered text."""

    def _read(self, *parts: 'str') -> 'str':
        return ROOT.joinpath('pcapkit', 'const', *parts).read_text(encoding='utf-8')

    def test_issue_1846_lines(self) -> None:
        self.assertIn('    #: \\(S) flag [:rfc:`5844`]\n    S_flag = 0x1\n',
                      self._read('mh', 'dhcp_support_mode.py'))
        self.assertIn('    #: ELE2 Lawful Interception [http://ele2.io] [Damir Franusic]\n',
                      self._read('sctp', 'payload_protocol_identifier.py'))

    def test_issue_1847_lines(self) -> None:
        self.assertIn('    #: [draft-ietf-httpbis-resumable-upload-05]\n', self._read('http', 'status_code.py'))
        tcp = self._read('reg', 'apptype', 'tcp.py')
        self.assertIn('    #: run-time state\n', tcp)
        self.assertIn('    #: (NG-PON2) system', tcp)
        self.assertIn('           [https://github.com/chentianren0/MiniXiangqi/blob/main/docs/boardgame-protocol.md]\n',
                      tcp)

    def test_no_comment_or_cell_is_broken_at_a_hyphen(self) -> None:
        cell = re.compile(r'(?:[^\d\W]{2}|[^\d\W]-[^\d\W])-\n {11}[^\d\W]-?[^\d\W]')
        for path in sorted(ROOT.joinpath('pcapkit', 'const').rglob('*.py')):
            source = path.read_text(encoding='utf-8')
            with self.subTest(path=str(path.relative_to(ROOT))):
                self.assertIsNone(HYPHEN_BREAK.search(source))
                if path.parent.name == 'apptype':
                    self.assertIsNone(cell.search(source))


if __name__ == '__main__':
    unittest.main()
