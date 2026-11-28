# -*- coding: utf-8 -*-
"""The :mod:`pcapkit.vendor.smtp` crawlers render their ``DATA`` into the committed modules (#2960).

No registry lists SMTP's commands or reply codes, so each crawler reads a ``DATA``
literal transcribed from RFC 5321, and running it reproduces its
:mod:`pcapkit.const.smtp` module byte for byte. Nothing is fetched or written.

"""
from __future__ import annotations

import pathlib
import unittest

#: Test tier (#1958): the vendor extra is installed on latest alone, as for the
#: other crawler tests.
__tier__ = 'LATEST'

#: The repository root.
ROOT = pathlib.Path(__file__).resolve().parents[2]


def _render(crawler: 'type') -> 'str':
    """The module ``crawler`` writes, as :meth:`Vendor.__init__ <pcapkit.vendor.default.Vendor.__init__>`
    writes it, with no fetch and no write."""
    self = object.__new__(crawler)
    self.NAME = crawler.__name__
    self.DOCS = crawler.__doc__
    data = self._request()
    self.record = self.count(data)
    lines = [line.rstrip() for line in self.context(data).splitlines() if not line or line.strip()]
    return '\n'.join(lines) + '\n'


class SMTPCrawlerTests(unittest.TestCase):
    """Each crawler against its committed module."""

    def test_crawlers_reproduce_their_modules(self) -> None:
        from pcapkit.vendor.smtp.command import Command
        from pcapkit.vendor.smtp.reply_code import ReplyCode

        for crawler, module in ((Command, 'command'), (ReplyCode, 'reply_code')):
            with self.subTest(crawler=crawler.__name__):
                committed = (ROOT / 'pcapkit' / 'const' / 'smtp' / f'{module}.py').read_text()
                self.assertEqual(_render(crawler), committed)

    def test_data_is_rfc_5321(self) -> None:
        """The commands of section 4.1.1, and the reply codes of section 4.2.3 with
        the 530 RFC 4954 defines and RFC 6409 uses."""
        from pcapkit.vendor.smtp.command import DATA as COMMANDS
        from pcapkit.vendor.smtp.reply_code import DATA as CODES

        self.assertEqual(list(COMMANDS), ['EHLO', 'HELO', 'MAIL', 'RCPT', 'DATA', 'RSET', 'VRFY',
                                          'EXPN', 'HELP', 'NOOP', 'QUIT'])
        listed = (':rfc:`5321#section-4.2.3`',)
        self.assertEqual(sorted(code for code, (_, cites) in CODES.items() if cites != listed), [530])
        self.assertEqual(CODES[530][1], (':rfc:`4954#section-6`', ':rfc:`6409#section-4.3`'))

    def test_exports(self) -> None:
        import pcapkit.const.smtp as const
        import pcapkit.vendor.smtp as vendor

        self.assertEqual(vendor.__all__, const.__all__)
        for name in vendor.__all__:
            with self.subTest(name=name):
                self.assertEqual(getattr(vendor, name).__name__, getattr(const, name).__name__)


if __name__ == '__main__':
    unittest.main()
