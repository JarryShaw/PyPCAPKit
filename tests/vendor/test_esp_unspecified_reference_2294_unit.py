# -*- coding: utf-8 -*-
"""Regression tests for GitHub issue #2294.

:meth:`Integrity.rfcs <pcapkit.vendor.esp.integrity.Integrity.rfcs>` returns
an empty string for a cell that names no document, whether IANA brackets the
placeholder (``[UNSPECIFIED]``) or not, by dropping one surrounding pair of
brackets before testing the cell against ``UNKNOWN``. Guards against testing
the cell as it stands: a bracketed placeholder matches no ``UNKNOWN``
spelling, and :mod:`pcapkit.const.esp.integrity` then renders as
``#: AUTH_DES_MAC [UNSPECIFIED] (DEPRECATED [:rfc:`8247`])``.
:meth:`Cipher.rfcs <pcapkit.vendor.esp.cipher.Cipher.rfcs>` shares the check,
though its registry spells the cell without brackets.

"""
from __future__ import annotations

import importlib.util
import pathlib
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): renders a constant module from recorded data and compares it
#: with the committed file, which the vendor scripts regenerate on one interpreter.
__tier__ = 'LATEST'

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Every distribution importing :mod:`pcapkit.vendor` needs -- see
#: :mod:`tests.vendor.test_ipx_packet_unit` for why all three are checked.
VENDOR_DEPS = ('requests', 'bs4', 'html5lib')

#: Whether the crawlers are importable at all.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: ``ikev2-parameters/ikev2-parameters-7.csv`` (IKEv2 integrity algorithm
#: transform IDs), live registry, ``Last-Modified`` 2026-10-13 20:07:18Z.
INTEGRITY_CSV = (
    'Number,Name,Status,Reference\r\n'
    '0,NONE,,[RFC 7296]\r\n'
    '1,AUTH_HMAC_MD5_96,DEPRECATED [RFC 8247],[RFC 2403]; [RFC 7296]\r\n'
    '2,AUTH_HMAC_SHA1_96,,[RFC 2404]; [RFC 7296]\r\n'
    '3,AUTH_DES_MAC,DEPRECATED [RFC 8247],[UNSPECIFIED]\r\n'
    '4,AUTH_KPDK_MD5,DEPRECATED [RFC 8247],[UNSPECIFIED]\r\n'
    '5,AUTH_AES_XCBC_96,,[RFC 3566]; [RFC 7296]\r\n'
    '6,AUTH_HMAC_MD5_128,DEPRECATED [RFC 9395],[RFC 4595]\r\n'
    '7,AUTH_HMAC_SHA1_160,DEPRECATED [RFC 9395],[RFC 4595]\r\n'
    '8,AUTH_AES_CMAC_96,,[RFC 4494]\r\n'
    '9,AUTH_AES_128_GMAC,,[RFC 4543]\r\n'
    '10,AUTH_AES_192_GMAC,,[RFC 4543]\r\n'
    '11,AUTH_AES_256_GMAC,,[RFC 4543]\r\n'
    '12,AUTH_HMAC_SHA2_256_128,,[RFC 4868]\r\n'
    '13,AUTH_HMAC_SHA2_384_192,,[RFC 4868]\r\n'
    '14,AUTH_HMAC_SHA2_512_256,,[RFC 4868]\r\n'
    '15-1023,Unassigned,,\r\n'
    '1024-65535,Reserved for Private Use,,[RFC 7296]\r\n'
)


def _normalize(context: 'str') -> 'str':
    """Apply the whitespace normalisation :meth:`Vendor.__init__` writes files through."""
    lines = []  # type: list[str]
    for line in context.splitlines():
        if line:
            if line.strip():
                lines.append(line.rstrip())
        else:
            lines.append(line)
    return '\n'.join(lines) + '\n'


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class UnspecifiedReferenceTests(unittest.TestCase):
    """A bracketed ``[UNSPECIFIED]`` cell renders as no citation at all."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

        import pcapkit.vendor.default as default

        resolved = pathlib.Path(default.__file__).resolve()
        if ROOT not in resolved.parents:
            self.skipTest(f'{default.__name__} was imported from {resolved}, which is '
                          f'outside {ROOT}; install this checkout with `pip install -e .`')

    @staticmethod
    def _crawlers() -> 'tuple[Any, ...]':
        from pcapkit.vendor.esp.cipher import Cipher
        from pcapkit.vendor.esp.integrity import Integrity

        return Cipher, Integrity

    def test_rfcs_drops_a_bracketed_placeholder(self) -> None:
        for crawler in self._crawlers():
            for cell in ('[UNSPECIFIED]', '[ UNSPECIFIED ]', '[unspecified]', '[-]', '[]',
                         'UNSPECIFIED', '-', ''):
                with self.subTest(crawler=crawler.__name__, cell=cell):
                    self.assertEqual(crawler.rfcs(cell), '')

    def test_rfcs_keeps_a_bracketed_citation(self) -> None:
        for crawler in self._crawlers():
            with self.subTest(crawler=crawler.__name__):
                self.assertEqual(crawler.rfcs('[RFC 4868]'), '[:rfc:`4868`]')
                self.assertEqual(crawler.rfcs('[RFC 2403]; [RFC 7296]'),
                                 '[:rfc:`2403`][:rfc:`7296`]')
                self.assertEqual(crawler.rfcs('DEPRECATED [RFC 8247]'),
                                 'DEPRECATED [:rfc:`8247`]')

    def test_integrity_matches_the_committed_file(self) -> None:
        from pcapkit.vendor.esp.integrity import Integrity

        vendor = Integrity.__new__(Integrity)
        vendor.NAME = Integrity.__name__
        vendor.DOCS = Integrity.__doc__
        lines = vendor.request(INTEGRITY_CSV)
        vendor.record = vendor.count(lines)
        rendered = _normalize(vendor.context(lines))

        path = ROOT / 'pcapkit' / 'const' / 'esp' / 'integrity.py'
        committed = path.read_text(encoding='utf-8')
        self.assertNotIn('UNSPECIFIED', committed)
        self.assertIn('#: AUTH_DES_MAC (DEPRECATED [:rfc:`8247`])', committed)
        self.assertIn('#: AUTH_KPDK_MD5 (DEPRECATED [:rfc:`8247`])', committed)
        self.assertEqual(rendered, committed)


if __name__ == '__main__':
    unittest.main()
