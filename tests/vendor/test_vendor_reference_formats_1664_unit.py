# -*- coding: utf-8 -*-
"""Regression tests for GitHub issue #1664.

IANA re-exported its registries on 2026-10-13 (``Last-Modified`` between
17:26Z and 17:54Z) and changed how a CSV cell spells its citations, while the
XML records behind them still read ``<xref type="rfc" data="rfc1072"/>``.
``[RFC7401]`` became ``[RFC 7401]``, and ``[RFC1072][RFC6247]`` -- or one
citation per line of a quoted cell -- became ``[RFC 1072]; [RFC 6247]``. The
crawlers matched only the first spelling, so Vendor Update rewrote 73 const
files with ``[RFC 7401]`` where ``[:rfc:`7401`]`` had been, and with
``[RFC 1072][; ][RFC 6247]`` lists.

Every fixture below is a pair of real cells: ``*_OLD`` from a dated Wayback
Machine copy of the registry (bar :data:`TLS_LABEL_OLD`), ``*_NEW`` from the
live registry at 18:21Z on 2026-10-13. Each pair is fed through the crawler's
own ``request``, ``count`` and ``process``/``context`` -- no network call is
made -- and must render identically, with :rst:role:`rfc` roles and no
separator artefacts.

"""
from __future__ import annotations

import importlib.util
import pathlib
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): renders constant modules from recorded data and compares them
#: with the committed files, which the vendor scripts regenerate on one interpreter.
__tier__ = 'LATEST'

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Every distribution importing :mod:`pcapkit.vendor` needs -- see
#: :mod:`tests.vendor.test_ipx_packet_unit` for why all three are checked.
VENDOR_DEPS = ('requests', 'bs4', 'html5lib')

#: Whether the crawlers are importable at all.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: ``hip-parameters/hip-parameters-5.csv`` (HIP Group IDs), Wayback 2025-11-16.
HIP_GROUP_OLD = (
    'Value,Group ID,Reference\r\n'
    '0,Reserved,[RFC7401]\r\n'
    '1,384-bit group (DEPRECATED),[RFC5201]\r\n'
    '2,OAKLEY well known group 1 (DEPRECATED),[RFC5201]\r\n'
    '3,1536-bit MODP group,[RFC7401]\r\n'
    '4,3072-bit MODP group,[RFC7401]\r\n'
    '5,6144-bit MODP group (DEPRECATED),[RFC5201]\r\n'
    '6,8192-bit MODP group (DEPRECATED),[RFC5201]\r\n'
    '7,NIST P-256,[RFC7401]\r\n'
    '8,NIST P-384,[RFC7401]\r\n'
    '9,NIST P-521,[RFC7401]\r\n'
    '10,SECP160R1,[RFC7401]\r\n'
    '11,2048-bit MODP group,[RFC7401]\r\n'
    '12-255,Unassigned,\r\n'
)

#: The same registry, live on 2026-10-13.
HIP_GROUP_NEW = HIP_GROUP_OLD.replace('[RFC', '[RFC ')

#: ``arp-parameters/arp-parameters-1.csv`` (Operation Codes), Wayback 2025-01-14.
ARP_OPERATION_OLD = (
    'Number,Operation Code (op),References\r\n'
    '0,Reserved,[RFC5494]\r\n'
    '1,REQUEST,[RFC826][RFC5227]\r\n'
    '2,REPLY,[RFC826][RFC5227]\r\n'
    '3,request Reverse,[RFC903]\r\n'
    '4,reply Reverse,[RFC903]\r\n'
    '5,DRARP-Request,[RFC1931]\r\n'
    '6,DRARP-Reply,[RFC1931]\r\n'
    '7,DRARP-Error,[RFC1931]\r\n'
    '8,InARP-Request,[RFC2390]\r\n'
    '9,InARP-Reply,[RFC2390]\r\n'
    '10,ARP-NAK,[RFC1577]\r\n'
    '11,MARS-Request,[Grenville_Armitage]\r\n'
    '12,MARS-Multi,[Grenville_Armitage]\r\n'
    '13,MARS-MServ,[Grenville_Armitage]\r\n'
    '14,MARS-Join,[Grenville_Armitage]\r\n'
    '15,MARS-Leave,[Grenville_Armitage]\r\n'
    '16,MARS-NAK,[Grenville_Armitage]\r\n'
    '17,MARS-Unserv,[Grenville_Armitage]\r\n'
    '18,MARS-SJoin,[Grenville_Armitage]\r\n'
    '19,MARS-SLeave,[Grenville_Armitage]\r\n'
    '20,MARS-Grouplist-Request,[Grenville_Armitage]\r\n'
    '21,MARS-Grouplist-Reply,[Grenville_Armitage]\r\n'
    '22,MARS-Redirect-Map,[Grenville_Armitage]\r\n'
    '23,MAPOS-UNARP,[Mitsuru_Maruyama][RFC2176]\r\n'
    '24,OP_EXP1,[RFC5494]\r\n'
    '25,OP_EXP2,[RFC5494]\r\n'
    '26-65534,Unassigned,\r\n'
    '65535,Reserved,[RFC5494]\r\n'
)

#: The same registry, live on 2026-10-13: ``[RFC 826]; [RFC 5227]`` and
#: ``[Mitsuru_Maruyama]; [RFC 2176]``.
ARP_OPERATION_NEW = ARP_OPERATION_OLD.replace('[RFC', '[RFC ').replace('][', ']; [')

#: ``tcp-parameters/tcp-parameters-1.csv`` (Option Kinds), Wayback 2025-11-21.
TCP_OPTION_OLD = (
    'Kind,Length,Meaning,Reference\r\n'
    '0,-,End of Option List,[RFC9293]\r\n'
    '6,6,Echo (obsoleted by option 8),[RFC1072][RFC6247]\r\n'
    '18,3,Trailer Checksum Option,[Subbu_Subramaniam][Monroe_Bridges]\r\n'
)

#: The same rows, live on 2026-10-13.
TCP_OPTION_NEW = (
    'Kind,Length,Meaning,Reference\r\n'
    '0,-,End of Option List,[RFC 9293]\r\n'
    '6,6,Echo (obsoleted by option 8),[RFC 1072]; [RFC 6247]\r\n'
    '18,3,Trailer Checksum Option,[Subbu_Subramaniam]; [Monroe_Bridges]\r\n'
)

#: ``http2-parameters/error-code.csv``, Wayback 2025-11-17: a section citation.
HTTP_ERROR_OLD = (
    'Code,Name,Description,Reference\r\n'
    '0x00,NO_ERROR,Graceful shutdown,"[RFC9113, Section 7]"\r\n'
)

#: The same row, live on 2026-10-13.
HTTP_ERROR_NEW = HTTP_ERROR_OLD.replace('[RFC', '[RFC ')

#: ``ikev2-parameters/ikev2-parameters-5.csv`` (ESP ciphers), Wayback
#: 2025-12-08 -- a two-citation cell was one citation per line.
ESP_CIPHER_OLD = (
    'Number,Name,Status,ESP Reference,IKEv2 Reference\r\n'
    '1,ENCR_DES_IV64,DEPRECATED [RFC9395],UNSPECIFIED,-\r\n'
    '18,ENCR_AES_GCM_8,,"[RFC4106]\n          [RFC8247]","[RFC5282]\n          [RFC8247]"\r\n'
)

#: The same rows, live on 2026-10-13.
ESP_CIPHER_NEW = (
    'Number,Name,Status,ESP Reference,IKEv2 Reference\r\n'
    '1,ENCR_DES_IV64,DEPRECATED [RFC 9395],UNSPECIFIED,-\r\n'
    '18,ENCR_AES_GCM_8,,[RFC 4106]; [RFC 8247],[RFC 5282]; [RFC 8247]\r\n'
)

#: ``ftp-commands-extensions/ftp-commands-extensions-2.csv``, Wayback
#: 2024-06-13, with the 2026-10-13 row beside it.
FTP_COMMAND_OLD = (
    'cmd,FEAT code,description,type,conf,References and Notes\r\n'
    'ADAT,secu,Authentication/Security Data,a,o,"[RFC2228]\n      [RFC2773]\n      [RFC4217]"\r\n'
)
FTP_COMMAND_NEW = (
    'cmd,FEAT code,description,type,conf,References and Notes\r\n'
    'ADAT,secu,Authentication/Security Data,a,o,[RFC 2228]; [RFC 2773]; [RFC 4217]\r\n'
)

#: ``ALGS`` live on 2026-10-13. It read ``[RFC6384] Section 11`` before, so it
#: is the one row whose rendering moves: the section is now in the citation.
FTP_ALGS_NEW = (
    'cmd,FEAT code,description,type,conf,References and Notes\r\n'
    'ALGS,,FTP64 ALG status,,o,"[RFC 6384, Section 11]"\r\n'
)

#: ``service-names-port-numbers.csv``, Wayback 2026-10-07, when 392 of the 393
#: RFC citations in its ``Reference`` column were already spelt ``RFC 3501``:
#: this registry switched by 2026-09-29, whose ``1.5.0b6`` bump dropped the
#: roles from 670 lines of the AppType const files. ``dns-push-tls`` was the
#: exception.
APPTYPE_HEADER = ('Service Name,Port Number,Transport Protocol,Description,Assignee,Contact,'
                  'Registration Date,Modification Date,Reference,Service Code,'
                  'Unauthorized Use Reported,Assignment Notes\r\n')
APPTYPE_OLD = APPTYPE_HEADER + (
    'imap,143,tcp,Internet Message Access Protocol,[IESG],[IETF_Chair],,2021-02-22,'
    '[RFC 3501][RFC 9051],,,\r\n'
    'dns-push-tls,,tcp,DNS Push Notification Service Type,[IESG],[IETF_Chair],2019-11-25,,'
    '"[RFC8765, Section 6.1]",,,Defined TXT Keys: None\r\n'
)

#: The same rows, live on 2026-10-13.
APPTYPE_NEW = APPTYPE_HEADER + (
    'imap,143,tcp,Internet Message Access Protocol,[IESG],[IETF_Chair],,2021-02-22,'
    '[RFC 3501]; [RFC 9051],,,\r\n'
    'dns-push-tls,,tcp,DNS Push Notification Service Type,[IESG],[IETF_Chair],2019-11-25,,'
    '"[RFC 8765, Section 6.1]",,,Defined TXT Keys: None\r\n'
)

#: ``tls-parameters/tls-sslkeylogfile-labels.csv``. The crawler's own comment
#: records ``[RFC9850]`` for every row as of 2026-09-28; ``[RFC 9850]`` is live.
TLS_LABEL_OLD = ('Value,Description,Reference,Comment\r\n'
                 'CLIENT_RANDOM,Master secret in TLS 1.2 and earlier,[RFC9850],\r\n')
TLS_LABEL_NEW = TLS_LABEL_OLD.replace('[RFC', '[RFC ')


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
class ReferenceFormatTests(unittest.TestCase):
    """Both of IANA's reference spellings render the same const file."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

        import pcapkit.vendor.default as default

        resolved = pathlib.Path(default.__file__).resolve()
        if ROOT not in resolved.parents:
            self.skipTest(f'{default.__name__} was imported from {resolved}, which is '
                          f'outside {ROOT}; install this checkout with `pip install -e .`')

    @staticmethod
    def _vendor(cls: 'Any', text: 'str') -> 'tuple[Any, list[str]]':
        """A crawler as ``__init__`` would set it up, without the fetch and the write."""
        vendor = cls.__new__(cls)
        vendor.NAME = cls.__name__
        vendor.DOCS = cls.__doc__
        lines = vendor.request(text)
        vendor.record = vendor.count(lines)
        return vendor, lines

    def _context(self, cls: 'Any', text: 'str') -> 'str':
        vendor, lines = self._vendor(cls, text)
        return _normalize(vendor.context(lines))

    def _comments(self, cls: 'Any', text: 'str') -> 'list[str]':
        vendor, lines = self._vendor(cls, text)
        enum, _ = vendor.process(lines)
        return [entry.split('\n    ', 1)[0] for entry in enum]

    def _assert_clean(self, text: 'str') -> None:
        for artefact in ('[; ]', '[;]', '[RFC '):
            self.assertNotIn(artefact, text)

    def test_split_references_reads_both_spellings_alike(self) -> None:
        from pcapkit.vendor.default import Vendor

        for old, new, expected in (
            ('[RFC1072][RFC6247]', '[RFC 1072]; [RFC 6247]', ['RFC1072', 'RFC6247']),
            ('[RFC4106]\n          [RFC8247]', '[RFC 4106]; [RFC 8247]', ['RFC4106', 'RFC8247']),
            ('[Subbu_Subramaniam][Monroe_Bridges]', '[Subbu_Subramaniam]; [Monroe_Bridges]',
             ['Subbu_Subramaniam', 'Monroe_Bridges']),
            ('[RFC9113, Section 7]', '[RFC 9113, Section 7]', ['RFC9113, Section 7']),
        ):
            with self.subTest(new=new):
                self.assertEqual(Vendor.split_references(old), expected)
                self.assertEqual(Vendor.split_references(new), expected)

    def test_split_references_keeps_other_segments_verbatim(self) -> None:
        from pcapkit.vendor.default import Vendor

        self.assertEqual(Vendor.split_references('[RFC 959]; [RFC Errata 5748]'),
                         ['RFC959', 'RFC Errata 5748'])
        self.assertEqual(Vendor.split_references('[RFC-ietf-tcpm-accurate-ecn-34]'),
                         ['RFC-ietf-tcpm-accurate-ecn-34'])
        self.assertEqual(Vendor.split_references('[         3GPP TS 36.462][KIMBA DIT ADAMOU Boubacar]'),
                         ['         3GPP TS 36.462', 'KIMBA DIT ADAMOU Boubacar'])

    def test_hip_group_matches_the_committed_file_from_both(self) -> None:
        from pcapkit.vendor.hip.group import Group

        committed = (ROOT / 'pcapkit' / 'const' / 'hip' / 'group.py').read_text(encoding='utf-8')
        self.assertIn('[:rfc:`7401`]', committed)
        self.assertEqual(self._context(Group, HIP_GROUP_OLD), committed)
        self.assertEqual(self._context(Group, HIP_GROUP_NEW), committed)

    def test_arp_operation_matches_the_committed_file_from_both(self) -> None:
        from pcapkit.vendor.arp.operation import Operation

        committed = (ROOT / 'pcapkit' / 'const' / 'arp' / 'operation.py').read_text(encoding='utf-8')
        self.assertIn('#: REQUEST [:rfc:`826`][:rfc:`5227`]', committed)
        self.assertIn('#: MAPOS-UNARP [Mitsuru Maruyama][:rfc:`2176`]', committed)
        self.assertEqual(self._context(Operation, ARP_OPERATION_OLD), committed)
        self.assertEqual(self._context(Operation, ARP_OPERATION_NEW), committed)

    def test_tcp_option_renders_both_alike(self) -> None:
        from pcapkit.vendor.tcp.option import Option

        new = self._comments(Option, TCP_OPTION_NEW)
        self.assertEqual(new, self._comments(Option, TCP_OPTION_OLD))
        self.assertEqual(new, [
            '#: End of Option List [:rfc:`9293`]',
            '#: Echo (obsoleted by option 8) [:rfc:`1072`][:rfc:`6247`]',
            '#: Trailer Checksum Option [Subbu Subramaniam][Monroe Bridges]',
        ])

    def test_http_error_code_keeps_its_section_role(self) -> None:
        from pcapkit.vendor.http.error_code import ErrorCode

        new = self._comments(ErrorCode, HTTP_ERROR_NEW)
        self.assertEqual(new, self._comments(ErrorCode, HTTP_ERROR_OLD))
        self.assertEqual(new, ['#: NO_ERROR, Graceful shutdown [:rfc:`9113#section-7`]'])

    def test_esp_cipher_renders_both_alike(self) -> None:
        from pcapkit.vendor.esp.cipher import Cipher

        new = self._context(Cipher, ESP_CIPHER_NEW)
        self.assertEqual(new, self._context(Cipher, ESP_CIPHER_OLD))
        self.assertIn('#: ENCR_DES_IV64 (DEPRECATED [:rfc:`9395`])', new)
        self.assertIn('#: ENCR_AES_GCM_8 [:rfc:`4106`][:rfc:`8247`]', new)
        self._assert_clean(new)

    def test_ftp_command_renders_both_alike(self) -> None:
        from pcapkit.vendor.ftp.command import Command

        new = self._comments(Command, FTP_COMMAND_NEW)
        self.assertEqual(new, self._comments(Command, FTP_COMMAND_OLD))
        self.assertEqual(new, ['#: Authentication/Security Data [:rfc:`2228`][:rfc:`2773`][:rfc:`4217`]'])

    def test_ftp_command_renders_a_section_inside_the_citation(self) -> None:
        from pcapkit.vendor.ftp.command import Command

        self.assertEqual(self._comments(Command, FTP_ALGS_NEW),
                         ['#: FTP64 ALG status [:rfc:`6384#section-11`]'])

    def test_apptype_renders_both_alike(self) -> None:
        from pcapkit.vendor.reg.apptype.apptype import AppType

        cells = {}
        for text in (APPTYPE_OLD, APPTYPE_NEW):
            vendor, lines = self._vendor(AppType, text)
            line, _ = vendor.records(lines)
            cells[text] = {name: record.cells for name, record in line.items()}
        self.assertEqual(cells[APPTYPE_NEW], cells[APPTYPE_OLD])
        self.assertEqual(cells[APPTYPE_NEW], {
            'imap': ['[TCP] Internet Message Access Protocol [:rfc:`3501`][:rfc:`9051`]'],
            'dns_push_tls': ['[TCP] DNS Push Notification Service Type [:rfc:`8765#section-6.1`]'],
        })

    def test_tls_key_label_accepts_both(self) -> None:
        from pcapkit.vendor.pcapng.tls_key_label import TLSKeyLabel

        new = self._comments(TLSKeyLabel, TLS_LABEL_NEW)
        self.assertEqual(new, self._comments(TLSKeyLabel, TLS_LABEL_OLD))
        self.assertIn('#: Master secret in TLS 1.2 and earlier, c.f., :rfc:`9850#section-4.2`.', new)
