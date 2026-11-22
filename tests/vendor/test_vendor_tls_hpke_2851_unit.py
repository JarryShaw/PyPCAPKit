# -*- coding: utf-8 -*-
"""The HPKE crawlers render IANA's ``hpke`` registry tables (#2851).

Each fixture is an excerpt of the live CSV, read on 2026-11-22: IANA writes every
value and range in hex, a KEM name carries a parenthetical, and each table puts its
``Reference`` in a different column. Each is fed through the crawler's own
``count`` and ``context``, with no network call.

"""
from __future__ import annotations

import unittest

#: Test tier (#1958): the vendor extra is installed on latest alone, as for the
#: other crawler tests.
__tier__ = 'LATEST'

#: An excerpt of ``hpke-kem-ids.csv``, HPKE KEM Identifiers.
KEM = [
    'Value,KEM,Nsecret,Nenc,Npk,Nsk,Auth,Reference',
    '0x0000,Reserved,N/A,N/A,N/A,N/A,N/A,[RFC-ietf-hpke-hpke-06]',
    '0x0001-0x000F,Unassigned,,,,,,',
    '0x0010,"DHKEM(P-256, HKDF-SHA256)",32,65,65,32,yes,[NISTCurves]; [RFC 5869]',
    '0x0020,"DHKEM(X25519, HKDF-SHA256)",32,32,32,32,yes,[RFC 5869]; [RFC 7748]',
    '0x0022,"DHKEM(X25519+Elligator, HKDF-SHA256)",32,32,32,32,yes,'
    '[https://lsd.gnunet.org/lsd0011/]; [draft-schanzen-hpke-elligator-kem-01]',
    '0x0040,ML-KEM-512,32,768,800,64,no,[draft-connolly-cfrg-hpke-mlkem-04]',
    '0x647A,X-Wing,32,1120,1216,32,no,[draft-connolly-cfrg-xwing-kem-06]',
    '0x647B-0xFFFF,Unassigned,,,,,,',
]

#: An excerpt of ``hpke-kdf-ids.csv``, HPKE KDF Identifiers.
KDF = [
    'Value,KDF,Nh,Two-Stage,Reference',
    '0x0000,Reserved,N/A,N/A,[RFC-ietf-hpke-hpke-06]',
    '0x0001,HKDF-SHA256,32,Y,[RFC 5869]',
    '0x0004-0x000F,Unassigned,,,',
    '0x0012,TurboSHAKE128,32,N,[draft-ietf-hpke-pq-04]',
]

#: An excerpt of ``hpke-aead-ids.csv``, HPKE AEAD Identifiers.
AEAD = [
    'Value,AEAD,Nk,Nn,Nt,Reference',
    '0x0001,AES-128-GCM,16,12,16,[GCM]',
    '0x0003,ChaCha20Poly1305,32,12,16,[RFC 8439]',
    '0x0004-0xFFFE,Unassigned,,,,',
    '0xFFFF,Export-only,0,0,N/A,[RFC-ietf-hpke-hpke-06]',
]


def _render(crawler: 'type', rows: 'list[str]') -> 'str':
    """The module ``crawler`` generates from ``rows``, with no fetch and no write."""
    self = object.__new__(crawler)
    self.NAME = crawler.__name__
    self.DOCS = crawler.__doc__
    self.record = self.count(rows)
    return self.context(rows)


class HpkeCrawlerTests(unittest.TestCase):
    """What each crawler makes of its registry's rows."""

    def test_kem_names_keep_the_parenthetical(self) -> None:
        from pcapkit.vendor.tls.hpke_kem_id import HpkeKemId

        text = _render(HpkeKemId, KEM)
        for line in (
                '    #: Reserved [RFC-ietf-hpke-hpke-06]\n    Reserved_0x0000 = 0x0000\n',
                '    #: DHKEM(P-256, HKDF-SHA256) [NISTCurves][:rfc:`5869`]\n    DHKEM_P_256_HKDF_SHA256 = 0x0010\n',
                '    #: DHKEM(X25519, HKDF-SHA256) [:rfc:`5869`][:rfc:`7748`]\n'
                '    DHKEM_X25519_HKDF_SHA256 = 0x0020\n',
                '    #: DHKEM(X25519+Elligator, HKDF-SHA256) [https://lsd.gnunet.org/lsd0011/]\n'
                '    #: [draft-schanzen-hpke-elligator-kem-01]\n    DHKEM_X25519_Elligator_HKDF_SHA256 = 0x0022\n',
                '    ML_KEM_512 = 0x0040\n',
                '    X_Wing = 0x647A\n',
                "        if 0x0001 <= value <= 0x000F:\n            #: Unassigned\n"
                "            return cls._unregistered_member(value, 'Unassigned')\n",
                '        if 0x647B <= value <= 0xFFFF:\n',
                '        if not (isinstance(value, int) and 0x0000 <= value <= 0xFFFF):\n',
        ):
            with self.subTest(line=line):
                self.assertIn(line, text)
        self.assertIn('.. module:: pcapkit.const.tls.hpke_kem_id\n', text)
        self.assertNotIn('DHKEM_0x', text)

    def test_kdf_and_aead_read_their_reference_columns(self) -> None:
        from pcapkit.vendor.tls.hpke_aead_id import HpkeAeadId
        from pcapkit.vendor.tls.hpke_kdf_id import HpkeKdfId

        for crawler, rows, lines in (
                (HpkeKdfId, KDF, ('    #: HKDF-SHA256 [:rfc:`5869`]\n    HKDF_SHA256 = 0x0001\n',
                                  '    #: TurboSHAKE128 [draft-ietf-hpke-pq-04]\n    TurboSHAKE128 = 0x0012\n',
                                  '        if 0x0004 <= value <= 0x000F:\n')),
                (HpkeAeadId, AEAD, ('    #: AES-128-GCM [GCM]\n    AES_128_GCM = 0x0001\n',
                                    '    #: ChaCha20Poly1305 [:rfc:`8439`]\n    ChaCha20Poly1305 = 0x0003\n',
                                    '    #: Export-only [RFC-ietf-hpke-hpke-06]\n    Export_only = 0xFFFF\n',
                                    '        if 0x0004 <= value <= 0xFFFE:\n')),
        ):
            text = _render(crawler, rows)
            for line in lines:
                with self.subTest(crawler=crawler.__name__, line=line):
                    self.assertIn(line, text)


if __name__ == '__main__':
    unittest.main()
