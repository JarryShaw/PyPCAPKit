# -*- coding: utf-8 -*-
"""OSPF rebuilds byte for byte from the dict form of its info, :issue:`1464`.

Under cryptographic authentication (AuType 2) the ``auth`` field is a
:class:`~pcapkit.protocols.data.application.ospf.CryptographicAuthentication`,
which ``to_dict()`` flattens into a plain :obj:`dict`. ``from_dict`` cannot
restore it, since the field is declared ``bytes | CryptographicAuthentication``,
so :meth:`OSPF._make_encrypt_auth
<pcapkit.protocols.application.ospf.OSPF._make_encrypt_auth>` has to accept
that :obj:`dict`; it used to raise ``invalid type for auth_data``.

Every case builds its own octets in memory and reads no capture.

"""
from __future__ import annotations

import importlib.util
import struct
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


def packet(autype: int, auth: bytes, trailer: bytes = b'') -> bytes:
    """A header-only OSPFv2 Hello with ``auth`` and, past its Packet Length, ``trailer``."""
    return struct.pack('!BBHIIHH', 2, 1, 24, 0x01010101, 0, 0, autype) + auth + trailer


def crypto(reserved: int = 0, key_id: int = 1, auth_len: int = 16, seq: int = 7) -> bytes:
    """The 8-octet Authentication field of AuType 2."""
    return struct.pack('!HBBI', reserved, key_id, auth_len, seq)


#: One packet per AuType: none, simple password, cryptographic, and unassigned.
PACKETS = {
    'autype-0': packet(0, bytes(8)),
    'autype-0-nonzero-auth': packet(0, bytes(range(1, 9))),
    'autype-1': packet(1, b'secret!!'),
    'autype-2': packet(2, crypto(), b'\xaa' * 16),
    'autype-2-nonzero-reserved': packet(2, crypto(reserved=0xbeef, key_id=255, seq=0xffffffff), b'\xaa' * 16),
    'autype-2-no-digest': packet(2, crypto(auth_len=0)),
    'autype-7-unassigned': packet(7, b'ABCDEFGH'),
    'autype-65535-unassigned': packet(0xffff, b'\xff' * 8),
}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestOSPFAuthDictRoundTrip(unittest.TestCase):
    """Pin the dict-form rebuild of the Authentication field."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_from_data_rebuilds_dict_form_byte_for_byte(self) -> None:
        from pcapkit.protocols.application.ospf import OSPF

        for name, raw in PACKETS.items():
            with self.subTest(packet=name):
                parsed = OSPF(raw, len(raw))
                self.assertEqual(OSPF.from_data(parsed.info.to_dict()).data, raw)

    def test_from_data_rebuilds_object_form_byte_for_byte(self) -> None:
        from pcapkit.protocols.application.ospf import OSPF

        for name, raw in PACKETS.items():
            with self.subTest(packet=name):
                parsed = OSPF(raw, len(raw))
                self.assertEqual(OSPF.from_data(parsed.info).data, raw)

    def test_to_dict_flattens_cryptographic_authentication(self) -> None:
        # The premise of the fix: the dict form really does carry a plain
        # mapping -- the OrderedMultiDict ``to_dict()`` writes (#1484).
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.application.ospf import OSPF

        raw = PACKETS['autype-2-nonzero-reserved']
        auth = OSPF(raw, len(raw)).info.to_dict()['auth']
        self.assertIsInstance(auth, OrderedMultiDict)
        self.assertEqual(auth.to_dict(), {'reserved': b'\xbe\xef', 'key_id': 255, 'len': 16, 'seq': 0xffffffff})

    def test_make_accepts_dict_auth_data(self) -> None:
        from pcapkit.protocols.application.ospf import OSPF

        proto = OSPF(router_id='1.1.1.1', auth_type=2,
                     auth_data={'reserved': b'\xbe\xef', 'key_id': 255, 'len': 16, 'seq': 0xffffffff})
        self.assertEqual(proto.data, packet(2, crypto(reserved=0xbeef, key_id=255, seq=0xffffffff)))

    def test_make_dict_auth_data_defaults_reserved_to_zero(self) -> None:
        from pcapkit.protocols.application.ospf import OSPF

        proto = OSPF(router_id='1.1.1.1', auth_type=2, auth_data={'key_id': 1, 'len': 16, 'seq': 7})
        self.assertEqual(proto.data, packet(2, crypto()))

    def test_make_dict_auth_data_missing_key_is_refused(self) -> None:
        from pcapkit.protocols.application.ospf import OSPF
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaisesRegex(ProtocolError, r"^OSPF: missing 'seq' in auth_data: "):
            OSPF(auth_type=2, auth_data={'key_id': 1, 'len': 16})


if __name__ == '__main__':
    unittest.main()
