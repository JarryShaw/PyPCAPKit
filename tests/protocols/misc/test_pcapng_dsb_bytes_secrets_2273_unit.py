# -*- coding: utf-8 -*-
"""GitHub issue #2273: a Decryption Secrets Block is made from raw ``secrets_data``.

Without the fix, ``_make_block_dsb`` stores a :obj:`bytes` ``secrets_data``,
its default included, in the block's schema as given, and every
``_read_secrets_*`` then fails on it, as it expects a parsed secrets schema: the
block cannot be made for any secrets type. The octets are read through the
schema the parse side selects, so the made block packs them back verbatim, and
its info is the info of the block parsed from its own octets.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import struct
import unittest
import warnings

from tests.protocols.misc.test_pcapng_roundtrip2_unit import PCAPNGTestCase

#: Secrets Type of each registered secrets schema, and one no registry names.
TLS_KEY_LOG = 0x544C534B
WIREGUARD_KEY_LOG = 0x57474B4C
ZIGBEE_NWK_KEY = 0x5A4E574B
ZIGBEE_APS_KEY = 0x5A415053
UNKNOWN_SECRETS = 0x12345678

#: Well-formed secrets of each type.
SECRETS = {
    TLS_KEY_LOG: b'CLIENT_RANDOM ' + b'ab' * 32 + b' ' + b'cd' * 48 + b'\n',
    WIREGUARD_KEY_LOG: b'LOCAL_STATIC_PRIVATE_KEY = ' + b'A' * 43 + b'=\n',
    ZIGBEE_NWK_KEY: bytes(range(1, 17)) + b'\x34\x12',
    ZIGBEE_APS_KEY: bytes(range(1, 17)) + b'\x34\x12\x78\x56\xbc\x9a',
    UNKNOWN_SECRETS: b'abc',
}


def _dsb(secrets_type: 'int', secrets: 'bytes') -> 'bytes':
    """A little-endian Decryption Secrets Block holding ``secrets``, padded to 32 bits."""
    body = struct.pack('<II', secrets_type, len(secrets)) + secrets + bytes(-len(secrets) % 4)
    total = 12 + len(body)
    return struct.pack('<II', 10, total) + body + struct.pack('<I', total)


class TestPCAPNGDSBBytesSecrets(PCAPNGTestCase):
    """Pin a Decryption Secrets Block made from raw ``secrets_data``."""

    def _round_trip(self, block: 'dict[str, object]', octets: 'bytes') -> None:
        """Make the block, then assert make, parse and rebuild agree on ``octets``."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        context = self._context()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')  # a short ZigBee key reads short, as parsed
            made = PCAPNG(num=2, sct=1, ctx=context, type=BlockType.Decryption_Secrets_Block,
                          block=block)
            parsed = PCAPNG(made.data, len(made.data), num=2, sct=1, ctx=context)
            remade = PCAPNG.from_data(made.info, num=2, sct=1, ctx=context).data
            self.assertRebuilds(octets, context)
        self.assertEqual(made.data.hex(), octets.hex())
        self.assertEqual(made.info, parsed.info)
        self.assertEqual(remade.hex(), octets.hex())

    def test_default_block(self) -> None:
        """The issue's case: ``block={}`` is an empty TLS key log."""
        self._round_trip({}, _dsb(TLS_KEY_LOG, b''))

    def test_every_secrets_type(self) -> None:
        for secrets_type, secrets in SECRETS.items():
            for data in (secrets, b''):
                with self.subTest(secrets_type=hex(secrets_type), data=data):
                    self._round_trip({'secrets_type': secrets_type, 'secrets_data': data},
                                     _dsb(secrets_type, data))

    def test_short_and_long_zigbee_keys(self) -> None:
        """A ZigBee key off its fixed width is kept as given (#1986)."""
        for secrets_type in (ZIGBEE_NWK_KEY, ZIGBEE_APS_KEY):
            for count in (3, 10, 30):
                data = bytes(range(1, count + 1))
                with self.subTest(secrets_type=hex(secrets_type), count=count):
                    self._round_trip({'secrets_type': secrets_type, 'secrets_data': data},
                                     _dsb(secrets_type, data))

    def test_parsed_secrets(self) -> None:
        """The made info carries the secrets parsed out of the octets."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.tls_key_label import TLSKeyLabel
        from pcapkit.protocols.misc.pcapng import PCAPNG

        made = PCAPNG(num=2, sct=1, ctx=self._context(), type=BlockType.Decryption_Secrets_Block,
                      block={'secrets_data': SECRETS[TLS_KEY_LOG]})
        entries = made.info.secrets_data.entries  # type: ignore[attr-defined]
        self.assertEqual(list(entries[TLSKeyLabel.CLIENT_RANDOM].items()),
                         [(b'\xab' * 32, b'\xcd' * 48)])


if __name__ == '__main__':
    unittest.main()
