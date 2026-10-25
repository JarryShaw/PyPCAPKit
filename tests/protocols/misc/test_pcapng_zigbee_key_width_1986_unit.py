# -*- coding: utf-8 -*-
"""GitHub issue #1986: a ZigBee key in a Decryption Secrets Block rebuilds as captured.

The ZigBee NWK and APS key schemas have a fixed width, but a block's
``secrets_length`` may declare fewer octets or more. A key shorter than the
width parsed, but its data model rebuilt it at full width: the key zero-padded,
``secrets_length`` rewritten and the block grown. Octets past the width were
dropped, by the parse itself. The data model keeps the Secrets Data octets
as the block holds them, the schema keeps those past the fixed fields, and both
rebuild byte for byte.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import struct
import unittest
import warnings

from tests.protocols.misc.test_pcapng_roundtrip2_unit import PCAPNGTestCase

#: Secrets Type of a ZigBee NWK Key and of a ZigBee APS Key.
ZIGBEE_NWK_KEY = 0x5A4E574B
ZIGBEE_APS_KEY = 0x5A415053

#: Fixed width of each key's Secrets Data.
WIDTH = {ZIGBEE_NWK_KEY: 18, ZIGBEE_APS_KEY: 22}


def _block(btype: 'int', body: 'bytes') -> 'bytes':
    """A little-endian block of ``btype`` around ``body``, padded to 32 bits."""
    body += bytes(-len(body) % 4)
    total = 12 + len(body)
    return struct.pack('<II', btype, total) + body + struct.pack('<I', total)


def _dsb(secrets_type: 'int', secrets_length: 'int', secrets: 'bytes') -> 'bytes':
    """A Decryption Secrets Block declaring ``secrets_length`` over ``secrets``."""
    return _block(10, struct.pack('<II', secrets_type, secrets_length) + secrets)


def _secrets(count: 'int') -> 'bytes':
    """``count`` non-zero octets, so a zero-filled rebuild cannot pass for them."""
    return bytes(range(1, count + 1))


class TestPCAPNGZigBeeKeyWidth(PCAPNGTestCase):
    """Pin how a ZigBee key off its fixed width parses and rebuilds."""

    def _quiet_rebuild(self, octets: 'bytes') -> 'tuple[bytes, list[str]]':
        """Parse ``octets`` quietly, then rebuild them, recording the rebuild's warnings."""
        from pcapkit.protocols.misc.pcapng import PCAPNG

        context = self._context()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = PCAPNG(octets, len(octets), num=2, sct=1, ctx=context)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            rebuilt = PCAPNG.from_data(parsed.info, num=2, sct=1, ctx=context).data
        return rebuilt, [str(item.message) for item in caught]

    def test_short_key_rebuilds(self) -> None:
        """The issue's case: ten key octets in a 32-octet block stay ten in 32."""
        for secrets_type in (ZIGBEE_NWK_KEY, ZIGBEE_APS_KEY):
            with self.subTest(secrets_type=hex(secrets_type)):
                octets = _dsb(secrets_type, 10, _secrets(10))
                self.assertEqual(len(octets), 32)
                rebuilt, messages = self._quiet_rebuild(octets)
                self.assertEqual(rebuilt.hex(), octets.hex())
                self.assertEqual(messages, [])

    def test_every_short_width_rebuilds(self) -> None:
        """Short anywhere, inside the key or inside a later field, the block rebuilds."""
        for secrets_type, width in WIDTH.items():
            for count in range(width):
                with self.subTest(secrets_type=hex(secrets_type), count=count):
                    octets = _dsb(secrets_type, count, _secrets(count))
                    rebuilt, _ = self._quiet_rebuild(octets)
                    self.assertEqual(rebuilt.hex(), octets.hex())

    def test_long_secrets_are_kept(self) -> None:
        """Octets past the fixed width parse into the schema and rebuild."""
        for secrets_type, width in WIDTH.items():
            for count in (width + 1, width + 2, width + 12):
                with self.subTest(secrets_type=hex(secrets_type), count=count):
                    octets = _dsb(secrets_type, count, _secrets(count))
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        parsed = self._parse(octets)
                    self.assertEqual(parsed.info.secrets_length, count)  # type: ignore[attr-defined]
                    self.assertEqual(parsed.info.secrets_data.data, _secrets(count))  # type: ignore[attr-defined]
                    self.assertEqual(parsed.__header__.block.secrets_data.trailing,  # type: ignore[attr-defined]
                                     _secrets(count)[width:])
                    self.assertEqual(parsed.__header__.pack().hex(), octets.hex())  # type: ignore[attr-defined]
                    rebuilt, messages = self._quiet_rebuild(octets)
                    self.assertEqual(rebuilt.hex(), octets.hex())
                    self.assertEqual(messages, [])

    def test_short_key_keeps_the_declared_length(self) -> None:
        for secrets_type in (ZIGBEE_NWK_KEY, ZIGBEE_APS_KEY):
            with self.subTest(secrets_type=hex(secrets_type)):
                octets = _dsb(secrets_type, 10, _secrets(10))
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    parsed = self._parse(octets)
                self.assertEqual(parsed.info.secrets_length, 10)  # type: ignore[attr-defined]
                self.assertEqual(parsed.info.secrets_data.data, _secrets(10))  # type: ignore[attr-defined]
                self.assertEqual(parsed.__header__.pack().hex(), octets.hex())  # type: ignore[attr-defined]

    def test_overrun_rebuilds(self) -> None:
        """A Secrets Length past the block keeps it, and the key the block holds (#1980)."""
        for secrets_type in (ZIGBEE_NWK_KEY, ZIGBEE_APS_KEY):
            for secrets_length in (0xFFFF_FFF0, 5):
                with self.subTest(secrets_type=hex(secrets_type), secrets_length=secrets_length):
                    octets = _dsb(secrets_type, secrets_length, b'abcd')
                    rebuilt, _ = self._quiet_rebuild(octets)
                    self.assertEqual(rebuilt.hex(), octets.hex())

    def test_made_block_parses_back(self) -> None:
        """Made from a parsed model, the block parses back to the same secrets."""
        from pcapkit.protocols.misc.pcapng import PCAPNG

        for secrets_type in (ZIGBEE_NWK_KEY, ZIGBEE_APS_KEY):
            for count in (10, WIDTH[secrets_type], WIDTH[secrets_type] + 6):
                with self.subTest(secrets_type=hex(secrets_type), count=count):
                    octets = _dsb(secrets_type, count, _secrets(count))
                    context = self._context()
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        parsed = PCAPNG(octets, len(octets), num=2, sct=1, ctx=context)
                        made = PCAPNG.from_data(parsed.info, num=2, sct=1, ctx=context).data
                        reparsed = PCAPNG(made, len(made), num=2, sct=1, ctx=context)
                    self.assertEqual(reparsed.info.secrets_length, count)  # type: ignore[attr-defined]
                    self.assertEqual(dict(reparsed.info.secrets_data),  # type: ignore[attr-defined]
                                     dict(parsed.info.secrets_data))  # type: ignore[attr-defined]
                    self.assertEqual(made.hex(), octets.hex())

    def test_made_from_fields_is_full_width(self) -> None:
        """Made from its fields, a key is its fixed width, and parses back to them."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.secrets_type import SecretsType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        key = _secrets(16)
        cases = (
            (SecretsType.ZigBee_NWK_Key, {'nwk_key': key, 'pan_id': 0x1234}),
            (SecretsType.ZigBee_APS_Key, {'aps_key': key, 'pan_id': 0x1234,
                                          'short_address': 0x56789ABC}),
        )
        for secrets_type, fields in cases:
            with self.subTest(secrets_type=secrets_type):
                context = self._context()
                made = PCAPNG(num=2, sct=1, ctx=context, type=BlockType.Decryption_Secrets_Block,
                              block={'secrets_type': secrets_type, 'secrets_data': fields}).data
                width = WIDTH[int(secrets_type)]
                self.assertEqual(struct.unpack('<I', made[12:16])[0], width, made.hex())
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    parsed = PCAPNG(made, len(made), num=2, sct=1, ctx=context)
                self.assertEqual([str(item.message) for item in caught], [])
                secrets = parsed.info.secrets_data  # type: ignore[attr-defined]
                self.assertEqual({name: secrets[name] for name in fields}, fields)
                self.assertEqual(len(secrets.data), width)
                self.assertRebuilds(made, context)

    def test_edited_fields_are_written(self) -> None:
        """A model built afresh, with no octets held, is written from its fields."""
        from pcapkit.protocols.data.misc.pcapng import ZigBeeNWKKey
        from pcapkit.protocols.misc.pcapng import PCAPNG

        octets = _dsb(ZIGBEE_NWK_KEY, 10, _secrets(10))
        context = self._context()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            info = PCAPNG(octets, len(octets), num=2, sct=1, ctx=context).info
        fields = {key: value for key, value in dict(info).items() if key != 'packet'}
        fields['secrets_data'] = ZigBeeNWKKey(nwk_key=_secrets(16), pan_id=0x1234)
        rebuilt = PCAPNG.from_data(info.__class__(**fields), num=2, sct=1, ctx=context).data
        self.assertEqual(struct.unpack('<I', rebuilt[12:16])[0], 18, rebuilt.hex())
        self.assertEqual(rebuilt[16:34], _secrets(16) + b'\x34\x12')
        length, = struct.unpack('<I', rebuilt[4:8])
        self.assertEqual((len(rebuilt), rebuilt[-4:]), (length, rebuilt[4:8]))


if __name__ == '__main__':
    unittest.main()
