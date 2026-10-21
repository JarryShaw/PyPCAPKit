# -*- coding: utf-8 -*-
"""GitHub issue #1980: a Decryption Secrets Block's secrets are bounded by the block.

A Decryption Secrets Block whose ``secrets_length`` ran far past the block read
that many octets as secrets: the trailing Block Total Length and the blocks after
it went with them, and past the zero-pad ceiling the read raised
:exc:`~pcapkit.utilities.exceptions.FieldValueError` from inside the block's
schema, which ended the whole extraction. The secrets are now bounded by the
block, as an Enhanced Packet Block's packet data is (#1405): the declared
``secrets_length`` is kept, a :class:`~pcapkit.utilities.warnings.ProtocolWarning`
reports the overrun, and extraction carries on to the next block.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import io
import struct
import unittest
import warnings

from tests.protocols.misc.test_pcapng_roundtrip2_unit import PCAPNGTestCase

FRAME = bytes(range(1, 61))

#: Secrets Type of a TLS Key Log, of a ZigBee NWK Key, and one no registry names.
TLS_KEY_LOG = 0x544C534B
ZIGBEE_NWK_KEY = 0x5A4E574B
UNKNOWN_SECRETS = 0x12345678

#: One well-formed TLS key log line.
KEY_LOG = b'CLIENT_RANDOM ' + b'ab' * 32 + b' ' + b'cd' * 48 + b'\n'


def _block(btype: 'int', body: 'bytes') -> 'bytes':
    """A little-endian block of ``btype`` around ``body``, padded to 32 bits."""
    body += bytes(-len(body) % 4)
    total = 12 + len(body)
    return struct.pack('<II', btype, total) + body + struct.pack('<I', total)


SHB = _block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
IDB = _block(1, struct.pack('<HHI', 1, 0, 0))


def _epb() -> 'bytes':
    """An Enhanced Packet Block on interface 0 holding :data:`FRAME`."""
    return _block(6, struct.pack('<IIIII', 0, 0, 0, len(FRAME), len(FRAME)) + FRAME)


def _dsb(secrets_type: 'int', secrets_length: 'int', secrets: 'bytes') -> 'bytes':
    """A Decryption Secrets Block declaring ``secrets_length`` over ``secrets``."""
    return _block(10, struct.pack('<II', secrets_type, secrets_length) + secrets)


class TestPCAPNGDSBSecretsOverrun(PCAPNGTestCase):
    """Pin how a Secrets Length past the block parses."""

    def _extract(self, block: 'bytes') -> 'tuple[list[bytes], list[str]]':
        """Extract a file holding ``block`` between two Enhanced Packet Blocks."""
        import pcapkit

        data = SHB + IDB + _epb() + block + _epb()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            extraction = pcapkit.extract(fin=io.BytesIO(data), nofile=True, store=True,
                                         engine='default')
        return ([bytes(frame.info.packet) for frame in extraction.frame],
                [str(item.message) for item in caught])

    def test_frames_around_an_overrun_survive(self) -> None:
        for secrets_type in (TLS_KEY_LOG, UNKNOWN_SECRETS, ZIGBEE_NWK_KEY):
            for secrets_length in (0xFFFF_FFF0, 5):
                with self.subTest(secrets_type=hex(secrets_type), secrets_length=secrets_length):
                    frames, messages = self._extract(_dsb(secrets_type, secrets_length, b'abcd'))
                    self.assertEqual(frames, [FRAME, FRAME])
                    self.assertIn(f'PCAP-NG: [Block 10] secrets length {secrets_length} runs past '
                                  'the block, which holds 4 octet(s); kept as captured', messages)
                    self.assertFalse(any('block length mismatch' in text for text in messages),
                                     messages)

    def test_overrun_keeps_the_declared_length(self) -> None:
        octets = _dsb(UNKNOWN_SECRETS, 0xFFFF_FFF0, b'abcd')
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = self._parse(octets)
        self.assertEqual(parsed.info.secrets_length, 0xFFFF_FFF0)  # type: ignore[attr-defined]
        self.assertEqual(parsed.info.secrets_data.data, b'abcd')  # type: ignore[attr-defined]
        self.assertEqual(parsed.__header__.pack().hex(), octets.hex())  # type: ignore[attr-defined]

    def test_overrun_rebuilds(self) -> None:
        """The data model rebuilds the declared ``secrets_length``, as an EPB does its ``captured_len``."""
        # NOTE: a ZigBee key shorter than its fixed width rebuilds as held too
        # (#1986).
        for secrets_type in (TLS_KEY_LOG, UNKNOWN_SECRETS, ZIGBEE_NWK_KEY):
            for secrets_length in (0xFFFF_FFF0, 5):
                with self.subTest(secrets_type=hex(secrets_type), secrets_length=secrets_length):
                    octets = _dsb(secrets_type, secrets_length, b'abcd')
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        self.assertEqual(self._parse(octets).__header__.pack().hex(), octets.hex())
                        self.assertRebuilds(octets)

    def test_cut_key_log_keeps_its_entries(self) -> None:
        """A key log the block ends inside keeps the lines before the cut one."""
        secrets = KEY_LOG + b'CLIENT_RA'
        # NOTE: short of the octets that follow, so the read is not a short one.
        octets = _dsb(TLS_KEY_LOG, len(secrets) + 60, secrets)
        frames, messages = self._extract(octets)
        self.assertEqual(frames, [FRAME, FRAME])
        self.assertTrue(any('runs past the block' in text for text in messages), messages)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = self._parse(octets)
        self.assertEqual(sum(len(entries) for entries in parsed.info.secrets_data.entries.values()),  # type: ignore[attr-defined]
                         1)
        self.assertEqual(parsed.__header__.pack().hex(), octets.hex())  # type: ignore[attr-defined]
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            self.assertRebuilds(octets)

    def assertValidBlock(self, octets: 'bytes', secrets_length: 'int') -> None:  # pylint: disable=invalid-name
        """Assert ``octets`` is one DSB as long as both its Block Total Lengths say."""
        length, = struct.unpack('<I', octets[4:8])
        self.assertEqual((len(octets), octets[-4:]), (length, octets[4:8]), octets.hex())
        self.assertEqual(struct.unpack('<I', octets[12:16])[0], secrets_length, octets.hex())

    def test_length_within_the_block_follows_the_secrets(self) -> None:
        """A length that fits the block is no overrun, so the rebuild keeps its padding.

        The two octets past the ZigBee key's fixed width are secrets the length
        declares, so they rebuild with it (#1986).
        """
        key = bytes(range(16)) + b'\x34\x12'
        octets = _dsb(ZIGBEE_NWK_KEY, 20, key)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            rebuilt = self._rebuild(octets)
        self.assertFalse(any('runs past the block' in str(item.message) for item in caught))
        self.assertValidBlock(rebuilt, 20)
        self.assertEqual(rebuilt.hex(), octets.hex())

    def test_edited_secrets_take_their_own_length(self) -> None:
        from pcapkit.protocols.misc.pcapng import PCAPNG

        info = self._parse(_dsb(UNKNOWN_SECRETS, 5, b'abcde')).info
        fields = {key: value for key, value in dict(info).items() if key != 'packet'}
        fields['secrets_data'] = info.secrets_data.__class__(data=b'ab')
        context = self._context()
        rebuilt = PCAPNG.from_data(info.__class__(**fields), num=2, sct=1, ctx=context).data
        self.assertValidBlock(rebuilt, 2)
        self.assertEqual(rebuilt[16:20], b'ab\x00\x00')

    def test_well_formed_blocks_are_unchanged(self) -> None:
        cases = (
            (TLS_KEY_LOG, KEY_LOG),
            (UNKNOWN_SECRETS, b'abcde'),
            (UNKNOWN_SECRETS, b''),
            (ZIGBEE_NWK_KEY, bytes(range(16)) + b'\x34\x12'),
        )
        for secrets_type, secrets in cases:
            with self.subTest(secrets_type=hex(secrets_type), secrets=secrets):
                octets = _dsb(secrets_type, len(secrets), secrets)
                frames, messages = self._extract(octets)
                self.assertEqual(frames, [FRAME, FRAME])
                self.assertFalse(any('runs past the block' in text for text in messages), messages)
                self.assertEqual(self._parse(octets).info.secrets_length, len(secrets))  # type: ignore[attr-defined]
                self.assertRebuilds(octets)

    def test_well_formed_block_with_options_is_unchanged(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        octets = _dsb(UNKNOWN_SECRETS, 5, b'abcde\x00\x00\x00' + b'\x01\x00\x03\x00abc\x00\x00\x00\x00\x00')
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            parsed = self._parse(octets)
        self.assertFalse(any('runs past the block' in str(item.message) for item in caught))
        self.assertEqual(parsed.info.options[OptionType.opt_comment].comment, 'abc')  # type: ignore[attr-defined]
        self.assertRebuilds(octets)


if __name__ == '__main__':
    unittest.main()
