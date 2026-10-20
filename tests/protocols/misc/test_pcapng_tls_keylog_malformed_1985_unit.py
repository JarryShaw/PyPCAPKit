# -*- coding: utf-8 -*-
"""GitHub issue #1985: a malformed key log line is reported, not refused.

A line of a TLS or WireGuard key log that does not parse -- an unknown label,
fields that are not hexadecimal, a garbage line, or the first octets of an entry
cut inside the block's padding -- raises a
:class:`~pcapkit.utilities.warnings.ProtocolWarning` from
:meth:`TLSKeyLog.post_process <pcapkit.protocols.schema.misc.pcapng.TLSKeyLog.post_process>`
rather than a :exc:`~pcapkit.utilities.exceptions.FieldValueError`, which would
end the whole extraction. The line is kept as captured in the log text and leaves
no trace in the entries, the well-formed entries around it are kept, and the
block rebuilds octet for octet.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import base64
import unittest
import warnings

from tests.protocols.misc.test_pcapng_dsb_secrets_overrun_1980_unit import (IDB, SHB,
                                                                            TLS_KEY_LOG, _dsb,
                                                                            _epb)
from tests.protocols.misc.test_pcapng_roundtrip2_unit import PCAPNGTestCase

FRAME = bytes(range(1, 61))

#: Secrets Type of a WireGuard Key Log.
WIREGUARD_KEY_LOG = 0x57474B4C

#: Two well-formed TLS key log lines, under different labels.
TLS_LINE = b'CLIENT_RANDOM ' + b'ab' * 32 + b' ' + b'cd' * 48 + b'\n'
TLS_LINE2 = b'SERVER_HANDSHAKE_TRAFFIC_SECRET ' + b'12' * 32 + b' ' + b'34' * 32 + b'\n'

#: One well-formed WireGuard key log line.
WG_KEY = bytes(range(32))
WG_LINE = b'LOCAL_STATIC_PRIVATE_KEY = ' + base64.b64encode(WG_KEY) + b'\n'

#: Malformed TLS key log lines, each followed by a newline.
TLS_MALFORMED = (
    b'NOT_A_LABEL aa bb\n',
    b'CLIENT_RANDOM zz yy\n',
    b'garbage\n',
    b'CLIENT_RANDOM ' + b'ab' * 32 + b'\n',
    b'\xff\xfe junk\n',
)


class TestPCAPNGKeyLogMalformedLine(PCAPNGTestCase):
    """Pin how a key log line that does not parse is treated."""

    def _extract(self, block: 'bytes') -> 'tuple[list[bytes], list[str]]':
        """Extract a file holding ``block`` between two Enhanced Packet Blocks."""
        import io

        import pcapkit
        from pcapkit.utilities.warnings import ProtocolWarning

        data = SHB + IDB + _epb() + block + _epb()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            extraction = pcapkit.extract(fin=io.BytesIO(data), nofile=True, store=True,
                                         engine='default')
        return ([bytes(frame.info.packet) for frame in extraction.frame],
                [str(item.message) for item in caught if issubclass(item.category, ProtocolWarning)])

    def _parse_quietly(self, octets: 'bytes') -> 'object':
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return self._parse(octets)

    def assertRebuildsQuietly(self, octets: 'bytes') -> None:  # pylint: disable=invalid-name
        """Assert ``octets`` rebuild byte-exactly from both the schema and the data model."""
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            self.assertEqual(self._parse(octets).__header__.pack().hex(), octets.hex())  # type: ignore[attr-defined]
            self.assertRebuilds(octets)

    def assertKeyLogLine(self, messages: 'list[str]', kind: 'str', line: 'bytes') -> None:  # pylint: disable=invalid-name
        """Assert ``messages`` report ``line`` of a ``kind`` key log kept as captured."""
        text = line.rstrip(b'\n').decode('ascii', errors='replace')
        self.assertIn(f'PCAP-NG: invalid {kind} key log format: {text!r}; line kept as captured',
                      messages)

    def _tls_entries(self, octets: 'bytes') -> 'list[tuple[str, bytes, bytes]]':
        secrets = self._parse_quietly(octets).info.secrets_data  # type: ignore[attr-defined]
        return [(label.name, random, secret)
                for label, entry in secrets.entries.items()
                for random, secret in entry.items(multi=True)]

    def test_malformed_first_line(self) -> None:
        for line in TLS_MALFORMED:
            with self.subTest(line=line):
                secrets = line + TLS_LINE
                octets = _dsb(TLS_KEY_LOG, len(secrets), secrets)
                frames, messages = self._extract(octets)
                self.assertEqual(frames, [FRAME, FRAME])
                self.assertKeyLogLine(messages, 'TLS', line)
                self.assertEqual(self._tls_entries(octets),
                                 [('CLIENT_RANDOM', b'\xab' * 32, b'\xcd' * 48)])
                self.assertRebuildsQuietly(octets)

    def test_malformed_middle_line(self) -> None:
        for line in TLS_MALFORMED:
            with self.subTest(line=line):
                secrets = TLS_LINE + line + TLS_LINE2
                octets = _dsb(TLS_KEY_LOG, len(secrets), secrets)
                frames, messages = self._extract(octets)
                self.assertEqual(frames, [FRAME, FRAME])
                self.assertKeyLogLine(messages, 'TLS', line)
                self.assertEqual(self._tls_entries(octets),
                                 [('CLIENT_RANDOM', b'\xab' * 32, b'\xcd' * 48),
                                  ('SERVER_HANDSHAKE_TRAFFIC_SECRET', b'\x12' * 32, b'\x34' * 32)])
                self.assertRebuildsQuietly(octets)

    def test_cut_last_line_inside_the_padding(self) -> None:
        """A last line cut inside the block's padding is no overrun, and is reported as malformed."""
        secrets = TLS_LINE + b'CLIENT_RA'
        # NOTE: one octet past the secrets, which the block's padding still holds.
        octets = _dsb(TLS_KEY_LOG, len(secrets) + 1, secrets)
        frames, messages = self._extract(octets)
        self.assertEqual(frames, [FRAME, FRAME])
        self.assertFalse(any('runs past the block' in text for text in messages), messages)
        self.assertKeyLogLine(messages, 'TLS', b'CLIENT_RA\x00')
        self.assertEqual(self._tls_entries(octets), [('CLIENT_RANDOM', b'\xab' * 32, b'\xcd' * 48)])
        self.assertEqual(self._parse_quietly(octets).info.secrets_length, len(secrets) + 1)  # type: ignore[attr-defined]
        self.assertRebuildsQuietly(octets)

    def test_malformed_wireguard_line(self) -> None:
        from pcapkit.protocols.misc.pcapng import WireGuardKeyLabel

        for line in (b'BOGUS = AAAA\n', b'LOCAL_STATIC_PRIVATE_KEY AAAA\n', b'LOCAL_STATIC_PRIVATE_KEY = Q\n'):
            for secrets in (line + WG_LINE, WG_LINE + line + WG_LINE):
                with self.subTest(secrets=secrets):
                    octets = _dsb(WIREGUARD_KEY_LOG, len(secrets), secrets)
                    frames, messages = self._extract(octets)
                    self.assertEqual(frames, [FRAME, FRAME])
                    self.assertKeyLogLine(messages, 'WireGuard', line)
                    entries = self._parse_quietly(octets).info.secrets_data.entries  # type: ignore[attr-defined]
                    self.assertEqual(list(entries.items(multi=True)),
                                     [(WireGuardKeyLabel.LOCAL_STATIC_PRIVATE_KEY, WG_KEY)]
                                     * secrets.count(WG_LINE))
                    self.assertRebuildsQuietly(octets)

    def test_malformed_line_leaves_no_empty_bucket(self) -> None:
        """A line with a known label but fields that do not decode adds no bucket for that label."""
        from pcapkit.const.pcapng.tls_key_label import TLSKeyLabel
        from pcapkit.protocols.schema.misc.pcapng import TLSKeyLog, WireGuardKeyLog

        for secrets in (b'CLIENT_RANDOM zz yy\n', b'CLIENT_RANDOM zz yy\n' + TLS_LINE2,
                        b'CLIENT_RANDOM ' + b'ab' * 32 + b' zz\n'):
            with self.subTest(secrets=secrets):
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    schema = TLSKeyLog.unpack(secrets, len(secrets))
                self.assertNotIn(TLSKeyLabel.CLIENT_RANDOM, schema.entries)
                self.assertTrue(all(len(entry) for entry in schema.entries.values()), schema.entries)

                octets = _dsb(TLS_KEY_LOG, len(secrets), secrets)
                entries = self._parse_quietly(octets).info.secrets_data.entries  # type: ignore[attr-defined]
                self.assertNotIn(TLSKeyLabel.CLIENT_RANDOM, entries)
                self.assertTrue(all(len(entry) for entry in entries.values()), entries)
                self.assertRebuildsQuietly(octets)

        secrets = b'LOCAL_STATIC_PRIVATE_KEY = Q\n'
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            schema = WireGuardKeyLog.unpack(secrets, len(secrets))
        self.assertEqual(len(schema.entries), 0)

    def test_well_formed_logs_are_unchanged(self) -> None:
        cases = (
            (TLS_KEY_LOG, TLS_LINE + b'# a comment\n\n' + TLS_LINE2),
            (TLS_KEY_LOG, TLS_LINE),
            (WIREGUARD_KEY_LOG, b'# a comment\n' + WG_LINE),
        )
        for secrets_type, secrets in cases:
            with self.subTest(secrets_type=hex(secrets_type), secrets=secrets):
                octets = _dsb(secrets_type, len(secrets), secrets)
                frames, messages = self._extract(octets)
                self.assertEqual(frames, [FRAME, FRAME])
                self.assertFalse(any('key log format' in text for text in messages), messages)
                self.assertRebuildsQuietly(octets)
        self.assertEqual(self._tls_entries(_dsb(TLS_KEY_LOG, len(cases[0][1]), cases[0][1])),
                         [('CLIENT_RANDOM', b'\xab' * 32, b'\xcd' * 48),
                          ('SERVER_HANDSHAKE_TRAFFIC_SECRET', b'\x12' * 32, b'\x34' * 32)])


if __name__ == '__main__':
    unittest.main()
