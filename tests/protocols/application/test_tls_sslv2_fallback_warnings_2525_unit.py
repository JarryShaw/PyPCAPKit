# -*- coding: utf-8 -*-
"""GitHub issue #2525: an SSLv2 hello on TCP 443 reports nothing of TLS's rejected trial.

:meth:`TLS.unpack <pcapkit.protocols.application.tls.TLS.unpack>` tries TLS
first, and offers the record to SSLv2 only once TLS rejects it. An SSLv2
CLIENT-HELLO advertising ``0x0300``, ``0x0301`` or ``0x0303`` puts that version's
octets where TLS reads its record length, so TLS's header read warns
``packet length < 0`` and TLS rejects the record. Unheld, that warning replays
with the kept SSLv2 layer, and under an ``error`` filter it turns the valid hello
into ``Raw``. A failed SSLv2 trial's warnings are dropped too, and a direct parse
that both trials reject reports TLS's alone, as #2308 rules for a trial outside
``beholder``.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import struct
import unittest
import warnings

from tests._support import reimport_once_per_class
from tests.utilities._harness import capture

#: Test tier (#1958): exercises the warning machinery, which free-threaded
#: builds make context-aware.
__tier__ = 'ALL'

#: A 20-octet TCP header, 50000 to 443, ACK.
TCP_TO_443 = struct.pack('!HHIIBBHHH', 50000, 443, 1, 1, 5 << 4, 0x10, 65535, 0, 0)
#: The versions the issue reports, all of them TLS-era values SSLv2 hellos carry.
VERSIONS = (0x0300, 0x0301, 0x0303)
#: An SSLv2 CLIENT-HELLO cut 4 octets short of its RECORD-LENGTH.
CUT_HELLO = (b'\x80\x1c' + b'\x01\x00\x02\x00\x03\x00\x00\x00\x10'
             + b'\x01\x00\x80' + bytes(12))
#: A TLS record header declaring a fragment far past the octets that follow it.
LONG_RECORD = b'\x17\x03\x03\xff\xffhello'


def _client_hello(version: 'int', *, two_byte_header: 'bool') -> 'bytes':
    """An SSLv2 CLIENT-HELLO advertising ``version``, with three cipher specs."""
    specs = bytes.fromhex('010080' '000004' '00002f')
    challenge = bytes(range(16))
    body = (b'\x01' + struct.pack('!HHHH', version, len(specs), 0, len(challenge))
            + specs + challenge)
    if two_byte_header:
        return struct.pack('!H', 0x8000 | len(body)) + body
    return struct.pack('!HB', len(body), 0) + body


class TestSSLv2FallbackWarnings(unittest.TestCase):
    """Pin that a trial the result does not keep reports none of its warnings."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _tcp(payload: 'bytes', action: 'str') -> 'tuple[object, list[warnings.WarningMessage]]':
        """Parse ``payload`` on TCP 443 under ``action``, with the warnings it reports."""
        from pcapkit.protocols.transport.tcp import TCP

        data = TCP_TO_443 + payload
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter(action)
            parsed = TCP(data, len(data))
        return parsed, caught

    def test_tls_header_read_warns_on_each_hello(self) -> None:
        """Premise: TLS's record header alone warns on each hello the issue reports."""
        from pcapkit.protocols.schema.application.tls import TLS as Schema_TLS

        for version in VERSIONS:
            for two_byte_header in (True, False):
                with self.subTest(version=hex(version), two_byte_header=two_byte_header):
                    with warnings.catch_warnings(record=True) as caught:
                        warnings.simplefilter('always')
                        Schema_TLS.unpack(_client_hello(version, two_byte_header=two_byte_header))
                    self.assertTrue(any(str(item.message).startswith('packet length < 0')
                                        for item in caught), [str(item.message) for item in caught])

    def test_hello_is_sslv2_and_warns_nothing(self) -> None:
        """Under ``always``, each hello is SSLv2 and reports nothing on either channel."""
        from pcapkit.utilities.logging import logger

        for version in VERSIONS:
            for two_byte_header in (True, False):
                with self.subTest(version=hex(version), two_byte_header=two_byte_header):
                    with capture(logger) as recorder:
                        parsed, caught = self._tcp(_client_hello(version, two_byte_header=two_byte_header),
                                                   'always')
                    self.assertEqual(str(parsed.protochain), 'TCP:SSLv2')  # type: ignore[attr-defined]
                    self.assertEqual(int(parsed.payload.info.body.client_version), version)  # type: ignore[attr-defined]
                    self.assertEqual([str(item.message) for item in caught], [])
                    self.assertEqual([record.getMessage() for record in recorder.records
                                      if record.getMessage().startswith('packet length')], [])

    def test_error_filter_keeps_the_hello(self) -> None:
        """Under ``error``, TLS's held warning cannot turn the hello into ``Raw``."""
        for version in VERSIONS:
            for two_byte_header in (True, False):
                with self.subTest(version=hex(version), two_byte_header=two_byte_header):
                    parsed, caught = self._tcp(_client_hello(version, two_byte_header=two_byte_header),
                                               'error')
                    self.assertEqual(str(parsed.protochain), 'TCP:SSLv2')  # type: ignore[attr-defined]
                    self.assertEqual(caught, [])

    def test_rejected_sslv2_trial_warns_nothing(self) -> None:
        """A cut hello fails the SSLv2 trial too, which drops its warnings under either filter."""
        for action in ('always', 'error'):
            with self.subTest(action=action):
                parsed, caught = self._tcp(CUT_HELLO, action)
                self.assertEqual(str(parsed.protochain), 'TCP:Raw')  # type: ignore[attr-defined]
                self.assertEqual(parsed.payload.info.error,  # type: ignore[attr-defined]
                                 'TLS: invalid format: unrecognised content type 128')
                self.assertEqual([str(item.message) for item in caught], [])

    def test_both_trials_rejected_under_beholder_warn_nothing(self) -> None:
        """On TCP 443 ``beholder`` replaces the layer, so TLS's trial warnings go with it."""
        for action in ('always', 'error'):
            with self.subTest(action=action):
                parsed, caught = self._tcp(LONG_RECORD, action)
                self.assertEqual(str(parsed.protochain), 'TCP:Raw')  # type: ignore[attr-defined]
                self.assertEqual(parsed.payload.info.error,  # type: ignore[attr-defined]
                                 'TLS: invalid format: record length 65535 runs past the end of the buffer')
                self.assertEqual([str(item.message) for item in caught], [])

    def test_both_trials_rejected_outside_beholder_report_tls_alone(self) -> None:
        """A direct parse raises TLS's error and reports TLS's trial warning, not SSLv2's."""
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.utilities.exceptions import ProtocolError

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            with self.assertRaisesRegex(ProtocolError, 'record length 65535 runs past'):
                TLS(LONG_RECORD, len(LONG_RECORD))
        self.assertEqual([str(item.message) for item in caught], ['packet length < 0: -65530'])


if __name__ == '__main__':
    unittest.main()
