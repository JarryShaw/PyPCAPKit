# -*- coding: utf-8 -*-
"""GitHub issue #2698: a Decryption Secrets Block rebuilds as captured from its dict.

:meth:`PCAPNG.from_data <pcapkit.protocols.protocol.Protocol.from_data>` takes a
parsed block's data model or the :obj:`dict` that ``to_dict`` makes of it, and
both must give the captured block back. The dict's secrets come back from
:meth:`~pcapkit.corekit.infoclass.Info.from_dict` as a mapping rather than as
their data model, so the block maker spreads them into the secrets maker as its
keywords. A key log's text and a ZigBee key's Secrets Data octets are held
under ``data``, which the TLS, WireGuard and ZigBee makers read from a data
model alone: from the dict, a key log was written from its entries under a
generated comment, and a ZigBee key from its zero-filled fields. Each takes
``data`` as a keyword too, as the unknown-secrets maker does.

Every registered secrets type, and an unregistered one, is swept whole, cut at
every octet, and past its fixed width where it has one. Each block is rebuilt
from its data model and from its dict, and both must give the captured octets
and report the same. :mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import contextlib
import logging
import struct
import unittest
import warnings
from typing import TYPE_CHECKING

from tests.protocols.misc.test_pcapng_roundtrip2_unit import PCAPNGTestCase

if TYPE_CHECKING:
    from typing import Any, Iterator

#: Secrets Types: an unregistered one, then the TLS and WireGuard key logs and
#: the ZigBee NWK and APS keys.
UNKNOWN = 0x12345678
TLS = 0x544C534B
WIREGUARD = 0x57474B4C
ZIGBEE_NWK = 0x5A4E574B
ZIGBEE_APS = 0x5A415053

#: Each Secrets Type's Secrets Data, whole: the key logs with a comment, a
#: label in lower case and a line that does not parse, all of which the
#: entries drop and the text keeps, and the ZigBee keys at their fixed width.
WHOLE = {
    UNKNOWN: bytes(range(1, 23)),
    TLS: (b'# keys\nCLIENT_RANDOM 00112233 aabbccdd\n'
          b'client_random 0011 aa\nCLIENT_RANDOM 00112233\n'),
    WIREGUARD: (b'# keys\nLOCAL_STATIC_PRIVATE_KEY = ' + b'A' * 43 + b'=\n'
                b'preshared_key = ' + b'B' * 43 + b'=\nPRESHARED_KEY\n'),
    ZIGBEE_NWK: bytes(range(1, 19)),
    ZIGBEE_APS: bytes(range(1, 23)),
}

#: The Secrets Types read as a fixed width, past which more octets are kept.
FIXED = (UNKNOWN, ZIGBEE_NWK, ZIGBEE_APS)

#: Octets past the whole Secrets Data that the sweep reads as well.
PAST = bytes(range(0xF0, 0xF4))


def _dsb(secrets_type: 'int', secrets: 'bytes', secrets_length: 'int | None' = None) -> 'bytes':
    """A little-endian Decryption Secrets Block over ``secrets``, padded with zeros."""
    declared = len(secrets) if secrets_length is None else secrets_length
    body = struct.pack('<II', secrets_type, declared) + secrets
    body += bytes(-len(body) % 4)
    total = 12 + len(body)
    return struct.pack('<II', 10, total) + body + struct.pack('<I', total)


class _Logged(logging.Handler):
    """Collect what the ``pcapkit`` logger reports."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.messages = []  # type: list[str]

    def emit(self, record: 'logging.LogRecord') -> None:
        self.messages.append(f'logged: {record.getMessage()}')


@contextlib.contextmanager
def _reported() -> 'Iterator[list[str]]':
    """Collect what a rebuild reports, on the :mod:`warnings` channel and the logger."""
    handler = _Logged()
    logger = logging.getLogger('pcapkit')
    logger.addHandler(handler)
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            yield handler.messages
    finally:
        logger.removeHandler(handler)
    handler.messages.extend(f'warned: {item.message}' for item in caught)


class TestPCAPNGDSBSecretsDict(PCAPNGTestCase):
    """Pin a Decryption Secrets Block rebuilt from its data model and from its dict."""

    def _secrets_types(self) -> 'Iterator[int]':
        """Each Secrets Type swept, after checking that the sweep names every registered one."""
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG

        self.assertNotIn(UNKNOWN, PCAPNG.__secrets__)
        self.assertEqual(set(WHOLE) - {UNKNOWN}, {int(code) for code in PCAPNG.__secrets__})
        yield from WHOLE

    def _assert_rebuilds(self, octets: 'bytes') -> None:
        """Parse ``octets``, then rebuild them from the data model and from its dict."""
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG

        context = self._context()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = PCAPNG(octets, len(octets), num=2, sct=1, ctx=context)

        reports = {}  # type: dict[str, list[str]]
        for path, data in (('model', parsed.info), ('dict', parsed.info.to_dict())):
            with self.subTest(path=path):
                with _reported() as messages:
                    rebuilt = PCAPNG.from_data(data, num=2, sct=1, ctx=context).data
                reports[path] = messages
                self.assertEqual(rebuilt.hex(), octets.hex())
        self.assertEqual(reports.get('dict'), reports.get('model'))

    def test_whole_secrets_rebuild(self) -> None:
        """The issue's TLS line, and each Secrets Type whole, rebuild from either."""
        with self.subTest(secrets_type='issue'):
            self._assert_rebuilds(_dsb(TLS, b'CLIENT_RANDOM 00112233 aabbccdd\n'))
        for secrets_type in self._secrets_types():
            with self.subTest(secrets_type=hex(secrets_type)):
                self._assert_rebuilds(_dsb(secrets_type, WHOLE[secrets_type]))

    def test_cut_secrets_rebuild(self) -> None:
        """Secrets Data cut at every octet rebuild from either, as captured."""
        for secrets_type in self._secrets_types():
            whole = WHOLE[secrets_type]
            for count in range(len(whole)):
                with self.subTest(secrets_type=hex(secrets_type), count=count):
                    self._assert_rebuilds(_dsb(secrets_type, whole[:count]))

    def test_secrets_past_the_fixed_width_rebuild(self) -> None:
        """Octets past a fixed width rebuild from either, as captured."""
        for secrets_type in self._secrets_types():
            if secrets_type not in FIXED:
                continue
            for count in range(1, len(PAST) + 1):
                with self.subTest(secrets_type=hex(secrets_type), count=count):
                    self._assert_rebuilds(_dsb(secrets_type, WHOLE[secrets_type] + PAST[:count]))

    def test_secrets_length_past_the_block_rebuilds(self) -> None:
        """A Secrets Length past the block rebuilds from either, as declared (#1980)."""
        for secrets_type in self._secrets_types():
            whole = WHOLE[secrets_type]
            for count in (0, len(whole) // 2, len(whole)):
                with self.subTest(secrets_type=hex(secrets_type), count=count):
                    self._assert_rebuilds(_dsb(secrets_type, whole[:count], 0xFFFF_FFF0))

    def test_data_keyword_is_written_verbatim(self) -> None:
        """Made from keywords, ``data`` is written as given, over the decoded fields."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.tls_key_label import TLSKeyLabel
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG, WireGuardKeyLabel

        decoded = {
            UNKNOWN: {},
            TLS: {'entries': {TLSKeyLabel.CLIENT_RANDOM: OrderedMultiDict([(b'\x01', b'\x02')])}},
            WIREGUARD: {'entries': OrderedMultiDict([(WireGuardKeyLabel.PRESHARED_KEY, bytes(32))])},
            ZIGBEE_NWK: {'nwk_key': bytes(16), 'pan_id': 0x1234},
            ZIGBEE_APS: {'aps_key': bytes(16), 'pan_id': 0x1234, 'short_address': 0x56789ABC},
        }  # type: dict[int, dict[str, Any]]
        for secrets_type in self._secrets_types():
            whole = WHOLE[secrets_type]
            data = whole.decode('ascii') if secrets_type in (TLS, WIREGUARD) else whole
            with self.subTest(secrets_type=hex(secrets_type)), warnings.catch_warnings():
                # the made block is parsed back, which reports the malformed lines
                warnings.simplefilter('ignore')
                made = PCAPNG(num=2, sct=1, ctx=self._context(), type=BlockType.Decryption_Secrets_Block,
                              block={'secrets_type': secrets_type,
                                     'secrets_data': dict(decoded[secrets_type], data=data)}).data
                self.assertEqual(made.hex(), _dsb(secrets_type, whole).hex())


if __name__ == '__main__':
    unittest.main()
