# -*- coding: utf-8 -*-
"""GitHub issue #2688: a held ZigBee key is an ordinary short read.

:func:`~pcapkit.protocols.schema.misc.pcapng.zigbee_key_held` rebuilds a ZigBee
NWK or APS key schema from the Secrets Data octets a parsed block held. Without
the fix it zero-fills those octets to the key's fixed width and records the cut
by hand, so the schema's buffers span the fixed width until it is packed:
:func:`bytes` and :func:`len` of it are wrong, and a Decryption Secrets Block
made from a parsed short key is sized from them and written corrupt. With it,
the octets are unpacked as they are, :meth:`Schema.unpack` records the cut, and
the warning the parse reported for that cut is not reported again.

Each key is cut at every offset, and read past its fixed width as well.
:mod:`pcapkit` is imported inside each test, after
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
    from typing import Any, Iterator, Optional

#: Each key's Secrets Type, with its fields and their widths in octets as the
#: PCAP-NG specification lays the Secrets Data out.
FIELDS = {
    0x5A4E574B: (('key', 16), ('panid', 2)),  # ZigBee NWK Key
    0x5A415053: (('key', 16), ('panid', 2), ('addr_low', 2), ('addr_high', 2)),  # ZigBee APS Key
}

#: Octets past the fixed width the sweep reads as well, kept as ``trailing``.
PAST = 3


def _secrets(count: 'int') -> 'bytes':
    """``count`` non-zero octets, so a zero-filled rebuild cannot pass for them."""
    return bytes(range(1, count + 1))


def _dsb(secrets_type: 'int', secrets: 'bytes') -> 'bytes':
    """A little-endian Decryption Secrets Block declaring exactly ``secrets``."""
    body = struct.pack('<II', secrets_type, len(secrets)) + secrets
    body += bytes(-len(body) % 4)
    total = 12 + len(body)
    return struct.pack('<II', 10, total) + body + struct.pack('<I', total)


def _cut(fields: 'tuple[tuple[str, int], ...]', count: 'int') -> 'Optional[tuple[str, int]]':
    """The field ``count`` octets end inside, and how many of its octets they hold."""
    offset = 0
    for name, width in fields:
        if count < offset + width:
            return (name, count - offset)
        offset += width
    return None


class _Logged(logging.Handler):
    """Collect what the ``pcapkit`` logger reports."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.messages = []  # type: list[str]

    def emit(self, record: 'logging.LogRecord') -> None:
        self.messages.append(f'logged: {record.getMessage()}')


@contextlib.contextmanager
def _reported() -> 'Iterator[list[str]]':
    """Collect what the block reports, on the :mod:`warnings` channel and the logger."""
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


class TestPCAPNGZigBeeKeyHeld(PCAPNGTestCase):
    """Pin a held ZigBee key cut at every offset, at schema and at protocol level."""

    def _cases(self) -> 'Iterator[tuple[Any, int, tuple[tuple[str, int], ...], int]]':
        """Each key's schema, Secrets Type and fields, with every count of octets swept."""
        from pcapkit.protocols.schema.misc.pcapng import ZigBeeAPSKey, ZigBeeNWKKey

        schemas = {0x5A4E574B: ZigBeeNWKKey, 0x5A415053: ZigBeeAPSKey}
        for secrets_type, fields in FIELDS.items():
            schema = schemas[secrets_type]
            self.assertEqual(tuple((name, field.length) for name, field in schema.__fields__.items()
                                   if name != 'trailing'), fields)
            for count in range(sum(width for _, width in fields) + PAST + 1):
                yield schema, secrets_type, fields, count

    def test_schema_holds_the_octets_held(self) -> None:
        """The schema holds exactly the octets given, records their cut, and reports nothing."""
        from pcapkit.protocols.schema.misc.pcapng import zigbee_key_held

        for schema, secrets_type, fields, count in self._cases():
            with self.subTest(secrets_type=hex(secrets_type), count=count):
                data = _secrets(count)
                with _reported() as messages:
                    held = zigbee_key_held(schema, data)
                self.assertEqual(messages, [])
                # read before packing, which cuts the buffers back itself
                self.assertEqual(bytes(held).hex(), data.hex())
                self.assertEqual(len(held), count)
                self.assertEqual(held.__dict__.get('__short_read__'), _cut(fields, count))
                self.assertEqual(held.key, data[:16].ljust(16, b'\x00'))
                self.assertEqual(held.panid, int.from_bytes(data[16:18].ljust(2, b'\x00'), 'little'))
                width = sum(width for _, width in fields)
                self.assertEqual(held.trailing, data[width:] if count > width else None)
                self.assertEqual(held.pack().hex(), data.hex())

    def test_made_block_is_the_captured_block(self) -> None:
        """Made from the parsed key, or rebuilt from the block, it is as captured and quiet."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        for _, secrets_type, _, count in self._cases():
            with self.subTest(secrets_type=hex(secrets_type), count=count):
                octets = _dsb(secrets_type, _secrets(count))
                context = self._context()
                with _reported():
                    parsed = PCAPNG(octets, len(octets), num=2, sct=1, ctx=context)
                with _reported() as messages:
                    made = PCAPNG(num=2, sct=1, ctx=context, type=BlockType.Decryption_Secrets_Block,
                                  block={'secrets_type': parsed.info.secrets_type,  # type: ignore[attr-defined]
                                         'secrets_data': parsed.info.secrets_data}).data  # type: ignore[attr-defined]
                    rebuilt = PCAPNG.from_data(parsed.info, num=2, sct=1, ctx=context).data
                self.assertEqual(made.hex(), octets.hex())
                self.assertEqual(rebuilt.hex(), octets.hex())
                self.assertEqual(messages, [])


if __name__ == '__main__':
    unittest.main()
