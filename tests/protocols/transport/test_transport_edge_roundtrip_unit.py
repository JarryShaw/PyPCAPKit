# -*- coding: utf-8 -*-
"""Transport-layer edge cases round-trip byte for byte. C.f. #1202.

TCP and its option area, UDP, and SCTP with its chunks, at their minimum and
maximum lengths, with reserved bits and every flag set, with zero-length
values and padding variants, and with unassigned kinds and chunk types (all
four high-bit actions). Per-code option and chunk coverage is
:mod:`tests.protocols.test_option_roundtrip_unit`'s; these are the header-level
cases it does not build. The harness is :mod:`tests.protocols._edge_roundtrip`.

Every case builds its own octets in memory and reads no capture.

"""

from __future__ import annotations

import struct
import unittest

from tests.protocols import _edge_roundtrip as edge
from tests.protocols._edge_roundtrip import Case, Gap, MakeCase, Reject

TCP = 'pcapkit.protocols.transport.tcp:TCP'
UDP = 'pcapkit.protocols.transport.udp:UDP'
SCTP = 'pcapkit.protocols.transport.sctp:SCTP'


def tcp(opts: bytes = b'', payload: bytes = b'', flags: int = 0x002, reserved: int = 0,
        offset: 'int | None' = None, urgent: int = 0, ports: 'tuple[int, int]' = (40000, 40001)) -> bytes:
    """A TCP header with ``opts``, then ``payload``."""
    offset = (20 + len(opts)) // 4 if offset is None else offset
    return struct.pack('!HHIIHHHH', *ports, 1, 0, (offset << 12) | (reserved << 9) | flags,
                       65535, 0, urgent) + opts + payload


def udp(payload: bytes = b'', length: 'int | None' = None, ports: 'tuple[int, int]' = (40000, 40001),
        checksum: int = 0) -> bytes:
    """A UDP header, then ``payload``."""
    length = 8 + len(payload) if length is None else length
    return struct.pack('!HHHH', *ports, length, checksum) + payload


def chunk(type_: int, flags: int, value: bytes, pad: 'bytes | None' = None) -> bytes:
    """An SCTP chunk, zero-padded to four octets unless ``pad`` is given."""
    length = 4 + len(value)
    pad = bytes(-length % 4) if pad is None else pad
    return struct.pack('!BBH', type_, flags, length) + value + pad


#: SCTP common header.
COMMON = struct.pack('!HHII', 5000, 5001, 0xdeadbeef, 0)
#: DATA chunk TSN, stream, sequence and PPID.
DATA_HEAD = b'\x00\x00\x00\x01' + b'\x00\x01\x00\x02' + bytes(4)
#: INIT chunk fixed part.
INIT_HEAD = b'\x00\x00\x00\x01' + b'\x00\x00\xff\xff' + b'\x00\x01\x00\x01' + b'\x00\x00\x00\x01'

CASES = (
    # -- TCP ---------------------------------------------------------------
    Case('tcp/min-header', TCP, tcp()),
    Case('tcp/every-flag', TCP, tcp(flags=0x1ff)),
    Case('tcp/reserved-bits-set', TCP, tcp(reserved=7)),
    Case('tcp/urgent-pointer-max', TCP, tcp(flags=0x020, urgent=0xffff)),
    Case('tcp/offset-15-nop-pad', TCP, tcp(opts=b'\x01' * 40)),
    Case('tcp/offset-15-eol-pad', TCP, tcp(opts=bytes(40))),
    Case('tcp/eol-then-nonzero-pad', TCP, tcp(opts=b'\x00\xaa\xbb\xcc')),
    Case('tcp/nop-eol-nop-eol', TCP, tcp(opts=b'\x01\x00\x01\x00')),
    Case('tcp/mss-then-eol-pad', TCP, tcp(opts=b'\x02\x04\x05\xb4' + bytes(4))),
    Case('tcp/unassigned-kind-length-2', TCP, tcp(opts=b'\xfd\x02\x00\x00')),
    Case('tcp/unassigned-kind-200', TCP, tcp(opts=b'\xc8\x06abcd\x00\x00')),
    Case('tcp/unassigned-kind-max-length-40', TCP, tcp(opts=b'\x63\x28' + bytes(38))),
    Case('tcp/sack-permitted-then-nops', TCP, tcp(opts=b'\x04\x02\x01\x01')),
    Case('tcp/window-scale-shift-255', TCP, tcp(opts=b'\x03\x03\xff\x00')),
    Case('tcp/timestamps-max', TCP, tcp(opts=b'\x01\x01\x08\x0a' + b'\xff' * 8)),
    Case('tcp/payload-unknown-ports', TCP, tcp(payload=b'hello', ports=(1, 2))),
    Case('tcp/offset-4', TCP, tcp(offset=4)),
    Case('tcp/offset-past-the-data', TCP, tcp(offset=15)),
    # -- UDP ---------------------------------------------------------------
    Case('udp/min-header', UDP, udp()),
    Case('udp/length-0', UDP, udp(b'abc', length=0)),
    Case('udp/length-short-of-the-data', UDP, udp(b'abcd', length=10)),
    Case('udp/length-past-the-data', UDP, udp(b'ab', length=100)),
    Case('udp/length-short-of-the-header', UDP, udp(b'ab', length=4)),
    Case('udp/checksum-ffff', UDP, udp(b'ab', checksum=0xffff)),
    Case('udp/ports-0', UDP, udp(b'ab', ports=(0, 0))),
    Case('udp/ports-65535', UDP, udp(b'ab', ports=(65535, 65535))),
    # -- SCTP --------------------------------------------------------------
    Case('sctp/common-header-only', SCTP, COMMON),
    Case('sctp/data-1-octet-3-pad', SCTP, COMMON + chunk(0, 0x03, DATA_HEAD + b'X')),
    Case('sctp/data-nonzero-pad', SCTP, COMMON + chunk(0, 0x03, DATA_HEAD + b'X', pad=b'\xff' * 3)),
    Case('sctp/data-every-flag', SCTP, COMMON + chunk(0, 0xff, DATA_HEAD + b'XYZW')),
    Case('sctp/unassigned-type-action-00', SCTP, COMMON + chunk(0x3f, 0, b'ab')),
    Case('sctp/unassigned-type-action-01', SCTP, COMMON + chunk(0x7f, 0xff, b'')),
    Case('sctp/unassigned-type-action-10', SCTP, COMMON + chunk(0xbf, 0, b'abcde')),
    Case('sctp/unassigned-type-action-11', SCTP, COMMON + chunk(0xff, 0x55, b'abcdefgh')),
    Case('sctp/shutdown-ack-every-flag', SCTP, COMMON + chunk(8, 0xff, b'')),
    Case('sctp/cookie-ack', SCTP, COMMON + chunk(11, 0, b'')),
    Case('sctp/abort-t-bit', SCTP, COMMON + chunk(6, 1, b'')),
    Case('sctp/abort-unassigned-cause', SCTP, COMMON + chunk(6, 0, struct.pack('!HH', 0xfff0, 5) + b'z\x00\x00\x00')),
    Case('sctp/init-unassigned-parameter', SCTP,
         COMMON + chunk(1, 0, INIT_HEAD + struct.pack('!HH', 0xbfff, 5) + b'q\x00\x00\x00')),
    Case('sctp/two-empty-chunks', SCTP, COMMON + chunk(11, 0, b'') + chunk(14, 0, b'')),
    Case('sctp/heartbeat-empty-info', SCTP, COMMON + chunk(4, 0, struct.pack('!HH', 1, 4))),
    Case('sctp/last-chunk-unpadded', SCTP, COMMON + chunk(0x3f, 0, b'a', pad=b'')),
    Case('sctp/data-no-user-data', SCTP, COMMON + chunk(0, 0xff, DATA_HEAD)),
)

MAKE_CASES = (
    MakeCase('tcp/make/default', TCP, {}),
    MakeCase('tcp/make/every-flag', TCP,
             {'ns': True, 'cwr': True, 'ece': True, 'urg': True, 'ack': True, 'psh': True,
              'rst': True, 'syn': True, 'fin': True, 'urgent': 65535, 'window': 0}),
    MakeCase('udp/make/default', UDP, {}),
    MakeCase('udp/make/ports-max', UDP, {'srcport': 65535, 'dstport': 65535, 'payload': b'x'}),
    MakeCase('sctp/make/default', SCTP, {}),
)

REJECTED = {
    'tcp/offset-4': Reject('ProtocolError', 'resolved to a negative length'),
    'tcp/offset-past-the-data': Reject('ProtocolError', 'TCP: header length 60 runs past the end of the data'),
    'sctp/data-no-user-data': Reject('ProtocolError', 'SCTP: [Chunk 0] invalid format'),
}

KNOWN_FAILURES = (
    # ``sctp/last-chunk-unpadded`` is uncut: a final chunk sent without its pad
    # octets reads the pad short, and the rebuild writes three zero octets.
    Gap(1458, edge.ZERO_FILLED_SHORT_READ, 'PADDED', '',
        ('sctp/last-chunk-unpadded', 'sctp/last-chunk-unpadded/cut8',
         'sctp/common-header-only/cut*', 'sctp/data-1-octet-3-pad/cut31',
         'sctp/data-nonzero-pad/cut31', 'sctp/unassigned-type-action-00/cut*',
         'sctp/unassigned-type-action-01/cut8', 'sctp/unassigned-type-action-10/cut23',
         'sctp/shutdown-ack-every-flag/cut8', 'sctp/cookie-ack/cut8', 'sctp/abort-t-bit/cut8',
         'sctp/two-empty-chunks/cut10', 'sctp/heartbeat-empty-info/cut10', 'udp/min-header/cut*',
         'udp/length-0/cut5', 'udp/length-short-of-the-data/cut6', 'udp/length-past-the-data/cut5',
         'udp/length-short-of-the-header/cut5', 'udp/checksum-ffff/cut5', 'udp/ports-0/cut5',
         'udp/ports-65535/cut5')),
)


@unittest.skipUnless(edge.HAS_RUNTIME, 'runtime dependencies not installed')
class TransportEdgeRoundTripTests(edge.EdgeRoundTripBase):
    """Transport-layer edge cases."""

    CASES = CASES
    MAKE_CASES = MAKE_CASES
    REJECTED = REJECTED
    KNOWN_FAILURES = KNOWN_FAILURES


if __name__ == '__main__':
    unittest.main()
