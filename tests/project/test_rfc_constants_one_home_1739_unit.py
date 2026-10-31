# -*- coding: utf-8 -*-
"""Each duplicated RFC-fixed constant has one home, and its readers import it.

Ruling 7 on GitHub issue #1726, tracked as #1739: a protocol constant that the
RFC (or the file format) fixes, and that more than one module spelled out, is
defined once, in the module that owns the protocol -- or that protocol's schema
or :mod:`pcapkit.const` module -- and every reader imports it from there. Such a
constant is never configurable, and no other module re-exports it.

These checks pin that:

* :class:`TestHomes` -- each constant is defined in its home, with the value the
  RFC or the format gives it;
* :class:`TestOneDefinition` -- no other module under :mod:`pcapkit` assigns the
  name, at module or class level, and none spells the distinctive literals (the
  PCAP and PCAP-NG magic numbers and the PCAP timestamp resolutions) itself;
* :class:`TestReaders` -- each reader imports the constant from its home and
  reads it, and :mod:`pcapkit.toolkit.pypcapfile`, a reader of several, binds
  none of those names at all;
* :class:`TestNotReinlined` -- no module in :data:`SWEPT`, the homes included,
  spells a homed value anywhere but in the home's own definition: not as an
  operand, a call argument, a subscript, a default, a returned value, a tuple
  or table element, a branch of a conditional, nor an assignment at any level.
  Each match that means something else is listed in :data:`NOT_A_COPY` or
  :data:`UNRELATED` with the reason, and the values that are equal but not the
  same constant in :data:`DISTINCT`.

The source checks read each module with :mod:`ast` rather than importing it.
:mod:`pcapkit.vendor` and :mod:`pcapkit.const` are generated and are not read.

This module is unit-tier and reads no capture.

"""
from __future__ import annotations

import ast
import importlib
import pathlib
import sys
import unittest

#: Test tier (#1958): checks that each RFC constant has one home, a question about the
#: tree.
__tier__ = 'LATEST'

#: Repository root.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The package directory.
PACKAGE = ROOT / 'pcapkit'

#: Each consolidated constant: its home module, its name and its value.
HOMES = (
    ('pcapkit.protocols.schema.internet.ipv4', 'IPV4_HEADER_LEN', 20),
    ('pcapkit.protocols.internet.ipv6', 'IPV6_HEADER_LEN', 40),
    ('pcapkit.protocols.internet.ipv6', 'IPV6_NEXT_HEADER_OFFSET', 6),
    ('pcapkit.protocols.schema.internet.ipv6', 'IP_MAX_LENGTH', 65535),
    ('pcapkit.protocols.schema.internet.ah', 'AH_HEADER_LEN', 12),
    ('pcapkit.protocols.schema.transport.tcp', 'TCP_MIN_HEADER_LEN', 20),
    ('pcapkit.protocols.schema.transport.tcp', 'TCP_DATA_OFFSET_OCTET', 12),
    ('pcapkit.protocols.schema.misc.pcap.header', 'GLOBAL_HEADER_LEN', 24),
    ('pcapkit.protocols.schema.misc.pcap.frame', 'RECORD_HEADER_LEN', 16),
    ('pcapkit.protocols.schema.misc.pcap.header', 'MAGIC_NUMBER', {
        b'\xa1\xb2\x3c\x4d': ('big', True),
        b'\xa1\xb2\xc3\xd4': ('big', False),
        b'\x4d\x3c\xb2\xa1': ('little', True),
        b'\xd4\xc3\xb2\xa1': ('little', False),
    }),
    ('pcapkit.protocols.schema.misc.pcap.header', 'RESOLUTION', {False: 10 ** 6, True: 10 ** 9}),
    ('pcapkit.protocols.schema.misc.pcap.header', 'RESOLUTION_PLACES', {False: 6, True: 9}),
    ('pcapkit.protocols.schema.misc.pcapng', 'BYTE_ORDER_MAGIC', 0x1A2B3C4D),
    ('pcapkit.protocols.schema.misc.pcapng', 'DEFAULT_RESOLUTION', 10 ** 6),
    ('pcapkit.protocols.schema.misc.pcapng', 'GENERIC_BLOCK_MINIMUM', 12),
    ('pcapkit.protocols.schema.misc.pcapng', 'BLOCK_MINIMUM', {
        0x0A0D0D0A: 28, 0x00000001: 20, 0x00000002: 32, 0x00000003: 16, 0x00000005: 24,
        0x00000006: 32, 0x0000000A: 20, 0x00000BAD: 16, 0x40000BAD: 16,
    }),
)

#: Names a module other than their home must not define, each with a module
#: that must not define it (#1739). ``MAGIC_NUMBER`` stays a class attribute of the PCAP
#: and PCAP-NG engines -- the extractor dispatches on it -- but is built from
#: the home rather than spelled out, which :class:`TestOneDefinition` checks
#: through the literals.
OLD_NAMES = (
    ('pcapkit/toolkit/pypcapfile.py', 'TCP_MIN_HEADER_LEN'),
    ('pcapkit/toolkit/pypcapfile.py', 'IPV4_HEADER_LEN'),
    ('pcapkit/toolkit/pypcapfile.py', 'IPV6_HEADER_LEN'),
    ('pcapkit/toolkit/pypcapfile.py', 'AH_HEADER_LEN'),
    ('pcapkit/foundation/reassembly/ip.py', '_MAX_LENGTH'),
    ('pcapkit/foundation/reassembly/ipv6.py', '_IPV6_HDR_LEN'),
    ('pcapkit/foundation/reassembly/ipv6.py', '_IPV6_NEXT_HEADER'),
    ('pcapkit/dumpkit/pcap.py', '_RESOLUTION'),
    ('pcapkit/protocols/misc/pcap/header.py', '_MAGIC_NUM'),
    ('pcapkit/foundation/engines/pcapng.py', 'BLOCK_MINIMUM'),
    ('pcapkit/foundation/engines/pcapng.py', 'BYTE_ORDER_MAGIC'),
)

#: Literals distinctive enough to find by value, mapped to the one file allowed
#: to spell them. ``1_000_000_000`` is also Python's nanoseconds per second, so a
#: division of :func:`time.time_ns` by it is exempt (see :func:`_time_ns_divisor`).
LITERALS = {
    b'\xa1\xb2\x3c\x4d': 'pcapkit/protocols/schema/misc/pcap/header.py',
    b'\xa1\xb2\xc3\xd4': 'pcapkit/protocols/schema/misc/pcap/header.py',
    b'\x4d\x3c\xb2\xa1': 'pcapkit/protocols/schema/misc/pcap/header.py',
    b'\xd4\xc3\xb2\xa1': 'pcapkit/protocols/schema/misc/pcap/header.py',
    b'\x0a\x0d\x0d\x0a': None,
    b'\x1a\x2b\x3c\x4d': None,
    b'\x4d\x3c\x2b\x1a': None,
    0x1A2B3C4D: 'pcapkit/protocols/schema/misc/pcapng.py',
    0x4D3C2B1A: None,
    10 ** 9: 'pcapkit/protocols/schema/misc/pcap/header.py',
    10 ** 6: ('pcapkit/protocols/schema/misc/pcap/header.py', 'pcapkit/protocols/schema/misc/pcapng.py'),
}

#: Each reader module, the home it imports from, and the names it imports.
READERS = (
    ('pcapkit/toolkit/scapy.py', 'pcapkit.protocols.schema.internet.ipv4', 'IPV4_HEADER_LEN'),
    ('pcapkit/toolkit/scapy.py', 'pcapkit.protocols.internet.ipv6', 'IPV6_HEADER_LEN'),
    ('pcapkit/toolkit/scapy.py', 'pcapkit.protocols.schema.transport.tcp', 'TCP_MIN_HEADER_LEN'),
    ('pcapkit/toolkit/scapy.py', 'pcapkit.protocols.schema.transport.tcp', 'TCP_DATA_OFFSET_OCTET'),
    ('pcapkit/toolkit/scapy.py', 'pcapkit.protocols.schema.misc.pcap.header', 'RESOLUTION'),
    ('pcapkit/toolkit/scapy.py', 'pcapkit.protocols.schema.misc.pcap.header', 'RESOLUTION_PLACES'),
    ('pcapkit/toolkit/pcap.py', 'pcapkit.protocols.schema.transport.tcp', 'TCP_MIN_HEADER_LEN'),
    ('pcapkit/toolkit/pcap.py', 'pcapkit.protocols.schema.transport.tcp', 'TCP_DATA_OFFSET_OCTET'),
    ('pcapkit/toolkit/pcapng.py', 'pcapkit.protocols.schema.misc.pcap.header', 'RESOLUTION'),
    ('pcapkit/toolkit/dpkt.py', 'pcapkit.protocols.schema.misc.pcap.header', 'RESOLUTION'),
    ('pcapkit/toolkit/dpkt.py', 'pcapkit.protocols.schema.misc.pcap.header', 'RESOLUTION_PLACES'),
    ('pcapkit/toolkit/pypcapfile.py', 'pcapkit.protocols.schema.misc.pcap.header', 'RESOLUTION'),
    ('pcapkit/foundation/reassembly/ip.py', 'pcapkit.protocols.schema.internet.ipv6', 'IP_MAX_LENGTH'),
    ('pcapkit/foundation/reassembly/ipv6.py', 'pcapkit.protocols.internet.ipv6', 'IPV6_HEADER_LEN'),
    ('pcapkit/foundation/reassembly/ipv6.py', 'pcapkit.protocols.internet.ipv6',
     'IPV6_NEXT_HEADER_OFFSET'),
    ('pcapkit/protocols/internet/ipv6.py', 'pcapkit.protocols.schema.internet.ipv6', 'IP_MAX_LENGTH'),
    ('pcapkit/dumpkit/pcap.py', 'pcapkit.protocols.schema.misc.pcap.header', 'RESOLUTION'),
    ('pcapkit/protocols/misc/pcap/header.py', 'pcapkit.protocols.schema.misc.pcap.header',
     'MAGIC_NUMBER'),
    ('pcapkit/protocols/misc/pcap/frame.py', 'pcapkit.protocols.schema.misc.pcap.header',
     'RESOLUTION'),
    ('pcapkit/protocols/misc/pcapng.py', 'pcapkit.protocols.schema.misc.pcap.header', 'RESOLUTION'),
    ('pcapkit/protocols/misc/pcapng.py', 'pcapkit.protocols.schema.misc.pcapng', 'BLOCK_MINIMUM'),
    ('pcapkit/protocols/misc/pcapng.py', 'pcapkit.protocols.schema.misc.pcapng', 'BYTE_ORDER_MAGIC'),
    ('pcapkit/protocols/misc/pcapng.py', 'pcapkit.protocols.schema.misc.pcapng',
     'DEFAULT_RESOLUTION'),
    ('pcapkit/protocols/misc/pcapng.py', 'pcapkit.protocols.schema.misc.pcapng',
     'GENERIC_BLOCK_MINIMUM'),
    ('pcapkit/foundation/engines/pcap.py', 'pcapkit.protocols.schema.misc.pcap.header',
     'MAGIC_NUMBER'),
    ('pcapkit/foundation/engines/pcapng.py', 'pcapkit.protocols.schema.misc.pcapng',
     'BLOCK_MINIMUM'),
    ('pcapkit/foundation/engines/pcapng.py', 'pcapkit.protocols.schema.misc.pcapng',
     'BYTE_ORDER_MAGIC'),
    ('pcapkit/foundation/engines/pcapng.py', 'pcapkit.protocols.schema.misc.pcapng',
     'GENERIC_BLOCK_MINIMUM'),
    ('pcapkit/foundation/engines/scapy.py', 'pcapkit.protocols.schema.misc.pcap.header',
     'RESOLUTION'),
    ('pcapkit/foundation/engines/scapy.py', 'pcapkit.protocols.schema.misc.pcapng',
     'DEFAULT_RESOLUTION'),
    ('pcapkit/foundation/engines/dpkt.py', 'pcapkit.protocols.schema.misc.pcap.header',
     'RESOLUTION'),
    ('pcapkit/foundation/engines/dpkt.py', 'pcapkit.protocols.schema.misc.pcapng',
     'BYTE_ORDER_MAGIC'),
    ('pcapkit/foundation/engines/dpkt.py', 'pcapkit.protocols.schema.misc.pcapng',
     'DEFAULT_RESOLUTION'),
    ('pcapkit/foundation/engines/dpkt.py', 'pcapkit.protocols.schema.misc.pcapng',
     'GENERIC_BLOCK_MINIMUM'),
    ('pcapkit/foundation/engines/pcap.py', 'pcapkit.protocols.schema.misc.pcap.frame',
     'RECORD_HEADER_LEN'),
    ('pcapkit/foundation/engines/pypcapfile.py', 'pcapkit.protocols.schema.misc.pcap.frame',
     'RECORD_HEADER_LEN'),
    ('pcapkit/foundation/engines/scapy.py', 'pcapkit.protocols.schema.misc.pcap.frame',
     'RECORD_HEADER_LEN'),
    ('pcapkit/protocols/misc/pcap/frame.py', 'pcapkit.protocols.schema.misc.pcap.frame',
     'RECORD_HEADER_LEN'),
    ('pcapkit/protocols/misc/pcap/header.py', 'pcapkit.protocols.schema.misc.pcap.header',
     'GLOBAL_HEADER_LEN'),
    ('pcapkit/protocols/internet/ipv4.py', 'pcapkit.protocols.schema.internet.ipv4', 'IPV4_HEADER_LEN'),
    ('pcapkit/protocols/internet/ah.py', 'pcapkit.protocols.schema.internet.ah', 'AH_HEADER_LEN'),
    ('pcapkit/protocols/transport/tcp.py', 'pcapkit.protocols.schema.transport.tcp',
     'TCP_MIN_HEADER_LEN'),
)

#: Readers that reach a home as a module attribute, ``Module.NAME``, rather than
#: importing the name: the module, the home's module path and the name.
#: :mod:`pcapkit.toolkit.pypcapfile` does so because binding the homed names it
#: reads would re-export them (see :meth:`TestReaders.test_pypcapfile_binds_none`).
ATTRIBUTE_READERS = (
    ('pcapkit/toolkit/pypcapfile.py', 'pcapkit.protocols.schema.internet.ipv4', 'IPV4_HEADER_LEN'),
    ('pcapkit/toolkit/pypcapfile.py', 'pcapkit.protocols.internet.ipv6', 'IPV6_HEADER_LEN'),
    ('pcapkit/toolkit/pypcapfile.py', 'pcapkit.protocols.internet.ipv6', 'IPV6_NEXT_HEADER_OFFSET'),
    ('pcapkit/toolkit/pypcapfile.py', 'pcapkit.protocols.schema.internet.ah', 'AH_HEADER_LEN'),
    ('pcapkit/toolkit/pypcapfile.py', 'pcapkit.protocols.schema.transport.tcp', 'TCP_MIN_HEADER_LEN'),
    ('pcapkit/toolkit/pypcapfile.py', 'pcapkit.protocols.schema.transport.tcp',
     'TCP_DATA_OFFSET_OCTET'),
)

#: The trees :class:`TestNotReinlined` sweeps.
SWEPT = ('pcapkit/protocols', 'pcapkit/foundation', 'pcapkit/toolkit', 'pcapkit/dumpkit')

#: Values the sweep leaves to :meth:`TestOneDefinition.test_literals_at_home`,
#: which finds them anywhere because they are distinctive.
DISTINCTIVE = (10 ** 6, 10 ** 9, 0x1A2B3C4D)

#: Sweep hits of a homed value that are not a copy of it, one expression each:
#: the module, the expression (see :func:`_context`) and why. A hit here is in a
#: module whose own protocol owns a constant of that value, or that reads one.
NOT_A_COPY = {
    ('pcapkit/protocols/application/ssl.py', '_take(32)'):
        "a TLS/DTLS ClientHello/ServerHello Random is 32 octets (:rfc:`9846#section-4.2.2`), "
        'not an Interface Description Block minimum',
    ('pcapkit/protocols/schema/application/dtls.py', 'NumberField(length=6)'):
        "DTLS's 48-bit sequence_number (:rfc:`9147#section-4`), not the IPv6 Next "
        'Header offset',
    ('pcapkit/protocols/schema/application/dtls.py', "{'epoch': (6, 2)}"):
        "the EE bits of a DTLS 1.3 unified header, at bit 6 of its first octet "
        '(:rfc:`9147#section-4.1`), not the IPv6 Next Header offset',
    ('pcapkit/protocols/application/dtls.py', '_CIPHERTEXT_MIN_LENGTH = 16'):
        "the shortest DTLS 1.3 ciphertext, the record-number sample length "
        '(:rfc:`9147#section-4.2.3`), not a pcap record header',
    ('pcapkit/protocols/internet/ipv6.py', "schema.hextet['version'] != 6"):
        'the IP version number, not the Next Header offset',
    ('pcapkit/protocols/internet/ipv6.py', 'self._import_next_layer(version=6)'):
        'the IP version number, not the Next Header offset',
    ('pcapkit/protocols/internet/ipv6.py', "{'version': 6}"):
        'the IP version number, not the Next Header offset',
    ('pcapkit/protocols/schema/internet/ipv6.py', 'ptr + 6'):
        'the end of a Jumbo Payload option (2 octets of header, 4 of value)',
    ('pcapkit/protocols/link/linux_sll1.py', 'return 16'):
        'the fixed length of the LINUX_SLL (v1) header, not the PCAP record header',
    ('pcapkit/protocols/link/linux_sll2.py', 'return 20'):
        'the fixed length of the LINUX_SLL2 header, not the IPv4 or TCP minimum header',
    ('pcapkit/protocols/misc/pcap/frame.py', 'version == 6'):
        'the IP version number, not the decimal places of a resolution',
    ('pcapkit/protocols/misc/pcapng.py', 'version == 6'):
        'the IP version number, not the decimal places of a resolution',
    ('pcapkit/protocols/misc/pcapng.py', 'schema.length != 6'):
        'a MAC address option is 6 octets',
    ('pcapkit/protocols/misc/pcapng.py', 'Schema_IF_MACAddrOption(length=6)'):
        'a MAC address option is 6 octets',
    ('pcapkit/protocols/misc/pcapng.py', 'schema.length != 16'):
        'an IPv6 address option is 16 octets, not a Simple Packet Block',
    ('pcapkit/protocols/misc/pcapng.py', 'Schema_NS_DNSIP6AddrOption(length=16)'):
        'an IPv6 address option is 16 octets, not a Simple Packet Block',
    ('pcapkit/protocols/misc/pcapng.py', '(body + bytes(20))[:20]'):
        'an epb_hash option body padded to its 20-octet SHA-1 digest',
    ('pcapkit/protocols/misc/pcapng.py', 'bytes(20)'):
        'an epb_hash option body padded to its 20-octet SHA-1 digest',
    ('pcapkit/protocols/misc/pcapng.py', '(body + bytes(16))[4:16]'):
        'an epb_hash option body padded to its 16-octet MD5 digest',
    ('pcapkit/protocols/misc/pcapng.py', 'bytes(16)'):
        'an epb_hash option body padded to its 16-octet MD5 digest',
    ('pcapkit/protocols/misc/pcapng.py', '16 + _utf8_length(records)'):
        'an IPv6 name record is 16 octets of address, not a block',
    ('pcapkit/protocols/misc/pcapng.py', 'timestamp_high << 32'):
        'a bit width: the high half of a 64-bit timestamp',
    ('pcapkit/protocols/misc/pcapng.py', 'ts_info >> 32'):
        'a bit width: the high half of a 64-bit timestamp',
    ('pcapkit/protocols/misc/pcapng.py', 'short_address >> 16'):
        'a bit width: the high half of a 32-bit address',
    ('pcapkit/protocols/misc/pcapng.py', 'schema.addr_high << 16'):
        'a bit width: the high half of a 32-bit address',
    ('pcapkit/protocols/schema/misc/pcapng.py', 'BytesField(length=6)'):
        'a MAC address is 6 octets',
    ('pcapkit/protocols/schema/misc/pcapng.py', 'BytesField(length=16)'):
        'an IPv6 address is 16 octets',
    ('pcapkit/protocols/schema/misc/pcapng.py', "pkt['length'] - 16"):
        'an IPv6 name record is 16 octets of address, not a block',
    ('pcapkit/protocols/schema/misc/pcapng.py', 'magic == 12'):
        'the Block Total Length of a 12-octet Section Header Block read where the '
        'Byte-Order Magic belongs, spelled as the octets read to pair with the '
        'byte-swapped 0x0C000000 beside it',
    ('pcapkit/protocols/schema/misc/pcapng.py', 'magic in (BYTE_ORDER_MAGIC, 12)'):
        'the same octets read where the Byte-Order Magic belongs, paired with the '
        'byte-swapped 0x0C000000 beside it, as in the check above',
    ('pcapkit/protocols/schema/misc/pcapng.py', "{'reserved': (12, 12)}"):
        'an epb_flags bit-field: 12 reserved bits from bit 12',
    ('pcapkit/protocols/schema/misc/pcapng.py', "{'crc_error': (24, 1)}"):
        'an epb_flags bit offset, not an Interface Statistics Block',
    ('pcapkit/protocols/schema/misc/pcapng.py', "{'unaligned_error': (28, 1)}"):
        'an epb_flags bit offset, not a Section Header Block',
    ('pcapkit/protocols/schema/misc/pcapng.py', "{'byteorder': (32, 32)}"):
        "a bit-field: a Section Header Block's Byte-Order Magic, the 32 bits after "
        'its Block Total Length, not a Packet Block',
    ('pcapkit/protocols/schema/transport/tcp.py', "pkt['length'] > 12"):
        'an MP_CAPABLE option length, not the Data Offset octet',
    ('pcapkit/protocols/schema/transport/tcp.py', "pkt['length'] > 20"):
        'an MP_CAPABLE option length, not the minimum header length',
    ('pcapkit/protocols/schema/transport/tcp.py', 'BytesField(length=20)'):
        'an MPTCP MP_JOIN SYN/ACK truncated HMAC is 20 octets',
    ('pcapkit/protocols/schema/transport/tcp.py', "pkt['length'] in (20, 22, 28, 30)"):
        'the MP_ADD_ADDR option lengths with an IPv6 address, not the minimum header length',
    ('pcapkit/protocols/schema/transport/tcp.py', "{'reserved': (4, 12)}"):
        'an MPTCP bit-field: 12 reserved bits after the 4-bit subtype, not the Data '
        'Offset octet',
    ('pcapkit/protocols/transport/tcp.py', 'schema.length != 12'):
        'an MPTCP option length, not the Data Offset octet',
    ('pcapkit/protocols/transport/tcp.py', 'schema.length > 12'):
        'an MP_CAPABLE option length, not the Data Offset octet',
    ('pcapkit/protocols/transport/tcp.py', 'schema.length > 20'):
        'a field offset within the MP_CAPABLE option, not the minimum header length',
    ('pcapkit/protocols/transport/tcp.py', 'Schema_MPTCPJoinSYN(length=12)'):
        'an MP_JOIN SYN option is 12 octets',
    ('pcapkit/protocols/transport/tcp.py', 'Schema_MPTCPFallback(length=12)'):
        'an MP_FAIL option is 12 octets',
    ('pcapkit/protocols/transport/tcp.py', 'Schema_MPTCPFastclose(length=12)'):
        'an MP_FASTCLOSE option is 12 octets',
    ('pcapkit/protocols/transport/tcp.py', 'bytes(20)'):
        'an MP_JOIN SYN/ACK HMAC default of 20 octets',
    ('pcapkit/protocols/transport/tcp.py',
     "{20: ModuleDescriptor('pcapkit.protocols.application.ftp_data', 'FTP_DATA')}"):
        'the FTP data port, not the minimum header length',
    ('pcapkit/protocols/transport/tcp.py', 'schema.length not in (4, 12, 20, 22, 24)'):
        'the MP_CAPABLE option lengths, :rfc:`8684#section-3.1`',
    ('pcapkit/protocols/transport/tcp.py', '(4, 12, 20, 22, 24)[present]'):
        'the MP_CAPABLE option lengths, :rfc:`8684#section-3.1`',
    ('pcapkit/protocols/transport/tcp.py', 'schema.length not in (8, 10, 16, 18, 20, 22, 28, 30)'):
        'the MP_ADD_ADDR option lengths, :rfc:`8684#section-3.4.1`',
    ('pcapkit/foundation/engines/dpkt.py', 'pkt.ts_high << 32'):
        'a bit width: the high half of a 64-bit timestamp',
    ('pcapkit/foundation/engines/dpkt.py', 'version == 6'):
        'the IP version number',
    ('pcapkit/foundation/engines/dpkt.py', '{24: ip6}'):
        'the BSD loopback address family of IPv6 on NetBSD and OpenBSD',
    ('pcapkit/foundation/engines/dpkt.py', '{28: ip6}'):
        'the BSD loopback address family of IPv6 on FreeBSD',
    ('pcapkit/foundation/engines/pcap.py', 'head[8:12]'):
        "a record header's incl_len field, octets 8 to 12",
    ('pcapkit/foundation/engines/pcapng.py', 'self._peek(12)'):
        "the first 12 octets of a block -- type, length and a Section Header Block's "
        'Byte-Order Magic -- not the generic block minimum',
    ('pcapkit/foundation/engines/pcapng.py', 'head[8:12]'):
        "the Byte-Order Magic field of a Section Header Block, octets 8 to 12",
    ('pcapkit/foundation/engines/pcapng.py', 'self._peek(16)[12:16]'):
        "a Decryption Secrets Block's Secrets Length field, octets 12 to 16",
    ('pcapkit/foundation/engines/pcapng.py', 'self._peek(16)'):
        "a Decryption Secrets Block up to its Secrets Length, not a block minimum",
    ('pcapkit/foundation/engines/scapy.py', 'len(options) >= 12'):
        'an if_tsoffset option: 4 octets of header and 8 of value',
    ('pcapkit/foundation/engines/scapy.py', 'options[4:12]'):
        'the 8-octet value of an if_tsoffset option',
    ('pcapkit/foundation/reassembly/tcp.py', '1 << 24'):
        'a bit width, not a PCAP global header',
    ('pcapkit/toolkit/dpkt.py', '_fragment(6)'):
        'the IP version number',
    ('pcapkit/toolkit/dpkt.py', 'version == 6'):
        'the IP version number',
    ('pcapkit/toolkit/pcap.py', 'octets[8:12]'):
        "a TCP header's Acknowledgment Number, octets 8 to 12",
    ('pcapkit/toolkit/pypcapfile.py', 'len(raw) == 6'):
        'a MAC address is 6 octets',
    ('pcapkit/toolkit/pypcapfile.py', '{Enum_TransType.IPv6: 6}'):
        'the IP version an IPv6-in-IP tunnel carries, not the Next Header offset',
    ('pcapkit/dumpkit/common.py', 'ord(char) > 65535'):
        'the last code point of the Basic Multilingual Plane, not an IP length',
    ('pcapkit/dumpkit/common.py', 'codepoint > 65535'):
        'above the Basic Multilingual Plane, needs a UTF-16 surrogate pair, not an IP length',
    ('pcapkit/protocols/link/gre.py', 'return 16'):
        "GRE's own longest possible header -- the 4-octet base plus all three optional "
        'extensions at 4 octets each (:rfc:`2784`/:rfc:`2890`) -- not a PCAP record header',
    ('pcapkit/protocols/link/gre.py', '0 <= checksum <= 65535'):
        "the max value of GRE's own 2-octet Checksum field (:rfc:`2784#section-2.5`), "
        'not an IP total length',
    ('pcapkit/protocols/link/gre.py', '0 <= reserved1 <= 65535'):
        "the max value of GRE's own 2-octet Reserved1 field (:rfc:`2784#section-2.6`), "
        'not an IP total length',
    ('pcapkit/protocols/schema/link/gre.py', "{'reserved_2': (4, 9)}"):
        "the 9-bit span bits 4-12 leave of RFC 2784's 12-bit Reserved0 once RFC 2890 "
        'carves ``K``/``S`` out of it (:rfc:`2890#section-2`), not a PCAP-NG resolution-places '
        'table',
}

#: Sweep hits of a homed value in a module whose own protocol owns no constant
#: of that value, nor reads one: the module mapped to the values left there and
#: why. A value not listed still fails, so a copy added later is still caught.
UNRELATED = {
    'pcapkit/protocols/application/http.py': ((6, 9, 12), 'the length of an HTTP/1 version '
                                              'token, and HTTP/2 frame types and flag masks'),
    'pcapkit/protocols/application/httpv2.py': ((6, 9), 'HTTP/2 frame header and setting sizes'),
    'pcapkit/protocols/internet/ah.py': ((20,), "AH's length estimate, its 12-octet fixed part "
                                         'plus a minimal ICV, not the fixed part itself'),
    'pcapkit/protocols/schema/internet/ipv6_option.py': ((16,), 'an MPL Seed-ID of 16 octets'),
    'pcapkit/protocols/schema/application/httpv2.py': ((6, 32),
                                                       'an HTTP/2 setting size and a flag bit'),
    'pcapkit/protocols/application/ospf.py': ((24, 65535), 'OSPF header length and field bounds'),
    'pcapkit/protocols/schema/application/ospf.py': ((24,), 'the OSPF header length'),
    'pcapkit/protocols/internet/esp.py': ((12, 16, 20, 24, 32), 'ESP ICV and key sizes'),
    'pcapkit/protocols/internet/hip.py': ((6, 12, 16, 20, 32, 40, 65535),
                                          'HIP parameter fields and sizes; 65535 bounds the '
                                          'two-octet TLV Length a TRANSACTION_ID or OVERLAY_ID '
                                          'may declare (#2271), as it does in the schema module, '
                                          'and is not an IP total length'),
    'pcapkit/protocols/schema/internet/hip.py': ((12, 16, 20, 65535),
                                                'HIP parameter fields, sizes and bit-fields'),
    'pcapkit/protocols/internet/hopopt.py': ((6, 16, 32), 'HOPOPT option fields, widths and sizes'),
    'pcapkit/protocols/schema/internet/hopopt.py': ((6, 16), 'HOPOPT option field sizes '
                                                   'and bit-fields'),
    'pcapkit/protocols/internet/ipv6_opts.py': ((6, 16, 32),
                                                'IPv6-Opts option fields, widths and sizes'),
    'pcapkit/protocols/schema/internet/ipv6_opts.py': ((6, 16), 'IPv6-Opts option field sizes '
                                                      'and bit-fields'),
    'pcapkit/protocols/internet/ipv6_ext.py': ((6,), 'the IP version number'),
    'pcapkit/protocols/internet/ipv6_route.py': ((6, 16), 'Routing header address sizes'),
    'pcapkit/protocols/schema/internet/ipv6_route.py': ((16, 20), 'an IPv6 address is 16 '
                                                       'octets; a 20-bit reserved bit-field'),
    'pcapkit/protocols/schema/internet/ipv4.py': ((6, 16), 'the ECN and option-function '
                                                'bit-field offsets'),
    'pcapkit/protocols/schema/internet/ipv6.py': ((12, 20), 'the 20-bit Flow Label from bit 12 '
                                                'of the first 32 bits'),
    'pcapkit/protocols/internet/ipv6.py': ((16,), 'a hex base and an IPv6 address size'),
    'pcapkit/protocols/internet/ipv4.py': ((9, 12, 16, 40), 'IPv4 option counts and sizes; '
                                           '40 is the option area maximum, not an IPv6 header'),
    'pcapkit/protocols/internet/ipx.py': ((12,), 'an IPX address is 12 octets'),
    'pcapkit/protocols/schema/internet/ipx.py': ((12,), 'an IPX address is 12 octets'),
    'pcapkit/protocols/internet/mh.py': ((6, 16, 20, 24, 32),
                                         'Mobility Header option fields and sizes'),
    'pcapkit/protocols/schema/internet/mh.py': ((6, 9, 12, 16, 20, 24, 32),
                                                'Mobility Header option fields, sizes and bit-fields'),
    'pcapkit/protocols/link/arp.py': ((6, 9, 16, 28), 'address sizes, InARP operation codes, '
                                      'and the 28-octet IPv4 ARP length'),
    'pcapkit/protocols/link/loopback.py': ((24, 28), 'the BSD loopback address families of IPv6 '
                                           '(NetBSD and OpenBSD 24, FreeBSD 28)'),
    'pcapkit/protocols/link/l2tpv2.py': ((6, 12, 16), 'L2TPv2 header flags, widths and length'),
    'pcapkit/protocols/link/linux_sll1.py': ((65535,), "the max value of LINUX_SLL's own "
                                            '2-octet link_addr_length field, not an IP total '
                                            'length'),
    'pcapkit/protocols/schema/link/ethernet.py': ((6,), 'a MAC address is 6 octets'),
    'pcapkit/protocols/schema/link/l2tp.py': ((6, 12), 'an L2TP header field offset, and the '
                                             'version bit-field'),
    'pcapkit/protocols/schema/link/vlan.py': ((12,), 'the 12-bit VLAN identifier'),
    'pcapkit/protocols/misc/pcapng.py': ((65535,), 'a 16-bit mask'),
    'pcapkit/protocols/schema/misc/pcapng.py': ((9, 65535), 'an epb_flags bit offset, and a '
                                               '16-bit field default'),
    'pcapkit/protocols/transport/sctp.py': ((12, 16, 20), 'SCTP chunk and parameter sizes'),
    'pcapkit/protocols/schema/transport/sctp.py': ((6, 16, 20), 'SCTP chunk and parameter sizes, '
                                                  'and a flag bit'),
    'pcapkit/protocols/transport/tcp.py': ((6, 16, 24, 32, 65535), 'TCP and MPTCP option sizes, '
                                           'and the 16-bit window and MSS defaults'),
    'pcapkit/protocols/schema/transport/tcp.py': ((6, 16, 28), 'TCP and MPTCP option sizes, and '
                                                 'the MP_ADD_ADDR lengths'),
    'pcapkit/toolkit/pyshark.py': ((6, 9, 20, 24, 28), 'Wireshark encapsulation numbers mapped '
                                   'to link types'),
    'pcapkit/foundation/engines/pypcapfile.py': ((12,), 'the Python 3.12 version ceiling of '
                                                 'PyPCAPFile, not a length'),
}

#: Values equal to one of the homes' but meaning something else, so left where
#: they are rather than read from a home: the module, the name and the value.
#: ``0xFFFF_FFFF`` is the largest 32-bit captured length in the Scapy engine,
#: and the mask a PCAP record field is truncated to in the dumper.
DISTINCT = (
    ('pcapkit.foundation.engines.scapy', '_CAPLEN_MAX', 0xFFFF_FFFF),
    ('pcapkit.dumpkit.pcap', '_UINT32_MASK', 0xFFFF_FFFF),
)


def _sources() -> 'list[pathlib.Path]':
    """Every module the rule governs: all of :mod:`pcapkit` but the generated trees."""
    skip = (PACKAGE / 'vendor', PACKAGE / 'const')
    return sorted(path for path in PACKAGE.rglob('*.py')
                  if not any(base in path.parents for base in skip))


def _rel(path: 'pathlib.Path') -> 'str':
    """The path relative to the repository root, with forward slashes."""
    return path.relative_to(ROOT).as_posix()


def _assigned(tree: 'ast.Module') -> 'set[str]':
    """Names assigned at module level, or at the top level of a class body."""
    names = set()  # type: set[str]
    bodies = [tree.body] + [node.body for node in tree.body if isinstance(node, ast.ClassDef)]
    for body in bodies:
        for node in body:
            targets = []  # type: list[ast.expr]
            if isinstance(node, ast.Assign):
                targets = node.targets
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
                targets = [node.target]
            names.update(target.id for target in targets if isinstance(target, ast.Name))
    return names


def _swept_values() -> 'set[int]':
    """Every homed scalar value, a table's values each, less the distinctive ones."""
    values = set()  # type: set[int]
    for _, _, value in HOMES:
        for scalar in (value.values() if isinstance(value, dict) else (value,)):
            if type(scalar) is int and scalar not in DISTINCTIVE:
                values.add(scalar)
    return values


def _segment(text: 'str', node: 'ast.AST') -> 'str':
    """The source of ``node``, on one line."""
    return ' '.join((ast.get_source_segment(text, node) or '').split())


#: Nodes a constant may sit inside without changing what it means: the
#: expression that holds the container names it (see :func:`_context`).
_CONTAINERS = (ast.Tuple, ast.List, ast.Set, ast.Starred, ast.UnaryOp, ast.keyword)

#: Statements with a body, too long to name a constant by.
_COMPOUND = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.For, ast.AsyncFor,
             ast.While, ast.If, ast.With, ast.AsyncWith, ast.Try)


def _parents(tree: 'ast.AST') -> 'dict[int, ast.AST]':
    """``id`` of every node mapped to its parent."""
    return {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def _home_sites(rel: 'str', tree: 'ast.Module') -> 'set[int]':
    """``id`` of every constant in a home's own definition in ``rel``: its value and table."""
    names = {name for module, name, _ in HOMES if module.replace('.', '/') + '.py' == rel}
    sites = set()  # type: set[int]
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
        else:
            continue
        if any(isinstance(target, ast.Name) and target.id in names for target in targets):
            sites.update(id(sub) for sub in ast.walk(node.value))
    return sites


def _default_of(arguments: 'ast.arguments', operand: 'ast.expr') -> 'str':
    """The parameter whose default is ``operand``."""
    positional = [*getattr(arguments, 'posonlyargs', []), *arguments.args]
    pairs = list(zip(positional[len(positional) - len(arguments.defaults):], arguments.defaults))
    pairs += list(zip(arguments.kwonlyargs, arguments.kw_defaults))
    return next(arg.arg for arg, default in pairs if default is operand)


def _context(text: 'str', operand: 'ast.Constant', parents: 'dict[int, ast.AST]') -> 'str':
    """How :data:`NOT_A_COPY` names the expression ``operand`` sits in.

    The constant is named by the nearest node holding it that is not a mere
    container (a tuple, list, set, starred or unary operand, or a keyword) --
    unless that is a statement with a body, when the container names it. A call
    is named by its callee and the one argument, ``f(name=value)``, so that a
    multi-line call keeps a short key; a default by its function and parameter,
    ``def f(name=value)``; a dictionary entry by its pair, ``{key: value}``; a
    subscript or slice bound by the whole subscript; anything else by its source.

    """
    child, node = operand, parents[id(operand)]  # type: ast.AST, ast.AST
    while isinstance(node, _CONTAINERS) and not isinstance(parents.get(id(node)), _COMPOUND):
        child, node = node, parents[id(node)]
    if sys.version_info < (3, 9) and isinstance(node, ast.Index):  # an ast.Index wraps the subscript
        child, node = node, parents[id(node)]  # pragma: no cover
    if isinstance(node, ast.Slice):
        child, node = node, parents[id(node)]
    if isinstance(node, ast.Call):
        if isinstance(child, ast.keyword):
            return f'{_segment(text, node.func)}({child.arg}={operand.value})'
        return f'{_segment(text, node.func)}({operand.value})'
    if isinstance(node, ast.arguments):
        function = parents[id(node)]
        name = getattr(function, 'name', 'lambda')
        return f'def {name}({_default_of(node, child)}={operand.value})'
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values):
            if child is key or child is value:
                return f'{{{_segment(text, key) if key else "**"}: {_segment(text, value)}}}'
    if isinstance(node, (ast.Compare, ast.BinOp)):
        # hex spellings are named by value, as the scan compares them
        return _segment(text, node).replace('0x0000000C', '12').replace('0xFFFF', '65535')
    if isinstance(node, _COMPOUND):
        return _segment(text, child)
    return _segment(text, node)


def _sweep() -> 'list[tuple[str, int, int, str]]':
    """Every homed value in :data:`SWEPT`: module, value, line, expression.

    A value is swept wherever it is spelled -- an operand, a call argument, a
    subscript, a default, a returned value, an element of a tuple or a table,
    a branch of a conditional, or an assignment at any level, which is how a
    renamed copy (``_TCP_HDR = 20``) would read. Only the homes' own
    definitions, their tables included, are not hits.

    """
    values = _swept_values()
    hits = []  # type: list[tuple[str, int, int, str]]
    for tree_root in SWEPT:
        for path in sorted((ROOT / tree_root).rglob('*.py')):
            rel = _rel(path)
            text = path.read_text(encoding='utf-8')
            tree = ast.parse(text)
            parents = _parents(tree)
            sites = _home_sites(rel, tree)
            for node in ast.walk(tree):
                if (isinstance(node, ast.Constant) and type(node.value) is int
                        and node.value in values and id(node) not in sites):
                    hits.append((rel, node.value, node.lineno, _context(text, node, parents)))
    return hits


def _time_ns_divisor(tree: 'ast.Module') -> 'set[int]':
    """``id`` of every constant that divides a :func:`time.time_ns` reading."""
    exempt = set()  # type: set[int]
    for node in ast.walk(tree):
        if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)
                and isinstance(node.right, ast.Constant)
                and any(isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                        and call.func.attr == 'time_ns' for call in ast.walk(node.left))):
            exempt.add(id(node.right))
    return exempt


class TestHomes(unittest.TestCase):
    """Each constant is defined in its home, with its RFC or format value."""

    def test_value(self) -> 'None':
        for module, name, value in HOMES:
            with self.subTest(module=module, name=name):
                home = importlib.import_module(module)
                self.assertTrue(hasattr(home, name), f'{module} defines no {name}')
                self.assertEqual(getattr(home, name), value)

    def test_defined_not_imported(self) -> 'None':
        for module, name, _ in HOMES:
            with self.subTest(module=module, name=name):
                path = ROOT / (module.replace('.', '/') + '.py')
                self.assertIn(name, _assigned(ast.parse(path.read_text(encoding='utf-8'))))


class TestOneDefinition(unittest.TestCase):
    """No module but the home defines the name or spells the literal."""

    def test_no_second_definition(self) -> 'None':
        homes = {name: module.replace('.', '/') + '.py' for module, name, _ in HOMES}
        offenders = []  # type: list[str]
        for path in _sources():
            assigned = _assigned(ast.parse(path.read_text(encoding='utf-8')))
            for name, home in homes.items():
                # NOTE: the engines' ``MAGIC_NUMBER`` is their dispatch contract
                # and is built from the home; the literal check covers it.
                if name == 'MAGIC_NUMBER' and _rel(path).startswith('pcapkit/foundation/engines/'):
                    continue
                if name in assigned and _rel(path) != home:
                    offenders.append(f'{_rel(path)}: {name}')
        self.assertEqual(offenders, [])

    def test_old_names_gone(self) -> 'None':
        for rel, name in OLD_NAMES:
            with self.subTest(module=rel, name=name):
                tree = ast.parse((ROOT / rel).read_text(encoding='utf-8'))
                self.assertNotIn(name, _assigned(tree))

    def test_literals_at_home(self) -> 'None':
        offenders = []  # type: list[str]
        for path in _sources():
            tree = ast.parse(path.read_text(encoding='utf-8'))
            exempt = _time_ns_divisor(tree)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Constant) or isinstance(node.value, bool):
                    continue
                if not isinstance(node.value, (bytes, int)) or node.value not in LITERALS:
                    continue
                allowed = LITERALS[node.value]
                allowed = (allowed,) if isinstance(allowed, str) or allowed is None else allowed
                if _rel(path) not in allowed and id(node) not in exempt:
                    offenders.append(f'{_rel(path)}:{node.lineno}: {node.value!r}')
        self.assertEqual(offenders, [])


class TestReaders(unittest.TestCase):
    """Each reader imports the constant from its home."""

    def test_imports_home(self) -> 'None':
        for rel, module, name in READERS:
            with self.subTest(reader=rel, name=name):
                tree = ast.parse((ROOT / rel).read_text(encoding='utf-8'))
                imported = {alias.name for node in ast.walk(tree)
                            if isinstance(node, ast.ImportFrom) and node.module == module
                            for alias in node.names}
                self.assertIn(name, imported, f'{rel} does not import {name} from {module}')

    def test_imported_name_is_read(self) -> 'None':
        # NOTE: an import left behind by a reader that spelled the value out
        # again would still pass :meth:`test_imports_home`.
        for rel, module, name in READERS:
            with self.subTest(reader=rel, name=name):
                tree = ast.parse((ROOT / rel).read_text(encoding='utf-8'))
                bound = {alias.asname or alias.name for node in ast.walk(tree)
                         if isinstance(node, ast.ImportFrom) and node.module == module
                         for alias in node.names if alias.name == name}
                loads = [node for node in ast.walk(tree) if isinstance(node, ast.Name)
                         and node.id in bound and isinstance(node.ctx, ast.Load)]
                self.assertTrue(loads, f'{rel} never reads {name}')

    def test_attribute_readers(self) -> 'None':
        for rel, module, name in ATTRIBUTE_READERS:
            with self.subTest(reader=rel, name=name):
                tree = ast.parse((ROOT / rel).read_text(encoding='utf-8'))
                package, _, leaf = module.rpartition('.')
                aliases = {alias.asname or alias.name for node in ast.walk(tree)
                           if isinstance(node, ast.ImportFrom) and node.module == package
                           for alias in node.names if alias.name == leaf}
                self.assertTrue(aliases, f'{rel} does not import {module}')
                loads = [node for node in ast.walk(tree) if isinstance(node, ast.Attribute)
                         and node.attr == name and isinstance(node.value, ast.Name)
                         and node.value.id in aliases and isinstance(node.ctx, ast.Load)]
                self.assertTrue(loads, f'{rel} never reads {module}.{name}')

    def test_pypcapfile_binds_none(self) -> 'None':
        # The homed names it reads (#1739): reading them through
        # ``pcapkit.toolkit.pypcapfile`` would be a re-export, which
        # ruling 1 on #1726 rules out, so the module reaches them as
        # module attributes.
        pypcapfile = importlib.import_module('pcapkit.toolkit.pypcapfile')
        for name in ('TCP_MIN_HEADER_LEN', 'IPV4_HEADER_LEN', 'IPV6_HEADER_LEN', 'AH_HEADER_LEN'):
            with self.subTest(name=name):
                self.assertFalse(hasattr(pypcapfile, name))

    def test_engine_tables_gone(self) -> 'None':
        engine = importlib.import_module('pcapkit.foundation.engines.pcapng').PCAPNG
        for name in ('BLOCK_MINIMUM', 'BYTE_ORDER_MAGIC'):
            with self.subTest(name=name):
                self.assertNotIn(name, vars(engine))

    def test_engine_magic_from_home(self) -> 'None':
        pcap = importlib.import_module('pcapkit.foundation.engines.pcap').PCAP
        pcapng = importlib.import_module('pcapkit.foundation.engines.pcapng').PCAPNG
        magic = importlib.import_module('pcapkit.protocols.schema.misc.pcap.header').MAGIC_NUMBER
        self.assertEqual(pcap.MAGIC_NUMBER, tuple(magic))
        self.assertEqual(pcapng.MAGIC_NUMBER, (b'\x0a\x0d\x0d\x0a',))


class TestNotReinlined(unittest.TestCase):
    """No module spells a homed value again where the name belongs."""

    def test_sweep(self) -> 'None':
        offenders = []  # type: list[str]
        seen_copy = set()  # type: set[tuple[str, str]]
        seen_unrelated = set()  # type: set[tuple[str, int]]
        for rel, value, lineno, context in _sweep():
            if (rel, context) in NOT_A_COPY:
                seen_copy.add((rel, context))
            elif value in UNRELATED.get(rel, ((), ''))[0]:
                seen_unrelated.add((rel, value))
            else:
                offenders.append(f'{rel}:{lineno}: {context} (a copy of a homed constant?)')
        self.assertEqual(offenders, [])
        # an entry that no longer matches anything is stale, and would hide a
        # copy that later took its place
        self.assertEqual(sorted(set(NOT_A_COPY) - seen_copy), [])
        listed = {(rel, value) for rel, (values, _) in UNRELATED.items() for value in values}
        self.assertEqual(sorted(listed - seen_unrelated), [])

    def test_every_entry_has_a_reason(self) -> 'None':
        reasons = list(NOT_A_COPY.values()) + [reason for _, reason in UNRELATED.values()]
        self.assertTrue(all(reason.strip() for reason in reasons))

    def test_distinct_values_stay_apart(self) -> 'None':
        homes = {name for _, name, _ in HOMES}
        for module, name, value in DISTINCT:
            with self.subTest(module=module, name=name):
                self.assertEqual(getattr(importlib.import_module(module), name), value)
                self.assertNotIn(name, homes)


if __name__ == '__main__':
    unittest.main()
