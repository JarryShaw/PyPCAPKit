# -*- coding: utf-8 -*-
"""Provision the ``.pcapng`` sample fixtures used by the test suite.

The test suite (``tests/protocols/test_pcapng_regression.py``) reads five
PCAP-NG captures out of ``examples/captures/`` that :file:`.gitignore` deliberately keeps
out of the repository. This module puts them back on any machine, without a
checkout of anything private, by two routes:

* **Downloaded** -- fetched from a public source, with the source URL and the
  SHA-256 of the exact bytes pinned below. The digest is checked after every
  download and a mismatch is a hard error, never a warning. If the network is
  unavailable the download degrades to a synthesised stand-in, and both the
  console output and the return value say so rather than pretending otherwise.
* **Synthesised** -- written byte by byte by :class:`_Blocks` below, with no
  network access whatsoever, from packet payloads carried in the committed
  ``examples/captures/dhcp.pcapng`` fixture. Generation is deterministic: the same input
  tree always produces the same bytes, so a second run is a no-op.

Which fixture comes from where:

=========================== ============= ===================================
Fixture                     Provenance    Exercises
=========================== ============= ===================================
``dhcp_big_endian.pcapng``  downloaded    big-endian section header block
``dhcp_little_endian.pcapng`` synthesised little-endian section header block
``many_interfaces.pcapng``  downloaded    eleven interface description blocks
``test.pcapng``             synthesised   the auxiliary block types
``profile.pcapng``          synthesised   the ``if_*``/``isb_*`` option space
=========================== ============= ===================================

Provenance and licensing of the downloaded captures
---------------------------------------------------

Both downloads come from the Wireshark source tree's ``test/captures``
directory (https://gitlab.com/wireshark/wireshark, mirrored on GitHub), which
is distributed under the GNU GPL v2 or later. They are fetched into ``examples/captures/``,
which :file:`.gitignore` excludes, so this project never redistributes them --
each machine fetches its own copy. ``many_interfaces.pcapng`` does not exist
upstream under that name; upstream ships a three-file ring-buffer set, and the
first member (``many_interfaces.pcapng.1``) is a complete, self-contained
PCAP-NG file, so that is what is fetched and stored under the name the test
expects.

The committed ``examples/captures/dhcp.pcapng`` is byte-identical to upstream's
``test/captures/dhcp.pcapng`` (SHA-256 ``e47f667c...5a1666``), which is where
the synthesised DHCP payloads come from.

Block types deliberately left out
---------------------------------

Two block types that used to raise on spec-conformant input now parse, so they
are absent from these fixtures only because the fixtures have not been extended
to carry them -- not because pcapkit cannot read them:

* **Custom Block** (``0x00000BAD``/``0x40000BAD``) -- **parses now.** Its
  padding was computed as ``(4 - pkt['data'] % 4) % 4``, i.e. on the
  :class:`bytes` object rather than on its length, so any custom block raised
  ``TypeError: not all arguments converted during bytes formatting``. The
  padding field is gone rather than repaired: the block carries no length for
  its custom data, so ``data`` already spans the custom data, its padding *and*
  the block's options, which is as much as a reader that does not own the
  private enterprise number can tell apart (GitHub issue #341).
* **Packet Block** (obsolete, ``0x00000002``) -- **parses now.** Its
  ``interface_id`` and ``drop_count`` were declared ``UInt32Field`` although
  Appendix A of draft-ietf-opsawg-pcapng (Figure 19) packs both into one 32-bit
  word -- which is the layout the ``options`` length's 32-octet overhead already
  assumed. Both are ``UInt16Field`` now, and the reader resolves the link type
  from the block's own ``interface_id`` rather than through the ``linktype``
  property, which needs a ``self._info`` that does not exist yet while the block
  is still being read and so failed with ``AttributeError: 'PCAPNG' object has
  no attribute '_info'`` (GitHub issue #345). The block MUST NOT appear in new
  files, so a fixture carrying one would be documenting the past.

Two further constructs used to be avoided rather than covered, and both are
**fixed** now, so the fixtures carry them as regression cover:

* **``if_IPv6addr``** -- ``IPv6InterfaceField.post_process`` in
  ``pcapkit/corekit/fields/ipaddress.py`` read the trailing prefix-length octet
  as ``int(value[16:])``, i.e. it parsed a raw byte as an ASCII decimal string,
  so a ``/64`` prefix raised ``ValueError`` and only the ten lengths 48-57
  parsed at all -- each of them to the wrong value (GitHub issue #346). Every
  interface built by :func:`_interface_profile` now carries the option, using
  the ``/64`` address from section 4.2 of the format specification.
* **Simple Packet Block** in a multi-interface section -- the engine raised
  ``FormatError: PCAP-NG: [SPB] invalid section with 2 interfaces`` for any
  simple packet block in a section declaring more than one interface, which the
  format specification (section 4.4 of draft-ietf-opsawg-pcapng) permits: it
  says only that such a block then refers to the interface described by the
  first Interface Description Block, not that it is invalid. The check is for
  *zero* interfaces now (GitHub issue #347), so ``test.pcapng`` carries its
  simple packet block in the two-interface first section, which is the case
  that used to be rejected.

Three further defects were exercised on purpose, because they warned rather than
raised, and a fixture that covers the code path is what will catch a future
crash there. All three were option-area sizing errors in
``pcapkit/protocols/schema/misc/pcapng.py``, all three were confirmed by
bisecting one block type at a time, and all three are now **fixed** -- so the
fixtures that reached them are regression cover rather than known-bad input:

* **Interface Statistics Block** -- ``options`` was sized ``length - 20`` though
  the block's fixed fields occupy 24 octets, so the option area over-ran into
  the trailing block length. Unconditional: an explicit ``opt_endofopt`` did not
  save it, because the field still consumed its declared width. Symptom, on
  every capture containing one including the downloaded
  ``many_interfaces.pcapng``: ``packet length < 0: -8`` and ``[Block 5] block
  length mismatch: N != 0``. Now ``length - 24`` (GitHub issue #342).
* **Name Resolution Block options** -- ``options`` was sized
  ``__option_padding__ - 4``, which over-ran whenever ``ns_*`` options were
  present. Symptom: ``[Block 4] block length mismatch: 60 != 314``. Not a wrong
  constant: ``Schema.unpack`` advances the file by each field's *declared*
  length, so the octets the option field was trying to size had already been
  consumed by ``records``. An ``OptionField`` now hands the remainder it did not
  parse back to the file -- the rewind ``ForwardMatchField`` already did -- which
  is what makes ``__option_padding__`` mean the same thing to the field that
  reads it as to the field that reported it, and the NRB's ``options`` is sized
  ``__option_padding__`` (GitHub issue #344). ``ns_dnsname`` also gained the
  ``PaddingField`` its ``if_name`` and ``if_description`` siblings have, without
  which an unaligned DNS name under-read by its own padding.
* **Name Resolution Block IPv6 records** -- ``resol`` was sized ``length - 4``,
  copied from the IPv4 record where the address is four octets wide; an IPv6
  address is sixteen, so the name field over-read by twelve and swallowed the
  record terminator and the block's options. Symptom: ``packet length <
  0: -29273``, and the block's ``ns_*`` options vanished. Now ``length - 16``
  (GitHub issue #343).

``many_interfaces.pcapng`` and ``profile.pcapng`` now extract with neither a
block length mismatch nor a negative packet length; before these fixes each
reported one of each.

Every fixture here was checked against an independent PCAP-NG implementation
(scapy's ``PcapNgReader``) as well as against pcapkit, and against a structural
walk asserting that each block's total length is 4-octet aligned, repeated
identically at both ends, and that the block chain covers the file exactly. So
the complaints above were pcapkit's readings, not malformed fixtures.

One complaint is expected rather than a defect: ``test.pcapng`` carries a
deliberately truncated packet (``captured_len`` below ``original_len``, to
exercise snapshot-length handling) and dissecting it reports ``packet length <
0: -2``, which is simply what a snapped frame looks like to a dissector.

Usage
-----

.. code-block:: shell

   python examples/generators/pcapng.py           # write into examples/captures
   python examples/generators/pcapng.py /tmp/fix   # write somewhere else

"""

from __future__ import annotations

import hashlib
import logging
import pathlib
import struct
import sys
import urllib.error
import urllib.request
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from typing import Callable, Optional

__all__ = ['generate']

#: Repository root, i.e. the grandparent of the directory holding this script.
ROOT = pathlib.Path(__file__).resolve().parents[2]
#: Default destination directory for the fixtures.
SAMPLE_DIR = ROOT / 'examples' / 'captures'
#: Committed fixture the synthesised DHCP payloads are lifted from.
DHCP_SOURCE = SAMPLE_DIR / 'dhcp.pcapng'

#: Upstream directory the downloaded captures come from.
WIRESHARK_CAPTURES = ('https://raw.githubusercontent.com/wireshark/wireshark/'
                      'master/test/captures/')

#: Timeout, in seconds, for a single download attempt.
TIMEOUT = 30

#: Fixed base timestamp (2017-07-14T02:40:00Z) so generation is reproducible.
BASE_SECONDS = 1_500_000_000

# Block type numbers, from the PCAP-NG specification.
BLOCK_SHB = 0x0A0D_0D0A
BLOCK_IDB = 0x0000_0001
BLOCK_SPB = 0x0000_0003
BLOCK_NRB = 0x0000_0004
BLOCK_ISB = 0x0000_0005
BLOCK_EPB = 0x0000_0006
BLOCK_JOURNAL = 0x0000_0009
BLOCK_DSB = 0x0000_000A

#: Byte order magic, written in the section's own byte order.
BYTEORDER_MAGIC = 0x1A2B_3C4D

# Option codes. The numbers repeat across namespaces on purpose: the spec scopes
# them to the block they appear in.
OPT_ENDOFOPT = 0
OPT_COMMENT = 1
SHB_HARDWARE, SHB_OS, SHB_USERAPPL = 2, 3, 4
(IF_NAME, IF_DESCRIPTION, IF_IPV4ADDR, IF_IPV6ADDR, IF_MACADDR, IF_EUIADDR,
 IF_SPEED, IF_TSRESOL, IF_TZONE, IF_FILTER, IF_OS, IF_FCSLEN, IF_TSOFFSET,
 IF_HARDWARE, IF_TXSPEED, IF_RXSPEED) = range(2, 18)
(EPB_FLAGS, EPB_HASH, EPB_DROPCOUNT, EPB_PACKETID, EPB_QUEUE,
 EPB_VERDICT) = range(2, 8)
NS_DNSNAME, NS_DNSIP4ADDR, NS_DNSIP6ADDR = 2, 3, 4
(ISB_STARTTIME, ISB_ENDTIME, ISB_IFRECV, ISB_IFDROP, ISB_FILTERACCEPT,
 ISB_OSDROP, ISB_USRDELIV) = range(2, 9)

#: Name resolution record types.
NRB_RECORD_END, NRB_RECORD_IPV4, NRB_RECORD_IPV6 = 0, 1, 2

#: ``TLSK``, the decryption secrets type for a TLS key log.
SECRETS_TLS_KEY_LOG = 0x544C_534B

#: Link types used by the synthesised fixtures.
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101


class _Blocks:
    """Byte-order aware PCAP-NG block writer.

    Every block is emitted with its body padded to a 4-octet boundary and its
    total length repeated at both ends, as the specification requires, so the
    fixtures are correct by construction rather than by inspection.

    Args:
        endian: :mod:`struct` byte order character, ``'<'`` or ``'>'``.

    """

    def __init__(self, endian: 'str' = '<') -> 'None':
        if endian not in ('<', '>'):
            raise ValueError(f'byte order must be < or >, not {endian!r}')
        self.endian = endian

    @property
    def name(self) -> 'str':
        """Human-readable byte order, for console output."""
        return 'little-endian' if self.endian == '<' else 'big-endian'

    def pack(self, fmt: 'str', *args: 'int') -> 'bytes':
        """Pack ``args`` in this writer's byte order."""
        return struct.pack(self.endian + fmt, *args)

    @staticmethod
    def pad(data: 'bytes') -> 'bytes':
        """Pad ``data`` with NULs up to a 4-octet boundary."""
        return data + b'\x00' * (-len(data) % 4)

    def option(self, code: 'int', value: 'bytes') -> 'bytes':
        """Encode one option as code, length, value, padding."""
        return self.pack('HH', code, len(value)) + self.pad(value)

    def options(self, items: 'list[tuple[int, bytes]]') -> 'bytes':
        """Encode an option list, terminated by ``opt_endofopt``.

        An empty list encodes to nothing at all: the specification makes the
        whole option area optional, and a bare ``opt_endofopt`` is not the same
        thing as its absence.

        """
        if not items:
            return b''
        return b''.join(self.option(code, value) for code, value in items) \
            + self.pack('HH', OPT_ENDOFOPT, 0)

    def block(self, block_type: 'int', body: 'bytes') -> 'bytes':
        """Wrap ``body`` in a block header and trailer."""
        body = self.pad(body)
        total = len(body) + 12
        return self.pack('II', block_type, total) + body + self.pack('I', total)

    # -- individual block types ------------------------------------------------

    def shb(self, options: 'Optional[list[tuple[int, bytes]]]' = None) -> 'bytes':
        """Section Header Block.

        The byte order magic is written in this writer's byte order, which is
        exactly how a reader is meant to discover the section's byte order.

        """
        body = self.pack('IHHq', BYTEORDER_MAGIC, 1, 0, -1)
        return self.block(BLOCK_SHB, body + self.options(options or []))

    def idb(self, linktype: 'int' = LINKTYPE_ETHERNET, snaplen: 'int' = 0x0004_0000,
            options: 'Optional[list[tuple[int, bytes]]]' = None) -> 'bytes':
        """Interface Description Block."""
        body = self.pack('HHI', linktype, 0, snaplen)
        return self.block(BLOCK_IDB, body + self.options(options or []))

    def epb(self, interface: 'int', timestamp: 'int', data: 'bytes',
            options: 'Optional[list[tuple[int, bytes]]]' = None,
            original_len: 'Optional[int]' = None) -> 'bytes':
        """Enhanced Packet Block.

        Args:
            interface: Index of the interface description block it belongs to.
            timestamp: 64-bit timestamp, split high word first.
            data: Captured packet bytes.
            options: ``epb_*`` options, if any.
            original_len: On-the-wire length, when the packet was truncated.

        """
        body = self.pack('IIIII', interface, timestamp >> 32, timestamp & 0xFFFF_FFFF,
                         len(data), len(data) if original_len is None else original_len)
        return self.block(BLOCK_EPB, body + self.pad(data) + self.options(options or []))

    def spb(self, data: 'bytes', original_len: 'Optional[int]' = None) -> 'bytes':
        """Simple Packet Block."""
        body = self.pack('I', len(data) if original_len is None else original_len)
        return self.block(BLOCK_SPB, body + self.pad(data))

    def nrb(self, records: 'list[tuple[int, bytes]]',
            options: 'Optional[list[tuple[int, bytes]]]' = None) -> 'bytes':
        """Name Resolution Block.

        The record list is terminated by an ``nrb_record_end`` record, which the
        specification requires even when the option area is empty.

        """
        body = b''.join(self.pack('HH', kind, len(value)) + self.pad(value)
                        for kind, value in records)
        body += self.pack('HH', NRB_RECORD_END, 0)
        return self.block(BLOCK_NRB, body + self.options(options or []))

    def isb(self, interface: 'int', timestamp: 'int',
            options: 'Optional[list[tuple[int, bytes]]]' = None) -> 'bytes':
        """Interface Statistics Block."""
        body = self.pack('III', interface, timestamp >> 32, timestamp & 0xFFFF_FFFF)
        return self.block(BLOCK_ISB, body + self.options(options or []))

    def dsb(self, secrets_type: 'int', secrets: 'bytes',
            options: 'Optional[list[tuple[int, bytes]]]' = None) -> 'bytes':
        """Decryption Secrets Block."""
        body = self.pack('II', secrets_type, len(secrets)) + self.pad(secrets)
        return self.block(BLOCK_DSB, body + self.options(options or []))

    def journal(self, entry: 'bytes') -> 'bytes':
        """:manpage:`systemd(1)` Journal Export Block.

        ``entry`` is padded out to a 4-octet boundary by the caller rather than
        here -- see :func:`_journal_entry` for why that distinction matters.

        """
        return self.block(BLOCK_JOURNAL, entry)


def _timestamp(offset_us: 'int') -> 'int':
    """Microsecond timestamp ``offset_us`` after :data:`BASE_SECONDS`."""
    return BASE_SECONDS * 1_000_000 + offset_us


def _read_epb_packets(path: 'pathlib.Path') -> 'list[bytes]':
    """Extract the enhanced packet block payloads from a PCAP-NG file.

    A deliberately minimal reader: it walks the block chain, tracks the byte
    order declared by each section header, and returns the captured bytes of
    every enhanced packet block. It exists so the synthesised fixtures can carry
    real DHCP traffic instead of hand-rolled filler.

    Args:
        path: PCAP-NG file to read.

    Returns:
        Captured packet payloads, in file order.

    Raises:
        RuntimeError: If ``path`` is missing or is not a PCAP-NG file.

    """
    if not path.is_file():
        raise RuntimeError(f'{path} is missing; it is a committed fixture and '
                           'the synthesised captures are derived from it')

    data = path.read_bytes()
    packets = []  # type: list[bytes]
    endian, offset = '<', 0

    while offset + 12 <= len(data):
        block_type, = struct.unpack_from(endian + 'I', data, offset)
        if block_type == BLOCK_SHB:
            magic, = struct.unpack_from('<I', data, offset + 8)
            endian = '<' if magic == BYTEORDER_MAGIC else '>'
        total, = struct.unpack_from(endian + 'I', data, offset + 4)
        if total < 12 or offset + total > len(data):
            raise RuntimeError(f'{path}: bad block length {total} at offset {offset}')

        if block_type == BLOCK_EPB:
            captured, = struct.unpack_from(endian + 'I', data, offset + 20)
            packets.append(data[offset + 28:offset + 28 + captured])
        offset += total

    if not packets:
        raise RuntimeError(f'{path}: no enhanced packet blocks found')
    return packets


def _journal_entry(message: 'str', realtime_us: 'int') -> 'bytes':
    """Build a :manpage:`systemd(1)` journal export entry of 4-octet length.

    The block body is padded to a 4-octet boundary like every other PCAP-NG
    block, but pcapkit hands the padding to its journal-entry parser along with
    the entry itself, and the parser then reads the NULs as the start of a
    binary field and raises ``struct.error: unpack requires a buffer of 8
    bytes``. Choosing a message whose entry is already aligned means no padding
    is added, which the specification allows and which keeps the fixture
    parseable. The underlying defect is
    ``pcapkit/protocols/schema/misc/pcapng.py:1376`` splitting ``self.entry``
    without first stripping the block padding.

    """
    while True:
        entry = (f'__REALTIME_TIMESTAMP={realtime_us}\n'
                 f'_TRANSPORT=journal\n'
                 f'PRIORITY=6\n'
                 f'MESSAGE={message}\n'
                 f'\n').encode('utf-8')
        if len(entry) % 4 == 0:
            return entry
        message += '.'


def _tls_key_log() -> 'bytes':
    """A synthetic, deterministic TLS key log for the decryption secrets block.

    The values are counted-up filler, not captured key material -- nothing here
    decrypts anything.

    """
    client_random = bytes(range(0x20, 0x40)).hex()
    secret = bytes(range(0x40, 0x70)).hex()
    return f'CLIENT_RANDOM {client_random} {secret}\n'.encode('ascii')


def _timestamp_options(writer: '_Blocks',
                       resolution: 'int' = 6) -> 'list[tuple[int, bytes]]':
    """The three timestamp options every synthesised interface carries.

    pcapkit looks ``if_tsresol``, ``if_tzone`` and ``if_tsoffset`` up on the
    owning interface for each packet block and logs a ``MissingKeyError`` for
    each one that is absent -- harmless, but it buries the interesting output
    under three lines per packet. Declaring them explicitly keeps the fixtures
    quiet as well as complete.

    Args:
        writer: Writer whose byte order the option values are packed in.
        resolution: ``if_tsresol`` exponent, 6 for microseconds, 9 for
            nanoseconds.

    """
    return [
        (IF_TSRESOL, bytes([resolution])),
        (IF_TZONE, writer.pack('i', 0)),
        (IF_TSOFFSET, writer.pack('q', 0)),
    ]


def _interface_profile(writer: '_Blocks', name: 'str', description: 'str',
                       address: 'str', mac: 'bytes',
                       resolution: 'int' = 6) -> 'list[tuple[int, bytes]]':
    """The full set of ``if_*`` options pcapkit can parse for one interface.

    ``if_IPv6addr`` used to be the one omission, because pcapkit raised on it
    rather than because it did not belong here; it is included now that the
    prefix-length octet is read correctly -- see the module docstring.

    Args:
        writer: Writer whose byte order the option values are packed in.
        name: ``if_name`` value.
        description: ``if_description`` value.
        address: Dotted-quad IPv4 address for ``if_IPv4addr``.
        mac: Six-octet hardware address for ``if_MACaddr``.
        resolution: ``if_tsresol`` exponent.

    """
    octets = bytes(int(part) for part in address.split('.'))
    return [
        (OPT_COMMENT, f'synthetic interface {name}'.encode('utf-8')),
        (IF_NAME, name.encode('utf-8')),
        (IF_DESCRIPTION, description.encode('utf-8')),
        (IF_IPV4ADDR, octets + bytes([255, 255, 255, 0])),
        # The address from section 4.2 of draft-ietf-opsawg-pcapng, whose /64
        # prefix is the case that used to raise: the trailing octet is 0x40,
        # which read as an ASCII decimal string is the character ``@``.
        (IF_IPV6ADDR, bytes.fromhex('20010db885a308d313198a2e03707344') + bytes([64])),
        (IF_MACADDR, mac),
        (IF_EUIADDR, mac[:3] + b'\xff\xfe' + mac[3:]),
        (IF_SPEED, writer.pack('Q', 1_000_000_000)),
        (IF_FILTER, b'\x00udp port 67 or udp port 68'),
        (IF_OS, b'synthetic capture host'),
        (IF_FCSLEN, b'\x04'),
        (IF_HARDWARE, b'PyPCAPKit synthetic adapter'),
        (IF_TXSPEED, writer.pack('Q', 1_000_000_000)),
        (IF_RXSPEED, writer.pack('Q', 1_000_000_000)),
    ] + _timestamp_options(writer, resolution)


def _statistics(writer: '_Blocks', interface: 'int', received: 'int', dropped: 'int',
                start_us: 'int', end_us: 'int') -> 'list[tuple[int, bytes]]':
    """The full set of ``isb_*`` options for one interface statistics block.

    The list is terminated by :meth:`_Blocks.options`, which matters here:
    pcapkit sizes an interface statistics block's option area four octets too
    generously, and only the explicit ``opt_endofopt`` stops it reading the
    trailing block length as an option.

    """
    def split(value: 'int') -> 'bytes':
        return writer.pack('II', value >> 32, value & 0xFFFF_FFFF)

    return [
        (OPT_COMMENT, f'statistics for interface {interface}'.encode('utf-8')),
        (ISB_STARTTIME, split(start_us)),
        (ISB_ENDTIME, split(end_us)),
        (ISB_IFRECV, writer.pack('Q', received)),
        (ISB_IFDROP, writer.pack('Q', dropped)),
        (ISB_FILTERACCEPT, writer.pack('Q', received)),
        (ISB_OSDROP, writer.pack('Q', 0)),
        (ISB_USRDELIV, writer.pack('Q', received - dropped)),
    ]


def _packet_options(writer: '_Blocks', index: 'int') -> 'list[tuple[int, bytes]]':
    """The full set of ``epb_*`` options for one packet."""
    return [
        (OPT_COMMENT, f'synthetic frame {index}'.encode('utf-8')),
        (EPB_FLAGS, writer.pack('I', 0b01 if index % 2 == 0 else 0b10)),
        (EPB_HASH, bytes([2]) + writer.pack('I', 0x0BAD_F00D ^ index)),
        (EPB_DROPCOUNT, writer.pack('Q', 0)),
        (EPB_PACKETID, writer.pack('Q', index)),
        (EPB_QUEUE, writer.pack('I', index % 4)),
        (EPB_VERDICT, bytes([0]) + writer.pack('Q', 1)),
    ]


def build_dhcp(endian: 'str') -> 'bytes':
    """Build a DHCP capture with a section header of the given byte order.

    Every multi-octet field in the file -- block types, lengths, option codes,
    timestamps -- is written in ``endian``, so the fixture genuinely exercises
    the byte order it is named for rather than only flipping the magic number.

    Args:
        endian: ``'<'`` for little-endian, ``'>'`` for big-endian.

    """
    writer = _Blocks(endian)
    packets = _read_epb_packets(DHCP_SOURCE)

    blocks = [writer.shb([
        (OPT_COMMENT, f'DHCP exchange in a {writer.name} section'.encode('utf-8')),
        (SHB_HARDWARE, b'synthetic'),
        (SHB_OS, b'synthetic capture host'),
        (SHB_USERAPPL, b'examples/generators/pcapng.py'),
    ])]
    blocks.append(writer.idb(LINKTYPE_ETHERNET, 0x0004_0000, [
        (IF_NAME, b'eth0'),
        (IF_DESCRIPTION, f'{writer.name} DHCP capture'.encode('utf-8')),
        (IF_OS, b'synthetic capture host'),
    ] + _timestamp_options(writer)))

    for index, packet in enumerate(packets):
        blocks.append(writer.epb(0, _timestamp(index * 1_000_000), packet, [
            (EPB_FLAGS, writer.pack('I', 0b01 if index % 2 == 0 else 0b10)),
        ]))
    return b''.join(blocks)


def build_test() -> 'bytes':
    """Build a capture carrying every auxiliary block type pcapkit accepts.

    Two sections, so the section-scoped interface table is exercised too:

    1. an Ethernet and a raw-IPv4 interface, three packets between them --
       including one truncated -- a simple packet block, which belongs here
       precisely because the section declares two interfaces, then a name
       resolution block, an interface statistics block, a decryption secrets
       block and a journal export block;
    2. a second section header with its own interface, which must not inherit
       anything from the first, and one packet.

    """
    writer = _Blocks('<')
    packets = _read_epb_packets(DHCP_SOURCE)

    blocks = [writer.shb([
        (OPT_COMMENT, b'auxiliary PCAP-NG block types, section 1 of 2'),
        (SHB_HARDWARE, b'synthetic'),
        (SHB_OS, b'synthetic capture host'),
        (SHB_USERAPPL, b'examples/generators/pcapng.py'),
    ])]
    blocks.append(writer.idb(LINKTYPE_ETHERNET, 0x0004_0000,
                             _interface_profile(writer, 'eth0', 'primary Ethernet interface',
                                                '10.0.0.1', b'\x02\x00\x00\x00\x00\x01')))
    blocks.append(writer.idb(LINKTYPE_RAW, 0x0000_FFFF, [
        (IF_NAME, b'raw0'),
        (IF_DESCRIPTION, b'raw IPv4 interface, nanosecond timestamps'),
    ] + _timestamp_options(writer, resolution=9)))

    # A packet on each interface, the first with the full option set.
    blocks.append(writer.epb(0, _timestamp(0), packets[0], _packet_options(writer, 0)))
    blocks.append(writer.epb(1, _timestamp(1_000), packets[1][14:]))

    # A truncated packet, so snaplen handling is exercised as well.
    blocks.append(writer.epb(0, _timestamp(2_000), packets[2][:32],
                             original_len=len(packets[2])))

    # The simple packet block sits in this section, which declares two
    # interfaces, because that is the shape the engine used to reject: the
    # format spec says such a block refers to the first interface description
    # block, not that it is invalid (GitHub issue #347).
    blocks.append(writer.spb(packets[3]))

    # Name resolution. The IPv6 record is included knowing pcapkit mis-sizes
    # it -- covering the path is what catches a future crash there.
    blocks.append(writer.nrb([
        (NRB_RECORD_IPV4, bytes([10, 0, 0, 1]) + b'gateway.example\x00'),
        (NRB_RECORD_IPV4, bytes([10, 0, 0, 2]) + b'client.example\x00alias.example\x00'),
        (NRB_RECORD_IPV6, bytes.fromhex('20010db8000000000000000000000001')
         + b'v6.example\x00'),
    ], [
        (NS_DNSNAME, b'resolver.example'),
        (NS_DNSIP4ADDR, bytes([10, 0, 0, 53])),
        (NS_DNSIP6ADDR, bytes.fromhex('20010db8000000000000000000000035')),
    ]))

    blocks.append(writer.isb(0, _timestamp(3_000),
                             _statistics(writer, 0, received=4, dropped=1,
                                         start_us=_timestamp(0),
                                         end_us=_timestamp(3_000))))
    blocks.append(writer.dsb(SECRETS_TLS_KEY_LOG, _tls_key_log(),
                             [(OPT_COMMENT, b'synthetic TLS key log, decrypts nothing')]))
    blocks.append(writer.journal(_journal_entry('synthetic journal entry',
                                                _timestamp(4_000))))

    # Second section, with its own interface table.
    blocks.append(writer.shb([
        (OPT_COMMENT, b'auxiliary PCAP-NG block types, section 2 of 2'),
        (SHB_USERAPPL, b'examples/generators/pcapng.py'),
    ]))
    blocks.append(writer.idb(LINKTYPE_ETHERNET, 0x0004_0000, [
        (IF_NAME, b'eth1'),
        (IF_DESCRIPTION, b'interface local to the second section'),
    ] + _timestamp_options(writer)))
    blocks.append(writer.epb(0, _timestamp(5_000), packets[0],
                             [(OPT_COMMENT, b'first packet of the second section')]))
    return b''.join(blocks)


def build_many_interfaces() -> 'bytes':
    """Build a capture with eight interface description blocks.

    The offline stand-in for the downloaded Wireshark capture. Packets are dealt
    round-robin across the interfaces so every interface index is referenced by
    at least one packet block, and each interface gets its own statistics block.

    """
    writer = _Blocks('<')
    packets = _read_epb_packets(DHCP_SOURCE)

    interfaces = [
        ('eth0', 'primary Ethernet interface', LINKTYPE_ETHERNET),
        ('eth1', 'secondary Ethernet interface', LINKTYPE_ETHERNET),
        ('eth2', 'tertiary Ethernet interface', LINKTYPE_ETHERNET),
        ('bond0', 'bonded Ethernet interface', LINKTYPE_ETHERNET),
        ('br0', 'bridged Ethernet interface', LINKTYPE_ETHERNET),
        ('tun0', 'raw IPv4 tunnel interface', LINKTYPE_RAW),
        ('tun1', 'second raw IPv4 tunnel interface', LINKTYPE_RAW),
        ('lo', 'loopback interface', LINKTYPE_ETHERNET),
    ]

    blocks = [writer.shb([
        (OPT_COMMENT, f'{len(interfaces)} interfaces in one section'.encode('utf-8')),
        (SHB_HARDWARE, b'synthetic'),
        (SHB_OS, b'synthetic capture host'),
        (SHB_USERAPPL, b'examples/generators/pcapng.py'),
    ])]
    for index, (name, description, linktype) in enumerate(interfaces):
        blocks.append(writer.idb(linktype, 0x0004_0000, [
            (IF_NAME, name.encode('utf-8')),
            (IF_DESCRIPTION, description.encode('utf-8')),
            (IF_IPV4ADDR, bytes([10, 0, index, 1]) + bytes([255, 255, 255, 0])),
            (IF_MACADDR, b'\x02\x00\x00\x00\x00' + bytes([index + 1])),
            (IF_SPEED, writer.pack('Q', 1_000_000_000)),
        ] + _timestamp_options(writer)))

    counts = [0] * len(interfaces)
    for index in range(len(interfaces) * 3):
        interface = index % len(interfaces)
        packet = packets[index % len(packets)]
        # A raw IPv4 interface carries the frame without its Ethernet header.
        if interfaces[interface][2] == LINKTYPE_RAW:
            packet = packet[14:]
        counts[interface] += 1
        blocks.append(writer.epb(interface, _timestamp(index * 1_000), packet, [
            (EPB_FLAGS, writer.pack('I', 0b01 if index % 2 == 0 else 0b10)),
            (EPB_PACKETID, writer.pack('Q', index)),
        ]))

    blocks.append(writer.nrb([
        (NRB_RECORD_IPV4, bytes([10, 0, 0, 1]) + b'gateway.example\x00'),
    ]))
    for index, received in enumerate(counts):
        blocks.append(writer.isb(index, _timestamp(100_000),
                                 _statistics(writer, index, received=received, dropped=0,
                                             start_us=_timestamp(0),
                                             end_us=_timestamp(100_000))))
    return b''.join(blocks)


def build_profile() -> 'bytes':
    """Build a capture profiling two interfaces in depth.

    Where ``test.pcapng`` goes wide over block types, this one goes deep over
    the option space that describes an interface and its counters: one interface
    carrying every ``if_*`` option pcapkit can parse, a second at nanosecond
    timestamp resolution, forty packets between them each with the full
    ``epb_*`` option set, and a statistics block per interface carrying every
    ``isb_*`` counter.

    """
    writer = _Blocks('<')
    packets = _read_epb_packets(DHCP_SOURCE)

    blocks = [writer.shb([
        (OPT_COMMENT, b'interface profile and statistics'),
        (SHB_HARDWARE, b'synthetic'),
        (SHB_OS, b'synthetic capture host'),
        (SHB_USERAPPL, b'examples/generators/pcapng.py'),
    ])]
    blocks.append(writer.idb(LINKTYPE_ETHERNET, 0x0004_0000,
                             _interface_profile(writer, 'eth0',
                                                'fully described Ethernet interface',
                                                '10.0.0.1', b'\x02\x00\x00\x00\x00\x01')))
    blocks.append(writer.idb(LINKTYPE_ETHERNET, 0x0000_FFFF,
                             _interface_profile(writer, 'eth1',
                                                'nanosecond resolution interface',
                                                '10.0.1.1', b'\x02\x00\x00\x00\x00\x02',
                                                resolution=9)))

    total = 40
    counts = [0, 0]
    for index in range(total):
        interface = index % 2
        counts[interface] += 1
        blocks.append(writer.epb(interface, _timestamp(index * 500),
                                 packets[index % len(packets)],
                                 _packet_options(writer, index)))

    for interface, received in enumerate(counts):
        blocks.append(writer.isb(interface, _timestamp(total * 500),
                                 _statistics(writer, interface, received=received,
                                             dropped=interface,
                                             start_us=_timestamp(0),
                                             end_us=_timestamp(total * 500))))
    return b''.join(blocks)


class _Fixture(NamedTuple):
    """One sample fixture, and where its bytes come from."""

    #: File name, as the test suite spells it.
    name: 'str'
    #: What PCAP-NG feature the fixture is there to exercise.
    feature: 'str'
    #: Offline builder, used when there is no URL or the download fails.
    build: 'Callable[[], bytes]'
    #: Public source URL, if the capture exists upstream.
    url: 'Optional[str]' = None
    #: SHA-256 of the exact bytes ``url`` is expected to serve.
    sha256: 'Optional[str]' = None


#: The five fixtures ``tests/protocols/test_pcapng_regression.py`` needs.
FIXTURES = (
    _Fixture(
        name='dhcp_big_endian.pcapng',
        feature='big-endian section header block',
        build=lambda: build_dhcp('>'),
        url=WIRESHARK_CAPTURES + 'dhcp_big_endian.pcapng',
        sha256='d9706606fc3febb9740897d85818bd06edc76dc7538ea13d8a9131a988376dfb',
    ),
    _Fixture(
        name='dhcp_little_endian.pcapng',
        feature='little-endian section header block',
        build=lambda: build_dhcp('<'),
    ),
    _Fixture(
        name='many_interfaces.pcapng',
        feature='many interface description blocks in one section',
        build=build_many_interfaces,
        url=WIRESHARK_CAPTURES + 'many_interfaces.pcapng.1',
        sha256='1efe50e015468a22a0aed403351fb4fb9bd3a6ce6221430358ad470aad4350be',
    ),
    _Fixture(
        name='test.pcapng',
        feature='auxiliary block types, and two sections',
        build=build_test,
    ),
    _Fixture(
        name='profile.pcapng',
        feature='the if_* and isb_* option space',
        build=build_profile,
    ),
)


def _download(url: 'str') -> 'bytes':
    """Fetch ``url`` and return its body."""
    with urllib.request.urlopen(url, timeout=TIMEOUT) as response:  # nosec: B310
        return response.read()


def _materialise(fixture: '_Fixture', path: 'pathlib.Path') -> 'tuple[bytes, str]':
    """Produce one fixture's bytes, and say where they came from.

    A fixture with no URL is built offline. A fixture with a URL is served from
    ``path`` when what is already there matches the recorded digest, which makes
    repeat runs both idempotent and offline-safe; otherwise it is downloaded and
    the digest is checked.

    Args:
        fixture: Fixture to produce.
        path: Where the fixture will be written, checked for a usable copy.

    Returns:
        The fixture's bytes, and a short description of their provenance.

    Raises:
        RuntimeError: If a download's digest does not match the recorded one.

    """
    if fixture.url is None:
        return fixture.build(), 'synthesised'

    if path.is_file():
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() == fixture.sha256:
            return data, 'downloaded (already present)'

    try:
        data = _download(fixture.url)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f'    ! {fixture.url} is unreachable ({exc});')
        print(f'    ! synthesising a stand-in for {fixture.name} instead -- the '
              'upstream capture was NOT used')
        return fixture.build(), 'synthesised (download unavailable)'

    digest = hashlib.sha256(data).hexdigest()
    if digest != fixture.sha256:
        raise RuntimeError(
            f'{fixture.name}: SHA-256 mismatch for {fixture.url}\n'
            f'  expected {fixture.sha256}\n'
            f'  received {digest}\n'
            'The upstream capture has changed, or the download was corrupted. '
            'Verify the new bytes by hand before updating the recorded digest.'
        )
    return data, 'downloaded'


class _LogCapture(logging.Handler):
    """Collect pcapkit's own log records rather than letting them print.

    pcapkit reports a parse complaint twice -- once through :mod:`warnings` and
    once through its ``pcapkit`` logger -- but only the logger call is reliable:
    it passes a computed ``stacklevel`` to :func:`warnings.warn` that can point
    outside the stack, and the record then never reaches a
    :func:`warnings.catch_warnings` recorder. So the logger is what this listens
    to. Duplicates are dropped, because one complaint per block in a capture
    with sixty-four packets is not sixty-four pieces of information.

    """

    def __init__(self) -> 'None':
        super().__init__(level=logging.WARNING)
        self.messages = []  # type: list[str]

    def emit(self, record: 'logging.LogRecord') -> 'None':
        """Record ``record``'s message, first occurrence only."""
        message = record.getMessage()
        if message not in self.messages:
            self.messages.append(message)


def _verify(path: 'pathlib.Path') -> 'tuple[str, list[str]]':
    """Round-trip one fixture through pcapkit and describe the result.

    Args:
        path: Fixture to parse.

    Returns:
        A short status string -- a frame count, or the failure -- and the
        distinct complaints pcapkit logged while parsing.

    """
    try:
        from pcapkit.interface import extract
    except ImportError as exc:  # pragma: no cover - depends on the environment
        return f'not verified ({exc})', []

    logger = logging.getLogger('pcapkit')
    capture = _LogCapture()
    level, handlers, propagate = logger.level, logger.handlers, logger.propagate
    logger.handlers, logger.propagate = [capture], False
    logger.setLevel(logging.WARNING)
    try:
        extractor = extract(fin=str(path), fout='/tmp/out', format='tree',
                            store=True, nofile=True)
        return f'{extractor.length} frames', capture.messages
    except Exception as exc:  # pylint: disable=broad-except
        return f'FAILED to parse: {type(exc).__name__}: {exc}', capture.messages
    finally:
        logger.setLevel(level)
        logger.handlers, logger.propagate = handlers, propagate


def generate(dest: 'pathlib.Path | None' = None) -> 'list[pathlib.Path]':
    """Write the ``.pcapng`` sample fixtures into ``dest``.

    Idempotent: a fixture already on disk with the right bytes is left alone,
    and a downloaded fixture already present with the right digest is not
    fetched again. Every fixture written is parsed back with pcapkit and the
    result reported, so a fixture that the library cannot read is loud rather
    than silent.

    Args:
        dest: Destination directory; defaults to ``<repo root>/sample``.

    Returns:
        The paths written, in fixture order.

    Raises:
        RuntimeError: If a download's digest does not match, or if any fixture
            fails to parse back through pcapkit.

    """
    root = SAMPLE_DIR if dest is None else pathlib.Path(dest)
    root.mkdir(parents=True, exist_ok=True)

    print(f'writing PCAP-NG fixtures into {root}')
    written = []  # type: list[pathlib.Path]
    broken = []  # type: list[str]

    for fixture in FIXTURES:
        path = root / fixture.name
        data, origin = _materialise(fixture, path)

        if path.is_file() and path.read_bytes() == data:
            action = 'unchanged'
        else:
            path.write_bytes(data)
            action = 'written'

        status, complaints = _verify(path)
        if status.startswith('FAILED'):
            broken.append(f'{fixture.name}: {status}')

        print(f'  [{origin}] {fixture.name}')
        print(f'      {len(data)} bytes, {action}; {status}')
        print(f'      exercises {fixture.feature}')
        for complaint in complaints:
            print(f'      note: {complaint}')
        written.append(path)

    if broken:
        raise RuntimeError('pcapkit could not parse the following fixture(s):\n  '
                           + '\n  '.join(broken))
    return written


if __name__ == '__main__':
    generate(pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else None)
