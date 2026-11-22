# -*- coding: utf-8 -*-
"""``format='pcapng'`` and :class:`~pcapkit.dumpkit.pcapng.PCAPNGIO`. C.f. #2835.

The dumper writes one Section Header Block (SHB), an Interface Description Block
(IDB) per distinct interface, and an Enhanced Packet Block (EPB) per frame. A
frame read from PCAP-NG keeps its interface's options and its own. Each case
builds its captures with :mod:`struct`, from the block layouts of
draft-ietf-opsawg-pcapng, so the expected octets do not come from the code under
test, and reads them back through :func:`pcapkit.interface.extract`.

"""

import ast
import decimal
import importlib.util
import os
import pathlib
import struct
import sys
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): hand-picked dump round trips, in both byte orders.
__tier__ = 'ALL'

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Byte order prefixes for :mod:`struct`.
ORDERS = {'little': '<', 'big': '>'}

#: Block types, option codes and link types, from the draft's registries.
SHB, IDB, PB, SPB, NRB, ISB, EPB = 0x0A0D0D0A, 1, 2, 3, 4, 5, 6
OPT_ENDOFOPT, OPT_COMMENT = 0, 1
IF_NAME, IF_TSRESOL, IF_TSOFFSET = 2, 9, 14
EPB_FLAGS = 2
ETHERNET, RAW = 1, 101


def pad(data: 'bytes') -> 'bytes':
    """``data`` padded to 32 bits."""
    return data + b'\x00' * (-len(data) % 4)


def block(order: 'str', kind: 'int', body: 'bytes') -> 'bytes':
    """A block of ``kind``, with both Block Total Length fields."""
    body = pad(body)
    return struct.pack(f'{order}II', kind, 12 + len(body)) + body + struct.pack(f'{order}I', 12 + len(body))


def option(order: 'str', code: 'int', value: 'bytes') -> 'bytes':
    """An option, padded to 32 bits."""
    return struct.pack(f'{order}HH', code, len(value)) + pad(value)


def options(order: 'str', *items: 'tuple[int, bytes]') -> 'bytes':
    """An option list ending in ``opt_endofopt``."""
    return b''.join(option(order, code, value) for code, value in items) + option(order, OPT_ENDOFOPT, b'')


def shb(order: 'str') -> 'bytes':
    """An SHB of version 1.0, of no section length and no options."""
    return block(order, SHB, struct.pack(f'{order}IHHq', 0x1A2B3C4D, 1, 0, -1))


def idb(order: 'str', linktype: 'int', snaplen: 'int' = 0, opts: 'bytes' = b'') -> 'bytes':
    """An IDB."""
    return block(order, IDB, struct.pack(f'{order}HHI', linktype, 0, snaplen) + opts)


def epb(order: 'str', interface: 'int', ticks: 'int', packet: 'bytes',
        original: 'int | None' = None, opts: 'bytes' = b'') -> 'bytes':
    """An EPB."""
    head = struct.pack(f'{order}IIIII', interface, ticks >> 32, ticks & 0xFFFF_FFFF, len(packet),
                       len(packet) if original is None else original)
    return block(order, EPB, head + pad(packet) + opts)


def checksum(data: 'bytes') -> 'int':
    """The Internet checksum of ``data``."""
    data += b'\x00' * (len(data) % 2)
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def tcp(forward: 'bool', seq: 'int', ack: 'int', flags: 'int', payload: 'bytes' = b'') -> 'bytes':
    """An IPv4 datagram carrying a TCP segment between 10.0.0.1:1234 and 10.0.0.2:80."""
    src, dst, sport, dport = b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02', 1234, 80
    if not forward:
        src, dst, sport, dport = dst, src, dport, sport
    segment = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    segment = segment[:16] + struct.pack('!H', checksum(src + dst + struct.pack('!BBH', 0, 6, len(segment))
                                                        + segment)) + segment[18:]
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(segment), seq & 0xFFFF, 0x4000, 64, 6, 0, src, dst)
    return header[:10] + struct.pack('!H', checksum(header)) + header[12:] + segment


#: Ethernet header from 02:..:01 to 02:..:02, carrying IPv4.
ETHER = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00'

#: A TCP exchange as ``(forward, seq, ack, flags, payload)``: handshake, data, close.
EXCHANGE = (
    (True, 100, 0, 0x02, b''), (False, 500, 101, 0x12, b''), (True, 101, 501, 0x10, b''),
    (True, 101, 501, 0x18, b'GET / HTTP/1.0\r\n\r\n'), (False, 501, 119, 0x11, b''),
    (True, 119, 502, 0x11, b''), (False, 502, 120, 0x10, b''),
)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PCAPNGIOTestCase(unittest.TestCase):
    """A temporary directory, and the extractor with warnings silenced."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        self.tmpdir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self.tmpdir.cleanup)

    def path(self, name: 'str', data: 'bytes | None' = None) -> 'str':
        """``name`` in the temporary directory, holding ``data`` if given."""
        path = os.path.join(self.tmpdir.name, name)
        if data is not None:
            with open(path, 'wb') as file:
                file.write(data)
        return path

    def extract(self, **kwargs: 'Any') -> 'Any':
        """:func:`pcapkit.interface.extract`, with its warnings silenced."""
        from pcapkit.interface import extract

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return extract(**kwargs)

    def read(self, path: 'str') -> 'list[Any]':
        """The frames of ``path``, each its :attr:`info`."""
        return [frame.info for frame in self.extract(fin=path, nofile=True, store=True).frame]

    def dump(self, data: 'bytes', name: 'str' = 'in.pcapng', **kwargs: 'Any') -> 'tuple[Any, bytes]':
        """Extract ``data`` as PCAP-NG; the extractor and the octets written."""
        extractor = self.extract(fin=self.path(name, data), fout=self.path('out'), format='pcapng',
                                 store=True, **kwargs)
        with open(extractor.output, 'rb') as file:
            return extractor, file.read()


class DumperOctetsTests(PCAPNGIOTestCase):
    """What :class:`~pcapkit.dumpkit.pcapng.PCAPNGIO` writes of a frame, octet for octet."""

    def frame(self, epoch: 'str', packet: 'bytes', original: 'int') -> 'Any':
        """A PCAP frame at ``epoch`` holding ``packet``."""
        from pcapkit.protocols.misc.pcap.frame.data import Frame, FrameInfo

        second = int(decimal.Decimal(epoch))
        frame = Frame(frame_info=FrameInfo(ts_sec=second, ts_usec=0, incl_len=len(packet), orig_len=original),
                      time='time', number=1, time_epoch=decimal.Decimal(epoch), len=original, cap_len=len(packet))
        frame.__update__(packet=packet)
        return frame

    def test_frames_write_a_section_an_interface_and_an_epb_each(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.dumpkit import PCAPNGIO

        for byteorder, order in ORDERS.items():
            for nanosecond, resolution in ((False, 10 ** 6), (True, 10 ** 9)):
                with self.subTest(byteorder=byteorder, nanosecond=nanosecond):
                    path = self.path(f'{byteorder}-{nanosecond}.pcapng')
                    dumper = PCAPNGIO(path, protocol=LinkType.ETHERNET, byteorder=byteorder,
                                      nanosecond=nanosecond, snaplen=0x40000)
                    dumper(self.frame('7.123456789', b'abcde', 9))(self.frame('8', b'', 0))

                    opts = options(order, (IF_TSRESOL, b'\x09')) if nanosecond else b''
                    expected = (shb(order) + idb(order, ETHERNET, 0x40000, opts)
                                + epb(order, 0, 7123456789 * resolution // 10 ** 9, b'abcde', 9)
                                + epb(order, 0, 8 * resolution, b'', 0))
                    with open(path, 'rb') as file:
                        self.assertEqual(file.read(), expected)

    def test_kept_open_file_holds_each_block_as_written(self) -> None:
        from pcapkit.dumpkit import PCAPNGIO

        kept, reopened = self.path('kept.pcapng'), self.path('reopened.pcapng')
        dumper, reference = PCAPNGIO(kept, protocol='ETHERNET'), PCAPNGIO(reopened, protocol=1)
        dumper.open()
        for second in range(3):
            dumper(self.frame(str(second), b'\x00' * second, second))
            reference(self.frame(str(second), b'\x00' * second, second))
            with self.subTest(second=second), open(kept, 'rb') as file, open(reopened, 'rb') as other:
                self.assertEqual(file.read(), other.read())
        dumper.close()
        dumper(self.frame('3', b'', 0))
        reference(self.frame('3', b'', 0))
        with open(kept, 'rb') as file, open(reopened, 'rb') as other:
            self.assertEqual(file.read(), other.read())

    def test_a_frame_of_no_interface_needs_the_protocol(self) -> None:
        from pcapkit.dumpkit import PCAPNGIO
        from pcapkit.utilities.exceptions import FormatError

        path = self.path('none.pcapng')
        dumper = PCAPNGIO(path)
        with self.assertRaisesRegex(FormatError, "needs the dumper's protocol"):
            dumper(self.frame('1', b'x', 1))
        with open(path, 'rb') as file:
            self.assertEqual(file.read(), shb(ORDERS[sys.byteorder]))


class PCAPNGRoundTripTests(PCAPNGIOTestCase):
    """PCAP-NG in, PCAP-NG out, and parsed again."""

    def capture(self, order: 'str') -> 'tuple[bytes, bytes]':
        """A capture of mixed interfaces, and what PCAP-NG output of it holds.

        Interface 0 is Ethernet at microseconds; interface 1 is raw IPv4 at
        nanoseconds, shifted by ``if_tsoffset``. Each EPB carries options of its
        own. The output drops the Name Resolution and Interface Statistics
        Blocks and nothing else.

        """
        eth = idb(order, ETHERNET, 0xFFFF, options(order, (IF_NAME, b'eth0')))
        raw = idb(order, RAW, 0, options(order, (IF_NAME, b'tun0'), (IF_TSRESOL, b'\x09'),
                                         (IF_TSOFFSET, struct.pack(f'{order}q', 1_000_000))))
        packets = (
            epb(order, 0, 1_511_106_545_471_719, ETHER + tcp(True, 1, 0, 0x02), 80,
                options(order, (OPT_COMMENT, b'first'), (EPB_FLAGS, struct.pack(f'{order}I', 1)))),
            epb(order, 1, 1_511_106_545_471_719_123, tcp(False, 9, 2, 0x12)),
            epb(order, 0, 1_511_106_546_000_000, ETHER + tcp(True, 2, 10, 0x10)),
        )
        nrb = block(order, NRB, struct.pack(f'{order}HH', 0, 0))
        isb = block(order, ISB, struct.pack(f'{order}III', 0, 0, 0))
        source = shb(order) + eth + raw + nrb + packets[0] + packets[1] + isb + packets[2]
        return source, shb(order) + eth + raw + b''.join(packets)

    def test_frames_info_and_octets_come_back(self) -> None:
        for byteorder, order in ORDERS.items():
            with self.subTest(byteorder=byteorder):
                source, expected = self.capture(order)
                extractor, written = self.dump(source)

                self.assertEqual(extractor.format, 'pcapng')
                self.assertEqual(written, expected)
                again = self.read(extractor.output)
                self.assertEqual(len(again), 3)
                for before, after in zip(extractor.frame, again):
                    self.assertEqual(after, before.info)
                    self.assertEqual(after.packet, before.info.packet)
                self.assertEqual(again[1].timestamp_epoch, decimal.Decimal('1512106545.471719123'))

    def test_sections_share_one_and_identical_interfaces_one_idb(self) -> None:
        packet = ETHER + tcp(True, 1, 0, 0x02)
        source = (shb('>') + idb('>', ETHERNET) + idb('>', ETHERNET) + epb('>', 1, 5, packet)
                  + shb('<') + idb('<', RAW) + idb('<', ETHERNET) + epb('<', 1, 6, packet) + epb('<', 0, 7, b'\x45'))
        extractor, written = self.dump(source)

        self.assertEqual(written, shb('>') + idb('>', ETHERNET) + epb('>', 0, 5, packet)
                         + idb('>', RAW) + epb('>', 0, 6, packet) + epb('>', 1, 7, b'\x45'))
        again = self.read(extractor.output)
        self.assertEqual([info.packet for info in again], [info.packet for info in self.read(self.path('in.pcapng'))])

    def test_simple_and_obsolete_packet_blocks_become_epbs(self) -> None:
        order = '<'
        flags = option(order, EPB_FLAGS, struct.pack(f'{order}I', 2))
        source = (shb(order) + idb(order, ETHERNET)
                  + block(order, SPB, struct.pack(f'{order}I', 5) + b'spb!!')
                  + block(order, PB, struct.pack(f'{order}HHIIII', 0, 0, 0, 42, 3, 4) + pad(b'pb!') + flags))
        _, written = self.dump(source)

        self.assertEqual(written, shb(order) + idb(order, ETHERNET) + epb(order, 0, 0, b'spb!!')
                         + epb(order, 0, 42, b'pb!', 4, flags))

    def test_split_output_writes_a_capture_per_block(self) -> None:
        source, _ = self.capture('<')
        extractor = self.extract(fin=self.path('in.pcapng', source), fout=self.path('split'),
                                 format='pcapng', files=True, store=True)

        for frame in extractor.frame:
            path = os.path.join(extractor.output, f'Frame {frame.info.number}.pcapng')
            with self.subTest(frame=frame.info.number):
                (info,) = self.read(path)
                self.assertEqual((info.packet, info.timestamp_epoch, info.options),
                                 (frame.info.packet, frame.info.timestamp_epoch, frame.info.options))

    def test_traced_tcp_flow_keeps_interfaces_and_options(self) -> None:
        order = '<'
        eth = idb(order, ETHERNET, 0, options(order, (IF_NAME, b'eth0')))
        raw = idb(order, RAW, 0, options(order, (IF_TSRESOL, b'\x09')))
        source = shb(order) + eth + raw
        for number, (forward, seq, ack, flags, payload) in enumerate(EXCHANGE):
            if number % 2:
                source += epb(order, 1, 10 ** 9 + number, tcp(forward, seq, ack, flags, payload))
            else:
                source += epb(order, 0, 10 ** 6 + number, ETHER + tcp(forward, seq, ack, flags, payload),
                              opts=options(order, (OPT_COMMENT, b'#%d' % number)))
        extractor = self.extract(fin=self.path('flow.pcapng', source), nofile=True, store=True, tcp=True,
                                 trace=True, trace_format='pcapng', trace_fout=self.path('flows'),
                                 trace_byteorder='little')

        (flow,) = extractor.trace.tcp
        self.assertEqual(list(flow.index), list(range(1, len(EXCHANGE) + 1)))
        with open(flow.fpout, 'rb') as file:
            written = file.read()
        self.assertTrue(written.startswith(shb('<') + eth), written[:64].hex())
        self.assertIn(raw, written)
        self.assertEqual(self.read(flow.fpout), [frame.info for frame in extractor.frame])


class PCAPInputTests(PCAPNGIOTestCase):
    """PCAP in, PCAP-NG out, and parsed again."""

    def test_pcap_frames_come_back(self) -> None:
        for magic, order, resolution in ((0xA1B2C3D4, '<', 10 ** 6), (0xA1B23C4D, '>', 10 ** 9)):
            with self.subTest(order=order, resolution=resolution):
                packets = [ETHER + tcp(*step) for step in EXCHANGE]
                source = struct.pack(f'{order}IHHiIII', magic, 2, 4, 0, 0, 0x40000, ETHERNET)
                for number, packet in enumerate(packets):
                    source += struct.pack(f'{order}IIII', 100 + number, 999 * number, len(packet), len(packet) + 1)
                    source += packet
                extractor, written = self.dump(source, name='in.pcap', trace=True, tcp=True,
                                               trace_format='pcapng', trace_fout=self.path('flows'),
                                               trace_nanosecond=resolution > 10 ** 6)

                opts = options(order, (IF_TSRESOL, b'\x09')) if resolution > 10 ** 6 else b''
                self.assertEqual(written[:28], shb(order))
                self.assertEqual(written[28:28 + len(idb(order, ETHERNET, 0x40000, opts))],
                                 idb(order, ETHERNET, 0x40000, opts))
                again = self.read(extractor.output)
                self.assertEqual([info.packet for info in again], packets)
                self.assertEqual([info.timestamp_epoch for info in again],
                                 [frame.info.time_epoch for frame in extractor.frame])
                self.assertEqual([info.original_len for info in again], [len(packet) + 1 for packet in packets])

                (flow,) = extractor.trace.tcp
                self.assertEqual([info.packet for info in self.read(flow.fpout)], packets)


class FormatRegistrationTests(PCAPNGIOTestCase):
    """``'pcapng'`` is a format wherever ``'pcap'`` is."""

    @staticmethod
    def literal(path: 'str') -> 'set[str]':
        """The members of the ``Formats`` literal in the module at ``path``."""
        tree = ast.parse((ROOT / path).read_text(encoding='utf-8'))
        node = next(node for node in ast.walk(tree) if isinstance(node, ast.Assign)
                    and [getattr(target, 'id', None) for target in node.targets] == ['Formats'])
        members = getattr(node.value.slice, 'value', node.value.slice)  # type: ignore[attr-defined]
        return {element.value for element in members.elts}

    def test_both_registries_and_both_literals_name_it(self) -> None:
        from pcapkit.dumpkit import PCAPNGIO
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.traceflow.traceflow import TraceFlow

        for registry in (Extractor.__output__, TraceFlow.__output__):
            dumper, ext = registry['pcapng']
            self.assertIs(getattr(dumper, 'klass', dumper), PCAPNGIO)
            self.assertEqual(ext, '.pcapng')
        for path in ('pcapkit/foundation/extraction.py', 'pcapkit/interface/misc.py'):
            with self.subTest(path=path):
                self.assertEqual(self.literal(path), set(Extractor._shipped_output))  # pylint: disable=protected-access
        self.assertEqual(set(Extractor._shipped_output), set(TraceFlow._shipped_output))  # pylint: disable=protected-access


if __name__ == '__main__':
    unittest.main()
