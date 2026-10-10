# -*- coding: utf-8 -*-
"""The scapy engine starts each PCAP-NG section with its own interfaces (#1522).

An interface ID counts the Interface Description Blocks of its own section only,
but :class:`scapy.utils.RawPcapNgReader` appends every section's to one table, so
a later section's interface 0 resolved to the first section's, link type and
``if_tsresol`` included. :mod:`pcapkit.foundation.engines.scapy` resets the table
at each Section Header Block in its own reader subclass.

Both captures are synthesised from :file:`tcp.pcap`, so the module belongs to the
fixture-dependent tier. Each has two little-endian sections, the first on one
Ethernet interface with ``if_tsresol=9``, the second in microseconds:

* ``tsresol`` -- the issue's capture: the second section is one Ethernet
  interface too, so only the resolution tells the two apart;
* ``interfaces`` -- the second section's interface 0 is raw IPv6
  (``LINKTYPE_IPV6``) and its interface 1 Ethernet, so each ID would resolve to an
  interface of the other link type.

"""
from __future__ import annotations

import decimal
import importlib.util
import os
import struct
import tempfile
import unittest
import warnings

from tests._support import close_extractor, reimport_once_per_class, sample_path

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))
HAS_SCAPY = importlib.util.find_spec('scapy') is not None

#: ``LINKTYPE_ETHERNET`` and ``LINKTYPE_IPV6``.
ETHERNET, IPV6 = 1, 229

#: Nanoseconds added to each frame of the nanosecond section, so its timestamps
#: have sub-microsecond digits.
EXTRA_NS = 789

#: Frames of :file:`tcp.pcap` that go in the first section, per capture.
SPLIT = {'tsresol': 3, 'interfaces': 2}


def _block(kind: 'int', body: 'bytes') -> 'bytes':
    body += bytes(-len(body) % 4)
    length = len(body) + 12
    return struct.pack('<II', kind, length) + body + struct.pack('<I', length)


def _shb() -> 'bytes':
    return _block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))


def _idb(linktype: 'int', *, tsresol: 'int | None' = None) -> 'bytes':
    options = b''
    if tsresol is not None:
        options = struct.pack('<HHB', 9, 1, tsresol) + bytes(3) + struct.pack('<HH', 0, 0)
    return _block(1, struct.pack('<HHI', linktype, 0, 0x40000) + options)


def _epb(interface: 'int', ticks: 'int', orig_len: 'int', octets: 'bytes') -> 'bytes':
    return _block(6, struct.pack('<IIIII', interface, ticks >> 32, ticks & 0xFFFF_FFFF,
                                 len(octets), orig_len) + octets)


def _records() -> 'list[tuple[int, int, int, bytes]]':
    """``(ts_sec, ts_usec, orig_len, octets)`` of each record of :file:`tcp.pcap`."""
    with open(sample_path('tcp.pcap'), 'rb') as file:
        rest = file.read()[24:]
    records = []
    while rest:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', rest[:16])
        records.append((ts_sec, ts_usec, orig_len, rest[16:16 + incl_len]))
        rest = rest[16 + incl_len:]
    return records


def _capture(case: 'str') -> 'tuple[bytes, list[tuple[int, int, decimal.Decimal]]]':
    """The capture, and the ``(link type, resolution, timestamp)`` of each frame."""
    records, split = _records(), SPLIT[case]
    blocks, expected = [_shb(), _idb(ETHERNET, tsresol=9)], []
    for ts_sec, ts_usec, orig_len, octets in records[:split]:
        ns = ts_sec * 10**9 + ts_usec * 1000 + EXTRA_NS
        blocks.append(_epb(0, ns, orig_len, octets))
        expected.append((ETHERNET, 10**9, decimal.Decimal(ns).scaleb(-9)))

    interfaces = [ETHERNET] if case == 'tsresol' else [IPV6, ETHERNET]
    blocks.append(_shb())
    blocks.extend(_idb(linktype) for linktype in interfaces)
    for ts_sec, ts_usec, orig_len, octets in records[split:]:
        linktype = IPV6 if IPV6 in interfaces and octets[12:14] == b'\x86\xdd' else ETHERNET
        if linktype == IPV6:
            octets, orig_len = octets[14:], orig_len - 14
        us = ts_sec * 10**6 + ts_usec
        blocks.append(_epb(interfaces.index(linktype), us, orig_len, octets))
        expected.append((linktype, 10**6, decimal.Decimal(us).scaleb(-6)))
    return b''.join(blocks), expected


@unittest.skipUnless(HAS_RUNTIME and HAS_SCAPY, 'runtime dependencies or scapy not installed')
class ScapyPCAPNGSectionTests(unittest.TestCase):
    """Each section's interface IDs resolve against that section's interfaces."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        self.captures = {}  # type: dict[str, tuple[str, list]]
        for case in SPLIT:
            data, expected = _capture(case)
            path = os.path.join(self.tmp, f'{case}.pcapng')
            with open(path, 'wb') as file:
                file.write(data)
            self.captures[case] = (path, expected)

    def _extract(self, fin: 'str', engine: 'str', **kwargs: 'object'):  # type: ignore[no-untyped-def]
        from pcapkit import extract

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=fin, engine=engine, nofile=True, **kwargs)
        self.addCleanup(close_extractor, extractor)
        return extractor

    def test_each_frame_takes_its_own_sections_interface(self) -> None:
        from pcapkit.toolkit.scapy import RESOLUTION_ATTR

        for case, (fin, expected) in self.captures.items():
            with self.subTest(case=case):
                default = self._extract(fin, 'default', store=True)
                self.assertEqual([frame.info.timestamp_epoch for frame in default.frame],
                                 [stamp for _, _, stamp in expected])

                scapy = self._extract(fin, 'scapy', store=True)
                # the engine has imported scapy.all, so the link-type table is full
                from scapy.config import conf  # isort:skip

                self.assertEqual([(type(packet).__name__, getattr(packet, RESOLUTION_ATTR), packet.time)
                                  for packet in scapy.frame],
                                 [(conf.l2types.num2layer[linktype].__name__, resolution, stamp)
                                  for linktype, resolution, stamp in expected])

    def test_traced_pcap_matches_the_default_engine_byte_for_byte(self) -> None:
        for case, (fin, _) in self.captures.items():
            for nanosecond in (False, True):
                with self.subTest(case=case, nanosecond=nanosecond):
                    flows = {}
                    for engine in ('default', 'scapy'):
                        extractor = self._extract(fin, engine, tcp=True, trace=True, trace_format='pcap',
                                                  trace_fout=tempfile.mkdtemp(dir=self.tmp),
                                                  trace_nanosecond=nanosecond)
                        flows[engine] = []
                        for flow in extractor.trace.tcp:
                            with open(flow.fpout, 'rb') as file:
                                flows[engine].append((flow.label, tuple(flow.index), file.read()))

                    # an IPv4 flow across both sections, and an IPv6 one, which the
                    # ``interfaces`` capture carries on its raw IPv6 interface
                    self.assertEqual([struct.unpack('<I', data[20:24])[0] for _, _, data in flows['default']],
                                     [ETHERNET, IPV6 if case == 'interfaces' else ETHERNET])
                    self.assertEqual(flows['scapy'], flows['default'])


if __name__ == '__main__':
    unittest.main()
