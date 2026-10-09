# -*- coding: utf-8 -*-
"""Parse -> rebuild identity over every layer of every sample capture.

GitHub issue #1202. :file:`tests/protocols/test_option_roundtrip_unit.py` runs
construct -> parse -> construct over cases built from the dispatch registries.
This module runs the other direction, over real octets: for every layer of every
frame in :file:`examples/captures/`, ``Cls.from_data(layer.info).data`` must equal
``layer.data``. A *layer* is each protocol on the payload chain, from the
:class:`~pcapkit.protocols.misc.pcap.frame.Frame` or
:class:`~pcapkit.protocols.misc.pcapng.PCAPNG` record down, plus every IPv6
extension header, which IPv6 keeps off that chain.

The same layers are also rebuilt from ``layer.info.to_dict()``, which
:meth:`~pcapkit.protocols.protocol.ProtocolBase.from_data` accepts too, and each
:class:`~pcapkit.corekit.infoclass.Info` is put through ``to_dict`` and
``from_dict``. Finally each capture is rebuilt whole, header and records or
blocks, and compared with the file.

A case that does not close today is listed in :data:`LAYER_GAPS` or
:data:`DICT_GAPS` with the issue that tracks it. Both tables are asserted in both
directions: a listed case must still fail in the recorded way, a case not listed
must pass, and every entry must name a case that exists.

The module reads generated captures, so it belongs to the fixture-dependent tier.

"""
from __future__ import annotations

import importlib.util
import struct
import unittest
import warnings
from typing import TYPE_CHECKING, NamedTuple

from tests._support import close_extractor, reimport_once_per_class, time_limit
from tests._tiers import SAMPLE_ROOT

if TYPE_CHECKING:
    from typing import Any, Iterator, Optional

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Whole seconds one sweep over every capture may take. A sweep takes under ten.
SWEEP_TIMEOUT = 300


class Gap(NamedTuple):
    """One case that does not round-trip, and the defect that stops it."""

    #: Tracking issue, or :data:`None` while the defect is not yet filed.
    issue: 'Optional[int]'
    #: Expected outcome: ``'TRUNCATED'`` when the rebuild is a strict prefix of
    #: the original, ``'MISMATCH'`` for any other difference, or the name of the
    #: exception the rebuild raises.
    status: 'str'
    #: The defect and how to reproduce it.
    defect: 'str'


#: Every (capture, frame, layer path) whose object-form rebuild does not close.
#: Frame numbers are one-based, as in the dumps. Empty since #1449 fixed the
#: IPv6 extension-header rebuild (#1446).
LAYER_GAPS: 'dict[str, Gap]' = {}

class DictGap(NamedTuple):
    """A protocol whose dict-form rebuild does not close."""

    #: Tracking issue, or :data:`None` while the defect is not yet filed.
    issue: 'Optional[int]'
    #: As :attr:`Gap.status`.
    status: 'str'
    #: ``'payload'`` if only a layer carrying a payload or an IPv6 extension
    #: header fails, ``'always'`` if every layer of the protocol does.
    when: 'str'
    #: The defect and how to reproduce it.
    defect: 'str'


#: Every protocol, by class name, whose rebuild from ``info.to_dict()`` fails.
#: Empty since the payload is found from the dict's structure (#1447).
DICT_GAPS: 'dict[str, DictGap]' = {}


def captures() -> 'list[str]':
    """Every capture under :data:`~tests._tiers.SAMPLE_ROOT`, by file name."""
    return sorted(path.name for path in SAMPLE_ROOT.iterdir()
                  if path.suffix in ('.pcap', '.pcapng', '.cap'))


def outcome(layer: 'Any', as_dict: 'bool' = False) -> 'str':
    """Classify ``layer``'s rebuild from its info against ``layer.data``.

    Args:
        layer: The parsed layer.
        as_dict: Rebuild from ``layer.info.to_dict()`` rather than ``layer.info``.

    Returns:
        ``'OK'``, or a :attr:`Gap.status`.

    """
    original = layer.data
    try:
        data = type(layer).from_data(layer.info.to_dict() if as_dict else layer.info,
                                     **keywords(layer)).data
    except Exception as exc:  # pylint: disable=broad-except
        return type(exc).__name__
    if data == original:
        return 'OK'
    if len(data) < len(original) and original.startswith(data):
        return 'TRUNCATED'
    return 'MISMATCH'


def walk(frame: 'Any') -> 'Iterator[tuple[str, Any]]':
    """Yield ``(path, layer)`` for the payload chain and every IPv6 extension header."""
    from pcapkit.protocols.misc.null import NoPayload

    path = ''
    layer = frame
    while not isinstance(layer, NoPayload):
        path = f'{path}/{type(layer).__name__}' if path else type(layer).__name__
        yield path, layer
        for ext in getattr(layer, '_exthdr', {}).values():
            yield f'{path}/{type(ext).__name__}', ext
        layer = layer.payload


def keywords(layer: 'Any') -> 'dict[str, Any]':
    """Construction keywords ``layer.info`` does not carry, as the engines pass them."""
    from pcapkit.protocols.misc.pcap.frame import Frame
    from pcapkit.protocols.misc.pcapng import PCAPNG

    if isinstance(layer, Frame):
        return {'num': layer._fnum, 'header': layer._ghdr}  # pylint: disable=protected-access
    if isinstance(layer, PCAPNG):
        return {'num': layer._fnum, 'sct': layer._sect, 'ctx': layer._ctx}  # pylint: disable=protected-access
    return {}


def pcapng_blocks(raw: 'bytes') -> 'Iterator[bytes]':
    """Split a PCAP-NG file into its blocks by each block's total length."""
    offset, endian = 0, '<'
    while offset < len(raw):
        if raw[offset:offset + 4] == b'\x0a\x0d\x0d\x0a':
            endian = '<' if raw[offset + 8:offset + 12] == b'\x4d\x3c\x2b\x1a' else '>'
        (length,) = struct.unpack(f'{endian}I', raw[offset + 4:offset + 8])
        yield raw[offset:offset + length]
        offset += length


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class CaptureRoundTripTests(unittest.TestCase):
    """Every layer of every capture rebuilds from what was parsed."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        # The option captures carry deliberately odd values, and parsing or
        # rebuilding them warns; the octets are what is asserted.
        quiet = warnings.catch_warnings()
        quiet.__enter__()  # pylint: disable=unnecessary-dunder-call
        self.addCleanup(quiet.__exit__, None, None, None)
        warnings.simplefilter('ignore')

    def layers(self) -> 'Iterator[tuple[str, Any]]':
        """Yield ``(case id, layer)`` for every layer of every capture."""
        from pcapkit import extract

        names = captures()
        self.assertGreater(len(names), 2, f'no generated captures under {SAMPLE_ROOT}')
        for name in names:
            extractor = extract(fin=str(SAMPLE_ROOT / name), store=True, nofile=True)
            try:
                for number, frame in enumerate(extractor.frame, start=1):
                    for path, layer in walk(frame):
                        yield f'{name}#{number}:{path}', layer
            finally:
                close_extractor(extractor)

    def test_every_layer_rebuilds_from_its_info(self) -> None:
        seen = set()
        with time_limit(SWEEP_TIMEOUT):
            for case, layer in self.layers():
                seen.add(case)
                got = outcome(layer)
                gap = LAYER_GAPS.get(case)
                with self.subTest(case=case):
                    self.assertEqual(got, 'OK' if gap is None else gap.status)
        self.assertGreater(len(seen), 5000)
        self.assertEqual(set(LAYER_GAPS) - seen, set(), 'LAYER_GAPS names cases that no longer exist')

    def test_every_layer_rebuilds_from_its_info_as_a_dict(self) -> None:
        from pcapkit.protocols.misc.null import NoPayload

        hit = set()
        with time_limit(SWEEP_TIMEOUT):
            for case, layer in self.layers():
                name = type(layer).__name__
                gap = DICT_GAPS.get(name)
                if gap is not None and gap.when == 'payload':
                    payload = getattr(layer, '_next', None)
                    if (payload is None or isinstance(payload, NoPayload)) \
                            and not getattr(layer, '_exthdr', None):
                        gap = None
                got = outcome(layer, as_dict=True)
                if gap is not None:
                    hit.add(name)
                with self.subTest(case=case):
                    self.assertEqual(got, 'OK' if gap is None else gap.status)
        self.assertEqual(set(DICT_GAPS) - hit, set(), 'DICT_GAPS names protocols no capture exercises')

    def test_every_info_survives_to_dict_and_from_dict(self) -> None:
        with time_limit(SWEEP_TIMEOUT):
            for case, layer in self.layers():
                with self.subTest(case=case):
                    self.assertEqual(type(layer.info).from_dict(layer.info.to_dict()), layer.info)

    def test_every_capture_rebuilds_byte_for_byte(self) -> None:
        """Header and records (PCAP) or every block (PCAP-NG), rebuilt and joined."""
        from pcapkit import extract
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.foundation.engines.pcapng import Context
        from pcapkit.protocols.misc.pcap.header import Header
        from pcapkit.protocols.misc.pcapng import PCAPNG

        with time_limit(SWEEP_TIMEOUT):
            for name in captures():
                raw = (SAMPLE_ROOT / name).read_bytes()
                if name.endswith('.pcapng'):
                    parts, section, ctx = [], 0, None
                    for number, block in enumerate(pcapng_blocks(raw)):
                        if block[:4] == b'\x0a\x0d\x0d\x0a':
                            section += 1
                            parsed = PCAPNG(block, num=0, sct=section, ctx=None)
                            ctx = Context(parsed.info)
                        else:
                            parsed = PCAPNG(block, num=number, sct=section, ctx=ctx)
                            if parsed.info.type == BlockType.Interface_Description_Block:
                                ctx.interfaces.append(parsed.info)
                        parts.append(PCAPNG.from_data(parsed.info, **keywords(parsed)).data)
                else:
                    extractor = extract(fin=str(SAMPLE_ROOT / name), store=True, nofile=True)
                    self.addCleanup(close_extractor, extractor)
                    header = extractor._exeng._gbhdr  # pylint: disable=protected-access
                    parts = [Header.from_data(header.info).data]
                    parts.extend(type(frame).from_data(frame.info, **keywords(frame)).data
                                 for frame in extractor.frame)
                with self.subTest(capture=name):
                    self.assertEqual(b''.join(parts), raw)


if __name__ == '__main__':
    unittest.main()
