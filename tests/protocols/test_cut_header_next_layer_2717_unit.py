# -*- coding: utf-8 -*-
"""A header the capture cut short has the same next layer parsed and rebuilt.

GitHub issue #2717: a header cut short parsed with a ``Raw`` next layer, but
``from_data(info)`` rebuilt it with ``NoPayload``, from the same octets. Read at the
octets captured, a cut header leaves its next layer a negative length, which kept it
``Raw``, after dispatching no octets on a code the cut may have read as zeros. The
rebuild is read at the width the header declares (#2703), which leaves it none, so it
was ``NoPayload``. :meth:`Protocol._empty_next_layer
<pcapkit.protocols.protocol.Protocol._empty_next_layer>` keeps such a next layer
``Raw`` without the dispatch, and keeps it for a rebuild whose data model did. A cut
header given the width it declares, as a parent gives it, and a whole header with
nothing past it are ``NoPayload`` both ways.

The issue's Ethernet, GRE and FRAD cuts come first, with a whole header and octets past
a header as the controls. Then every protocol class with a non-empty ``__proto__``
table, its own or inherited, found by walking the protocol classes rather than listed,
is built from its ``make()`` defaults and cut at every octet of that header: its parse
and its rebuild from the data model and from the :obj:`dict` give the same layer chain.

The octets are built here; this module is unit-tier and reads no capture file.

"""
from __future__ import annotations

import importlib
import inspect
import pkgutil
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Iterator

#: Test tier (#1958): a sweep that cuts every dispatching protocol at every offset.
__tier__ = 'LATEST'

#: An IPv4 header (protocol UDP) and an 8-octet UDP header.
IPV4 = (bytes.fromhex('4500001c00010000401100000a0000010a000002')
        + bytes.fromhex('3039003500080000'))
#: A minimal ARP request (RFC 826).
ARP = bytes.fromhex('00010800060400010011223344550a0000010000000000000a000002')

#: The issue's cuts: the class under :mod:`pcapkit.protocols`, the octets captured,
#: and the record of the field the data ends inside.
REPROS = {
    'Ethernet': ('link.ethernet.protocol:Ethernet', '001122334455aabbccddeeff08', ('type', 1)),
    'GRE, flags only': ('link.gre.protocol:GRE', '2000', ('protocol_type', 0)),
    'GRE, one octet of Protocol Type': ('link.gre.protocol:GRE', '200008', ('protocol_type', 1)),
}

#: FRAD frames of DLCI 50 and UI control, by the length of their header: a direct NLPID,
#: a SNAP header, and the pad with an NLPID of zero.
FRAD = {
    'direct': (4, bytes.fromhex('0c21' '03' 'cc') + IPV4),
    'SNAP': (10, bytes.fromhex('0c21' '03' '00' '80' '000000' '0806') + ARP),
    'pad, zero NLPID': (5, bytes.fromhex('0c21' '03' '00' '00') + b'\xaa\xbb'),
}

#: Whole headers with nothing past them.
WHOLE = {
    'Ethernet': ('link.ethernet.protocol:Ethernet', '001122334455aabbccddeeff0800'),
    'GRE': ('link.gre.protocol:GRE', '00000800'),
    'GRE, Key present': ('link.gre.protocol:GRE', '2000080011223344'),
    **{f'FRAD, {label}': ('link.frad.protocol:FRAD', frame[:size].hex()) for label, (size, frame) in FRAD.items()},
}

#: ``make()`` keywords for a class whose defaults build a header it refuses to read:
#: a Query with a Max Resp Time of zero is IGMPv1's (RFC 3376, section 7.1).
MAKE = {
    'pcapkit.protocols.internet.igmpv2.protocol.IGMPv2': {'max_resp_time': 100},
}

#: Classes that dispatch on no field of their own header, and why.
NOT_A_HEADER_FIELD = {
    'pcapkit.protocols.misc.pcap.frame.protocol.Frame':
        "dispatches on the link type of the savefile's global header",
    'pcapkit.protocols.misc.pcapng.protocol.PCAPNG':
        'dispatches on the link type of the interface its block names',
}

#: The most layers a chain is walked through.
DEPTH = 16


def _resolve(path: str) -> type:
    module, _, name = path.partition(':')
    return getattr(importlib.import_module(f'pcapkit.protocols.{module}'), name)


def _chain(layer: 'Any') -> 'tuple[str, ...]':
    """The class names of ``layer`` and the layers below it."""
    names = []  # type: list[str]
    for _ in range(DEPTH):
        names.append(type(layer).__name__)
        if names[-1] == 'NoPayload':
            break
        layer = layer.payload
    return tuple(names)


def _dispatching() -> 'Iterator[type]':
    """Every concrete protocol class with a non-empty ``__proto__``, by qualified name."""
    import pcapkit.protocols as package
    from pcapkit.protocols.protocol import ProtocolBase

    for info in pkgutil.walk_packages(package.__path__, 'pcapkit.protocols.'):
        if 'NotImplemented' not in info.name:
            importlib.import_module(info.name)
    seen = set()  # type: set[type]
    pending = [ProtocolBase]  # type: list[type]
    found = {}  # type: dict[str, type]
    while pending:
        klass = pending.pop()
        if klass in seen:
            continue
        seen.add(klass)
        pending.extend(klass.__subclasses__())
        table = getattr(klass, '__proto__', None)
        if (klass.__module__.startswith('pcapkit.protocols.') and not inspect.isabstract(klass)
                and isinstance(table, dict) and table):
            found[f'{klass.__module__}.{klass.__qualname__}'] = klass
    for name in sorted(found):
        yield found[name]


class _Quiet(unittest.TestCase):
    """A cut header warns that its length runs past the data, which is the point."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        catcher = warnings.catch_warnings()
        catcher.__enter__()
        self.addCleanup(catcher.__exit__, None, None, None)
        warnings.simplefilter('ignore')

    def assertRebuildsItsChain(self, layer: 'Any') -> 'None':  # pylint: disable=invalid-name
        """``layer`` rebuilt from its data model and its dict: its octets and layers below."""
        for path, data in (('model', layer.info), ('dict', layer.info.to_dict())):
            with self.subTest(path=path):
                rebuilt = type(layer).from_data(data)
                self.assertEqual((rebuilt.data.hex(), _chain(rebuilt)), (layer.data.hex(), _chain(layer)))
                self.assertEqual(rebuilt.payload.info, layer.payload.info)


class CutHeaderNextLayerTests(_Quiet):
    """The issue's cuts keep ``Raw`` both ways; a whole header keeps ``NoPayload``."""

    def test_the_issue_cuts_rebuild_raw(self) -> None:
        from pcapkit.protocols.misc.raw.protocol import Raw

        for label, (path, octets, record) in REPROS.items():
            with self.subTest(case=label):
                raw = bytes.fromhex(octets)
                layer = _resolve(path)(raw, len(raw))
                self.assertEqual(layer.info.get('__short_read__'), record)
                self.assertIs(type(layer.payload), Raw)
                # nothing was dispatched on the code the cut read as zeros
                self.assertIsNone(layer.payload.info.error)
                self.assertRebuildsItsChain(layer)

    def test_every_frad_cut_rebuilds_raw(self) -> None:
        # A direct NLPID, a SNAP header and a pad, the second through FRAD's
        # own next-layer import and the others through the base's.
        from pcapkit.protocols.link.frad.protocol import FRAD as Cls
        from pcapkit.protocols.misc.raw.protocol import Raw

        for label, (size, frame) in FRAD.items():
            for count in range(1, size):
                with self.subTest(frame=label, captured=count):
                    layer = Cls(frame[:count], count)
                    self.assertIsNotNone(layer.info.get('__short_read__'))
                    self.assertIs(type(layer.payload), Raw)
                    self.assertRebuildsItsChain(layer)

    def test_a_cut_header_given_its_width_is_nopayload_both_ways(self) -> None:
        # Given the width the header declares, as its rebuild is read at, or
        # more, as a parent gives it, a cut header leaves no length.
        from pcapkit.protocols.link.ethernet.protocol import Ethernet
        from pcapkit.protocols.misc.no_payload.protocol import NoPayload

        raw = bytes.fromhex(REPROS['Ethernet'][1])
        for length in (14, 100):
            with self.subTest(length=length):
                layer = Ethernet(raw, length)
                self.assertIs(type(layer.payload), NoPayload)
                self.assertRebuildsItsChain(layer)

    def test_a_whole_header_with_no_payload_is_nopayload_both_ways(self) -> None:
        # Given more than it holds, as a parent declaring an uncaptured payload
        # gives it, the record falls in the payload field, not the header.
        from pcapkit.protocols.misc.no_payload.protocol import NoPayload

        for label, (path, octets) in WHOLE.items():
            raw = bytes.fromhex(octets)
            for length, record in ((len(raw), None), (len(raw) + 64, ('payload', 0))):
                with self.subTest(case=label, length=length):
                    layer = _resolve(path)(raw, length)
                    self.assertEqual(layer.info.get('__short_read__'), record)
                    self.assertIs(type(layer.payload), NoPayload)
                    for data in (layer.info, layer.info.to_dict()):
                        self.assertIs(type(type(layer).from_data(data).payload), NoPayload)

    def test_octets_past_a_header_are_still_dissected(self) -> None:
        # Given more than it holds, the payload field records the cut, and the
        # octets it did capture are dispatched as ever.
        from pcapkit.protocols.link.ethernet.protocol import Ethernet

        raw = bytes.fromhex(WHOLE['Ethernet'][1]) + IPV4
        layer = Ethernet(raw, 100)
        self.assertEqual(layer.info.get('__short_read__'), ('payload', len(IPV4)))
        self.assertEqual(_chain(layer), ('Ethernet', 'IPv4', 'UDP', 'NoPayload'))
        self.assertRebuildsItsChain(layer)

    def test_octets_past_a_negative_length_are_still_dissected(self) -> None:
        # A UDP Length of 4, short of its own header, leaves the payload a
        # negative length; the octets captured past the header are kept.
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.protocols.transport.udp.protocol import UDP

        raw = bytes.fromhex('9c409c41' '0004' '0000') + b'abcd'
        layer = UDP(raw, len(raw))
        self.assertIs(type(layer.payload), Raw)
        self.assertEqual(layer.payload.data, b'abcd')
        self.assertRebuildsItsChain(layer)


class DispatchingProtocolSweepTests(_Quiet):
    """Every protocol dispatching through ``__proto__`` rebuilds its chain at every cut."""

    def test_every_table_entry_names_a_dispatching_class(self) -> None:
        # A class missing from them fails the sweep instead, unbuildable or not swept.
        names = {f'{klass.__module__}.{klass.__qualname__}' for klass in _dispatching()}
        self.assertLessEqual(set(NOT_A_HEADER_FIELD) | set(MAKE), names)

    def test_every_cut_rebuilds_its_chain(self) -> None:
        from pcapkit.protocols.misc.no_payload.protocol import NoPayload
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.utilities.exceptions import BaseError, CaughtByCaller, ProtocolError

        for klass in _dispatching():
            name = f'{klass.__module__}.{klass.__qualname__}'
            if name in NOT_A_HEADER_FIELD:
                continue
            whole = klass(**MAKE.get(name, {})).data
            with self.subTest(protocol=name, captured='whole'):
                layer = klass(whole, len(whole))
                self.assertIs(type(layer.payload), NoPayload)
                self.assertRebuildsItsChain(layer)
            for count in range(1, len(whole)):
                with self.subTest(protocol=name, captured=count):
                    try:
                        with CaughtByCaller(ProtocolError):
                            layer = klass(whole[:count], count)
                    except BaseError:
                        continue  # refused, as a cut header may be
                    # Raw where the header leaves a negative length, NoPayload
                    # where its length comes from a field of its own, as UDP's
                    self.assertIn(type(layer.payload), (Raw, NoPayload))
                    self.assertRebuildsItsChain(layer)


if __name__ == '__main__':
    unittest.main()
