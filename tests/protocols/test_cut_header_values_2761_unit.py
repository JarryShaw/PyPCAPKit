# -*- coding: utf-8 -*-
"""A header the capture cut short rebuilds with the values its parse read.

GitHub issue #2761: a header cut short rebuilt to the octets captured, but
``from_data(info).info`` differed from ``info``. The rebuild was read from the header
``make()`` built, which holds what it filled in past the cut: the zeros
:meth:`Protocol._fill_short_read <pcapkit.protocols.protocol.Protocol._fill_short_read>`
gives a reserved field, a ``PadN`` padding an option area out, a nested schema at its
full width. The parse read the octets captured. The rebuild now parses those octets
back, at the width its parse read them at, so a round trip reproduces the parsed values
as well as the octets, with no exception.

Every concrete protocol class, found by walking the protocol classes rather than listed,
is built from its ``make()`` defaults and cut at every octet of that header, and so are
the octets below, which carry the values its defaults leave out. The parse and its
rebuild from the data model and from the :obj:`dict` give the same octets and the same
data model.

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

#: Test tier (#1958): a sweep that cuts every protocol class at every offset.
__tier__ = 'LATEST'

#: ``make()`` keywords for a class whose defaults build nothing it reads back: a Query
#: with a Max Resp Time of zero is IGMPv1's (RFC 3376, section 7.1), and HTTP builds
#: through the member its ``version`` names.
MAKE = {
    'pcapkit.protocols.application.http.protocol.HTTP': {'version': 2},
    'pcapkit.protocols.internet.igmpv2.protocol.IGMPv2': {'max_resp_time': 100},
}

#: Whole packets cut at every octet besides those ``make()`` builds, for a class whose
#: defaults build nothing, or leave empty the fields a cut reads short.
OCTETS = {
    'pcapkit.protocols.application.ftp.protocol.FTP': (b'XYZW arg\r\n',),
    'pcapkit.protocols.application.httpv1.protocol.HTTPv1': (b'GET / HTTP/1.1\r\n\r\n',),
    # an NGSetupRequest in aligned PER, which no cut of leaves decodable
    'pcapkit.protocols.application.ngap.protocol.NGAP': (
        bytes.fromhex('00150036000004001b00080002f839100001020052400d0500706361706b69742d676e62')
        + bytes.fromhex('0066000d00000000010002f839000000080015400140'),),
    # Hop-by-Hop and Destination Options: Router Alert, then a PadN of eight
    'pcapkit.protocols.internet.hopopt.protocol.HOPOPT': (bytes([17, 1, 5, 2, 0, 0, 1, 8]) + bytes(8),),
    'pcapkit.protocols.internet.ipv6_opts.protocol.IPv6_Opts': (bytes([17, 1, 5, 2, 0, 0, 1, 8]) + bytes(8),),
    # a Type 2 Routing header with a non-zero Reserved field
    'pcapkit.protocols.internet.ipv6_route.protocol.IPv6_Route': (
        bytes([59, 2, 2, 1, 1, 2, 3, 4]) + bytes(15) + b'\x01',),
    # a Report of two group records
    'pcapkit.protocols.internet.igmpv3.protocol.IGMPv3': (
        bytes.fromhex('2200c7e100000002') + bytes.fromhex('01000002ef0101010a0000010a000002')
        + bytes.fromhex('02000003ef0202020a0000030a0000040a000005'),),
    # a Binding Refresh Request carrying a PadN
    'pcapkit.protocols.internet.mh.protocol.MH': (
        bytes([59, 1, 5, 0, 0, 0, 0, 1, 0x80, 0, 0, 0x10, 1, 2, 0, 0]),),
}

#: Classes no octets are cut for, and why.
NOT_CUT = {
    'pcapkit.protocols.misc.checksum.ip_pseudo.protocol.IP_Pseudo':
        'is built from an IP layer, and is no header on the wire',
    'pcapkit.protocols.misc.pcap.frame.protocol.Frame':
        "reads its record by the global header of its savefile",
    'pcapkit.protocols.misc.pcapng.protocol.PCAPNG':
        'reads its block by the section and interfaces before it',
}


def _concrete() -> 'Iterator[tuple[str, type]]':
    """Every concrete protocol class, by qualified name."""
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
        if klass.__module__.startswith('pcapkit.protocols.') and not inspect.isabstract(klass):
            found[f'{klass.__module__}.{klass.__qualname__}'] = klass
    for name in sorted(found):
        yield name, found[name]


def _differing(parsed: 'Any', rebuilt: 'Any') -> 'tuple[str, ...]':
    """The keys whose values ``parsed`` and ``rebuilt`` do not share, in order."""
    keys = list(dict.fromkeys([*parsed, *rebuilt]))
    return tuple(key for key in keys if key not in parsed or key not in rebuilt or parsed[key] != rebuilt[key])


class CutHeaderValuesTests(unittest.TestCase):
    """Every protocol class rebuilds the values its parse read, at every cut."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        # a cut header warns that its length runs past the data, which is the point
        catcher = warnings.catch_warnings()
        catcher.__enter__()  # pylint: disable=unnecessary-dunder-call
        self.addCleanup(catcher.__exit__, None, None, None)
        warnings.simplefilter('ignore')

    def packets(self, name: str, klass: type) -> 'Iterator[bytes]':
        """The whole packets of ``klass`` to cut: its ``make()`` header, if it builds, and its octets."""
        from pcapkit.utilities.exceptions import BaseError, CaughtByCaller, ProtocolError

        try:
            with CaughtByCaller(ProtocolError):
                yield klass(**MAKE.get(name, {})).data
        except BaseError:
            pass  # its defaults build nothing, so its octets are below
        yield from OCTETS.get(name, ())

    def cuts(self) -> 'Iterator[tuple[str, bytes, Any]]':
        """Every class, the octets captured, and their parse, for each cut a class reads."""
        from pcapkit.utilities.exceptions import BaseError, CaughtByCaller, ProtocolError

        for name, klass in _concrete():
            if name in NOT_CUT:
                continue
            for whole in self.packets(name, klass):
                for count in range(1, len(whole)):
                    raw = whole[:count]
                    try:
                        with CaughtByCaller(ProtocolError):
                            layer = klass(raw, count)
                    except BaseError:
                        continue  # refused, as a cut header may be
                    yield name, raw, layer

    def test_every_class_is_cut(self) -> None:
        # a class with neither a header nor octets to cut is named, with its reason
        from pcapkit.utilities.exceptions import BaseError, CaughtByCaller, ProtocolError

        names = dict(_concrete())
        self.assertLessEqual(set(NOT_CUT) | set(MAKE) | set(OCTETS), set(names))
        for name, klass in names.items():
            with self.subTest(protocol=name):
                try:
                    with CaughtByCaller(ProtocolError):
                        built = klass(**MAKE.get(name, {})) is not None
                except (BaseError, TypeError):
                    built = False
                self.assertEqual(name in NOT_CUT, not built and name not in OCTETS)

    def test_every_cut_rebuilds_its_values(self) -> None:
        # read at the width its parse read the header at, as __short_width__ records
        for name, raw, layer in self.cuts():
            for path, data in (('model', layer.info), ('dict', layer.info.to_dict())):
                with self.subTest(protocol=name, captured=raw.hex(), path=path):
                    rebuilt = type(layer).from_data(data)
                    self.assertEqual(rebuilt.data, raw)
                    self.assertEqual(_differing(layer.info, rebuilt.info), ())


if __name__ == '__main__':
    unittest.main()
