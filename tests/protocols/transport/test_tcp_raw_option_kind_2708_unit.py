# -*- coding: utf-8 -*-
"""A TCP option given as raw octets builds whatever kind its first octet holds.

GitHub issue #2708: ``_make_tcp_options`` resolves the kind of a raw-octets
option through ``_make_index``, as it does the kind of a ``(code, arguments)``
pair, so a kind no member of :class:`~pcapkit.const.tcp.option.Option` holds,
255 among them, comes back as its code. ``Option.get`` itself raises
``EnumValueError`` for such a kind, which a parse gives back as an unassigned
option, and whose octets have to build through this branch as well. Empty
octets hold no kind at all, and raise ``ProtocolError`` as the other malformed
items do.

The kinds are the ones ``Option.get`` refuses, read off the registry rather
than listed, and each case asserts the octets against :rfc:`9293#section-3.1`:
the option is written as given, after the 20-octet header, and Data Offset
counts it.

Every case builds its own octets in memory and reads no capture. :class:`TCP`
is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""
# Deferring these is the design: each build runs after the per-class re-import.
# pylint: disable=import-outside-toplevel
from __future__ import annotations

import unittest

from tests._support import reimport_once_per_class


def _refused_kinds() -> 'list[int]':
    """Return the kinds that ``Option.get`` refuses."""
    from pcapkit.const.tcp.option import Option

    kinds = []
    for kind in range(256):
        try:
            Option.get(kind)
        except ValueError:
            kinds.append(kind)
    return kinds


class TestTCPRawOptionKind(unittest.TestCase):
    """A raw-octets TCP option of a kind no member holds builds and rebuilds."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_registry_refuses_a_kind(self) -> None:
        """The cases below are not vacuous: 255 is a kind ``Option.get`` refuses."""
        self.assertIn(255, _refused_kinds())

    def test_raw_octets_build_as_the_pair_does(self) -> None:
        from pcapkit.protocols.transport.tcp.protocol import TCP

        for kind in _refused_kinds():
            with self.subTest(kind=kind):
                raw = bytes([kind, 4]) + b'ab'
                built = TCP(options=[raw]).data
                self.assertEqual(built, TCP(options=[(kind, {'data': b'ab'})]).data)
                # Data Offset is 6 words: the 20-octet header and the option.
                self.assertEqual(built[12] >> 4, 6)
                self.assertEqual(built[20:], raw)

    def test_parsed_option_rebuilds_from_its_octets(self) -> None:
        from pcapkit.protocols.transport.tcp.protocol import TCP

        for kind in _refused_kinds():
            with self.subTest(kind=kind):
                packet = TCP(options=[(kind, {'data': b'ab'})]).data
                parsed = TCP(packet)
                (option,) = parsed.info.options.values()
                self.assertEqual(int(option.kind), kind)
                self.assertEqual(option.data, b'ab')

                octets = packet[20:20 + option.length]
                self.assertEqual(TCP(options=[octets]).data, packet)

    def test_empty_octets_are_refused(self) -> None:
        """Raw octets with no kind octet raise ``ProtocolError``, not ``IndexError``."""
        from pcapkit.protocols.transport.tcp.protocol import TCP
        from pcapkit.utilities.exceptions import ProtocolError

        for options in ([b''], [b'\x01', b'']):
            with self.subTest(options=options):
                with self.assertRaisesRegex(ProtocolError, 'holds no kind octet'):
                    TCP(options=options)


if __name__ == '__main__':
    unittest.main()
