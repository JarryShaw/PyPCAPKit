# -*- coding: utf-8 -*-
"""The L2TP family base dispatches on both paths. C.f. #2574.

A versioned family's base never yields an instance of itself: parsing octets
through :class:`~pcapkit.protocols.link.l2tp.protocol.L2TP`, constructing it from fields,
and its ``from_data`` all give the member the version names. The ``version``
field names it on either path, and it is the only thing that does from fields:
fields without it are refused. Octets without it are read by the version
nibble, bits 12 to 15 of the first word (RFC 2661, section 3.1), and data by its
``version``. ``2`` is ``L2TPv2``; no other member exists, so ``1`` (L2F) and
``3`` (L2TPv3) raise.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import struct
import unittest

from tests._support import reimport_once_per_class


def l2tp_data(version: 'int' = 2) -> 'bytes':
    """A data message, tunnel ``0x1234``, session ``0x5678``, with the nibble ``version``."""
    return struct.pack('!HHH', version, 0x1234, 0x5678) + b'\xff\x03\x00\x21PPP'


#: A control message (RFC 2661, section 3.1): T, L and S set, Length 12, Ns and Nr zero.
CONTROL = struct.pack('!HHHHHH', 0xC802, 12, 1, 0, 0, 0)

#: Octets ``L2TPv2`` parses.
OCTETS = {'data message': l2tp_data(), 'control message': CONTROL}

#: The refusal of fields given no ``version``.
NO_VERSION = '^L2TP: no version to build with; pass version=2$'


class L2TPBaseDispatchTests(unittest.TestCase):
    """``L2TP(...)`` and ``L2TP.from_data`` give the member, never the base."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_octets_without_version_give_the_member_their_nibble_names(self) -> None:
        from pcapkit.protocols.link.l2tp.protocol import L2TP
        from pcapkit.protocols.link.l2tpv2.protocol import L2TPv2

        for label, octets in OCTETS.items():
            for source in ('bytes', 'stream'):
                with self.subTest(octets=label, source=source):
                    layer = L2TP(octets) if source == 'bytes' else L2TP(io.BytesIO(octets), len(octets))
                    self.assertIs(type(layer), L2TPv2)
                    self.assertIsInstance(layer, L2TP)
                    self.assertEqual(layer.info.version, octets[1] & 0x0F)
                    self.assertEqual(layer.data, octets)
                    self.assertEqual(str(layer.protochain), str(L2TPv2(octets).protochain))

    def test_octets_no_member_reads_raise(self) -> None:
        from pcapkit.protocols.link.l2tp.protocol import L2TP
        from pcapkit.utilities.exceptions import ProtocolError

        for version in (1, 3, 15):
            with self.subTest(version=version):
                with self.assertRaisesRegex(ProtocolError, f'^L2TP: invalid version: {version}$'):
                    L2TP(l2tp_data(version))
        with self.assertRaisesRegex(ProtocolError, '^L2TP: no version in a packet shorter than 2 octets$'):
            L2TP(b'\x00')

    def test_version_picks_the_member_from_octets(self) -> None:
        from pcapkit.protocols.link.l2tp.protocol import L2TP
        from pcapkit.protocols.link.l2tpv2.protocol import L2TPv2

        for label, octets in OCTETS.items():
            for source in ('bytes', 'stream'):
                with self.subTest(octets=label, source=source):
                    layer = (L2TP(octets, version=2) if source == 'bytes'
                             else L2TP(io.BytesIO(octets), len(octets), version=2))
                    self.assertIs(type(layer), L2TPv2)
                    self.assertEqual(layer.data, octets)

    def test_version_over_octets_of_another_version_is_the_parser_s_error(self) -> None:
        """No cross-check: the member ``version`` names parses, and refuses the nibble."""
        from pcapkit.protocols.link.l2tp.protocol import L2TP
        from pcapkit.utilities.exceptions import ProtocolError

        for nibble in (1, 3):
            with self.subTest(nibble=nibble):
                with self.assertRaisesRegex(ProtocolError, f'^L2TPv2: invalid version: {nibble}$'):
                    L2TP(l2tp_data(nibble), version=2)
        with self.assertRaisesRegex(ProtocolError, '^L2TP: invalid version: 3$'):
            L2TP(l2tp_data(), version=3)

    def test_version_picks_the_member_from_fields(self) -> None:
        """Each build is byte-exact against the member's own and parses back unchanged."""
        from pcapkit.protocols.link.l2tp.protocol import L2TP
        from pcapkit.protocols.link.l2tpv2.protocol import L2TPv2

        for fields in ({}, {'tunnel_id': 0x1234, 'session_id': 0x5678}):
            with self.subTest(fields=fields):
                layer = L2TP(version=2, **fields)
                self.assertIs(type(layer), L2TPv2)
                self.assertEqual(layer.data, L2TPv2(version=2, **fields).data)
                self.assertEqual(layer.data, L2TPv2(**fields).data)
                parsed = L2TP(layer.data)
                self.assertIs(type(parsed), L2TPv2)
                self.assertEqual(parsed.data, layer.data)

    def test_fields_without_version_raise(self) -> None:
        """Even fields only L2TPv2 takes pick nothing."""
        from pcapkit.protocols.link.l2tp.protocol import L2TP
        from pcapkit.utilities.exceptions import ProtocolError

        for fields in ({}, {'tunnel_id': 0x1234, 'session_id': 0x5678}):
            with self.subTest(fields=fields):
                with self.assertRaisesRegex(ProtocolError, NO_VERSION):
                    L2TP(**fields)

    def test_version_is_the_only_check(self) -> None:
        """A version no member reads raises; a field the member lacks fails its check."""
        from pcapkit.protocols.link.l2tp.protocol import L2TP
        from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

        for version in (1, 3, True, '2', 2.0):
            with self.subTest(version=version):
                with self.assertRaisesRegex(ProtocolError, f'^L2TP: invalid version: {version!r}$'):
                    L2TP(version=version)
        with self.assertRaisesRegex(UnsupportedCall, "^L2TPv2: unexpected keyword\\(s\\): 'ttl'"):
            L2TP(version=2, ttl=3)
        with self.assertRaisesRegex(ProtocolError, '^L2TP: invalid version: 3$'):
            L2TP.from_data({'version': 3})
        with self.assertRaisesRegex(ProtocolError, '^L2TP: invalid version: None$'):
            L2TP.from_data({})

    def test_from_data_on_the_base_gives_the_member(self) -> None:
        from pcapkit.protocols.link.l2tp.protocol import L2TP
        from pcapkit.protocols.link.l2tpv2.protocol import L2TPv2

        for label, octets in OCTETS.items():
            parsed = L2TPv2(octets)
            for form in ('info', 'dict'):
                with self.subTest(octets=label, form=form):
                    data = parsed.info if form == 'info' else parsed.info.to_dict()
                    rebuilt = L2TP.from_data(data)
                    self.assertIs(type(rebuilt), L2TPv2)
                    self.assertEqual(rebuilt.data, octets)

    def test_only_the_base_dispatches(self) -> None:
        """A subclass of the base is constructed as itself, abstract or not."""
        from pcapkit.protocols.link.l2tp.data import L2TP as Data_L2TP
        from pcapkit.protocols.link.l2tp.protocol import L2TP
        from pcapkit.protocols.link.l2tpv2.protocol import L2TPv2
        from pcapkit.protocols.link.l2tp.schema import L2TP as Schema_L2TP

        class Abstract(L2TP):  # type: ignore[type-arg] # pylint: disable=abstract-method
            """A direct subclass of the base, still abstract."""

        class Custom(L2TPv2, schema=Schema_L2TP, data=Data_L2TP):
            """A concrete subclass of the base, through a member."""

        octets = OCTETS['data message']
        self.assertIs(type(L2TP(octets)), L2TPv2)
        self.assertIs(type(L2TP(version=2, tunnel_id=1)), L2TPv2)
        self.assertIs(type(Custom(octets)), Custom)
        self.assertIs(type(Custom(tunnel_id=1)), Custom)
        self.assertIs(type(Custom.from_data(Custom(octets).info)), Custom)
        with self.assertRaisesRegex(TypeError, 'abstract'):
            Abstract(octets)


if __name__ == '__main__':
    unittest.main()
