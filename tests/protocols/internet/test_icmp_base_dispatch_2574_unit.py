# -*- coding: utf-8 -*-
"""The ICMP family base dispatches where the version is known. C.f. #2574.

A versioned family's base never yields an instance of itself. The ``version``
keyword names the member :class:`~pcapkit.protocols.internet.icmp.ICMP` gives,
from octets or from fields, and nothing else does: an ICMP message has no
version field -- the IP layer names it, by protocol number 1 (RFC 792) or 58
(RFC 4443, section 1) -- and no field picks a member, so both are refused
without it, ``pseudo`` included. ``from_data`` gives the member whose data model
it is handed, and refuses a ``dict``, whose keys need not tell the two apart: an
Echo message's do not.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import struct
import unittest

from tests._support import reimport_once_per_class

#: An Echo Request of each version, identifier 7, sequence 2, checksum zero:
#: type 8 in ICMPv4 (RFC 792) and 128 in ICMPv6 (RFC 4443, section 4.1).
ECHO = {
    4: struct.pack('>BBHHH', 8, 0, 0, 7, 2) + b'odd',
    6: struct.pack('>BBHHH', 128, 0, 0, 7, 2) + b'odd',
}

#: The refusals given no ``version``.
NO_VERSION_OCTETS = '^ICMP: no version field; pass version=4 or version=6, or parse with ICMPv4 or ICMPv6$'
NO_VERSION_FIELDS = '^ICMP: no version to build with; pass version=4 or version=6$'


def pseudo() -> 'object':
    """An IPv6 pseudo-header, which only ICMPv6 takes."""
    from pcapkit.const.reg.transtype import TransType
    from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo

    return IP_Pseudo(src='2001:db8::1', dst='2001:db8::2', protocol=TransType.IPv6_ICMP, upper_length=0)


class ICMPBaseDispatchTests(unittest.TestCase):
    """``ICMP(...)`` and ``ICMP.from_data`` give the member, never the base."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def member(version: 'int') -> 'type':
        from pcapkit.protocols.internet.icmpv4 import ICMPv4
        from pcapkit.protocols.internet.icmpv6 import ICMPv6

        return {4: ICMPv4, 6: ICMPv6}[version]

    def test_octets_without_version_raise(self) -> None:
        from pcapkit.protocols.internet.icmp import ICMP
        from pcapkit.utilities.exceptions import ProtocolError

        for version, octets in ECHO.items():
            for source in ('bytes', 'stream'):
                with self.subTest(octets=version, source=source):
                    with self.assertRaisesRegex(ProtocolError, NO_VERSION_OCTETS):
                        if source == 'bytes':
                            ICMP(octets)
                        else:
                            ICMP(io.BytesIO(octets), len(octets))

    def test_version_picks_the_member_from_octets(self) -> None:
        """Even octets of the other version: the format carries none to object."""
        from pcapkit.protocols.internet.icmp import ICMP

        for version in (4, 6):
            for octets_of, octets in ECHO.items():
                for source in ('bytes', 'stream'):
                    with self.subTest(version=version, octets=octets_of, source=source):
                        layer = (ICMP(octets, version=version) if source == 'bytes'
                                 else ICMP(io.BytesIO(octets), len(octets), version=version))
                        self.assertIs(type(layer), self.member(version))
                        self.assertIsInstance(layer, ICMP)
                        self.assertEqual(layer.data, octets)
                        self.assertEqual(layer.data, self.member(version)(octets).data)

    def test_version_picks_the_member_from_fields(self) -> None:
        """Each build is byte-exact against the member's own and parses back unchanged."""
        from pcapkit.protocols.internet.icmp import ICMP

        cases = {
            'ICMPv4 defaults': ({}, 4),
            'ICMPv4 echo': ({'type': 8, 'body': ECHO[4][4:]}, 4),
            'ICMPv6 defaults': ({}, 6),
            'ICMPv6 echo': ({'type': 128, 'body': ECHO[6][4:], 'pseudo': pseudo()}, 6),
        }
        for label, (fields, version) in cases.items():
            with self.subTest(fields=label):
                layer = ICMP(version=version, **fields)
                self.assertIs(type(layer), self.member(version))
                self.assertEqual(layer.data, self.member(version)(**fields).data)
                parsed = ICMP(layer.data, version=version)
                self.assertEqual(parsed.data, layer.data)
                self.assertEqual(ICMP.from_data(parsed.info).data, layer.data)
        self.assertEqual(ICMP(version=4, type=8, body=ECHO[4][4:], checksum=b'\x00\x00').data, ECHO[4])

    def test_fields_without_version_raise(self) -> None:
        """Even ``pseudo``, the field only ICMPv6 takes, picks nothing."""
        from pcapkit.protocols.internet.icmp import ICMP
        from pcapkit.utilities.exceptions import ProtocolError

        for label, fields in (('no fields', {}), ('shared fields', {'type': 8, 'body': ECHO[4][4:]}),
                              ('pseudo', {'type': 128, 'pseudo': pseudo()})):
            with self.subTest(fields=label):
                with self.assertRaisesRegex(ProtocolError, NO_VERSION_FIELDS):
                    ICMP(**fields)

    def test_version_is_the_only_check(self) -> None:
        """A bad ``version`` raises; a field the member lacks fails the member's check."""
        from pcapkit.protocols.internet.icmp import ICMP
        from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

        for version in (1, True, '6', 4.0, 6.0):
            with self.subTest(version=version):
                with self.assertRaisesRegex(ProtocolError, f'^ICMP: invalid version: {version!r}$'):
                    ICMP(version=version)
        with self.assertRaisesRegex(UnsupportedCall, "^ICMPv4: unexpected keyword\\(s\\): 'pseudo'"):
            ICMP(version=4, pseudo=pseudo())

    def test_a_member_takes_version_only_as_its_own(self) -> None:
        """Building, ``version`` must name the member; parsing, it is handed on unread."""
        from pcapkit.protocols.internet.icmpv4 import ICMPv4
        from pcapkit.protocols.internet.icmpv6 import ICMPv6
        from pcapkit.utilities.exceptions import ProtocolError

        self.assertEqual(ICMPv4(version=4).data, ICMPv4().data)
        self.assertEqual(ICMPv6(version=6).data, ICMPv6().data)
        with self.assertRaisesRegex(ProtocolError, '^ICMPv4: version=6 names another member$'):
            ICMPv4(version=6)
        with self.assertRaisesRegex(ProtocolError, '^ICMPv6: version=4 names another member$'):
            ICMPv6(version=4)
        self.assertEqual(ICMPv6(ECHO[6], version=4).data, ECHO[6])

    def test_a_subclass_outside_the_members_has_no_version_of_its_own(self) -> None:
        """So it takes no ``version``, as a member takes no other's."""
        from pcapkit.protocols.internet.icmp import ICMP
        from pcapkit.utilities.exceptions import ProtocolError

        class Outside(ICMP):  # type: ignore[type-arg]
            """A concrete subclass of the base that is no member."""

            name = length = None  # type: ignore[assignment]
            @classmethod
            def __index__(cls) -> 'int':  # type: ignore[override]
                raise NotImplementedError

            def read(self, length: 'object' = None, **kwargs: 'object') -> 'object':
                raise NotImplementedError

            def make(self, **kwargs: 'object') -> 'object':
                raise NotImplementedError

        with self.assertRaisesRegex(ProtocolError, '^Outside: no version of its own to match version=6$'):
            Outside(version=6)

    def test_from_data_on_the_base_gives_the_member(self) -> None:
        from pcapkit.protocols.internet.icmp import ICMP
        from pcapkit.utilities.exceptions import ProtocolError

        for version, octets in ECHO.items():
            with self.subTest(octets=version):
                parsed = self.member(version)(octets)
                rebuilt = ICMP.from_data(parsed.info)
                self.assertIs(type(rebuilt), self.member(version))
                self.assertEqual(rebuilt.data, octets)
                with self.assertRaisesRegex(ProtocolError,
                                            '^ICMP: invalid data: must be an ICMPv4 or ICMPv6 data model$'):
                    ICMP.from_data(parsed.info.to_dict())
        with self.assertRaisesRegex(ProtocolError, '^ICMPv4: version=6 names another member$'):
            ICMP.from_data(self.member(4)(ECHO[4]).info, version=6)

    def test_only_the_base_dispatches(self) -> None:
        """A subclass of the base is constructed as itself, abstract or not."""
        from pcapkit.protocols.data.internet.icmpv4 import ICMPv4 as Data_ICMPv4
        from pcapkit.protocols.internet.icmp import ICMP
        from pcapkit.protocols.internet.icmpv4 import ICMPv4
        from pcapkit.protocols.schema.internet.icmpv4 import ICMPv4 as Schema_ICMPv4

        class Abstract(ICMP):  # type: ignore[type-arg] # pylint: disable=abstract-method
            """A direct subclass of the base, still abstract."""

        class Custom(ICMPv4, schema=Schema_ICMPv4, data=Data_ICMPv4):
            """A concrete subclass of the base, through a member."""

        octets = ECHO[4]
        self.assertIs(type(ICMP(type=8, version=4)), ICMPv4)
        self.assertIs(type(Custom(octets)), Custom)
        self.assertIs(type(Custom(type=8, version=4)), Custom)
        self.assertIs(type(Custom.from_data(Custom(octets).info)), Custom)
        with self.assertRaisesRegex(TypeError, 'abstract'):
            Abstract(octets)


if __name__ == '__main__':
    unittest.main()
