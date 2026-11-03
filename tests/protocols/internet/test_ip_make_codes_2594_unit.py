# -*- coding: utf-8 -*-
"""The IPv4, ICMP, IGMP and IPX makers take a member or a code, never a name.

GitHub issue #2594: each enumeration field of these makers takes a member of
its enumeration or an :class:`int` code, resolved with the enumeration's
``get``, and refuses with a :exc:`~pcapkit.utilities.exceptions.ProtocolError`
a member's name, a :obj:`bool` for a field wider than one bit (#2617), and a
code the field cannot carry. Unchecked, a name resolves against an enumeration
inferred from the caller's frame, ``IPv4(protocol=256)`` writes ``0x00``, a
too-wide ToS code raises a bare
:exc:`~pcapkit.utilities.exceptions.FieldValueError`, and every ToS field takes
``True``. A one-bit field takes ``True`` -- the IPv4 delay, throughput and
reliability bits of :rfc:`791` -- and writes it as ``1``.

``ROWS`` holds one row per migrated field: the maker, the field, its
enumeration, its width in bits, a member to build with, and where the code
lands in the octets. An option maker is reached through
:meth:`IPv4.make <pcapkit.protocols.internet.ipv4.IPv4.make>`, and the group
record maker through :meth:`IGMPv3.make
<pcapkit.protocols.internet.igmpv3.IGMPv3.make>`, as a caller reaches them.

The type of each IPv4 option is such a field as well, given to ``make`` in a
``(type, kwargs)`` pair or as the key of parsed options: :class:`OptionTypeTests`
refuses ``1 << 8``, ``-1``, ``True`` and a member's name there with the exact
message, and builds, parses back and rebuilds the widest type, ``255``.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""
# Deferring these is the design: each build runs after the per-class re-import.
# pylint: disable=import-outside-toplevel

import importlib
import io
import unittest

from tests._support import reimport_once_per_class

#: Option numbers of the IPv4 options under test (RFC 791, RFC 2113, RFC 4782).
SEC, RTRALT, QS = 130, 148, 25


def _ipv4(**kwargs: 'object') -> 'bytes':
    from pcapkit.protocols.internet.ipv4 import IPv4

    return IPv4(**kwargs).data


def _ipv4_option(code: 'int', field: 'str') -> 'object':
    def build(value: 'object') -> 'bytes':
        from pcapkit.const.ipv4.option_number import OptionNumber

        return _ipv4(options=[(OptionNumber.get(code), {field: value})])
    return build


def _ipx(value: 'object') -> 'bytes':
    from pcapkit.protocols.internet.ipx import IPX

    return IPX(type=value).data


def _icmpv4(value: 'object') -> 'bytes':
    from pcapkit.protocols.internet.icmpv4 import ICMPv4

    return ICMPv4(type=value).data


def _icmpv6(value: 'object') -> 'bytes':
    from pcapkit.protocols.internet.icmpv6 import ICMPv6

    return ICMPv6(type=value).data


def _igmpv2(value: 'object') -> 'bytes':
    # IGMPv2 makes with the family base's IGMP.make.
    from pcapkit.protocols.internet.igmpv2 import IGMPv2

    return IGMPv2(type=value).data


def _igmpv3(value: 'object') -> 'bytes':
    from pcapkit.protocols.internet.igmpv3 import IGMPv3

    return IGMPv3(type=value).data


def _igmpv3_record(value: 'object') -> 'bytes':
    from pcapkit.const.igmp.type import Type
    from pcapkit.protocols.internet.igmpv3 import IGMPv3

    return IGMPv3(type=Type.IGMPv3_Membership_Report, records=[{'record_type': value}]).data


#: ``(label, build, enumeration, member, bits, read)``: ``build(value)`` makes
#: octets with ``value`` in the field; ``enumeration`` is ``module:class``;
#: ``member`` is a member's name, chosen off the field's default; ``bits`` is
#: the field's width; ``read(octets)`` is the code the octets carry there.
ROWS = (
    # IPv4 header, RFC 791 section 3.1: the ToS octet 1 (ECN, RFC 3168
    # section 5, in its two low-order bits) and Protocol octet 9.
    ('IPv4.make tos_pre', lambda v: _ipv4(tos_pre=v), 'pcapkit.const.ipv4.tos_pre:ToSPrecedence',
     'Network_Control', 3, lambda o: o[1] >> 5),
    ('IPv4.make tos_del', lambda v: _ipv4(tos_del=v), 'pcapkit.const.ipv4.tos_del:ToSDelay',
     'LOW', 1, lambda o: o[1] >> 4 & 1),
    ('IPv4.make tos_thr', lambda v: _ipv4(tos_thr=v), 'pcapkit.const.ipv4.tos_thr:ToSThroughput',
     'HIGH', 1, lambda o: o[1] >> 3 & 1),
    ('IPv4.make tos_rel', lambda v: _ipv4(tos_rel=v), 'pcapkit.const.ipv4.tos_rel:ToSReliability',
     'HIGH', 1, lambda o: o[1] >> 2 & 1),
    ('IPv4.make tos_ecn', lambda v: _ipv4(tos_ecn=v), 'pcapkit.const.ipv4.tos_ecn:ToSECN',
     'CE', 2, lambda o: o[1] & 0b11),
    ('IPv4.make protocol', lambda v: _ipv4(protocol=v), 'pcapkit.const.reg.transtype:TransType',
     'TCP', 8, lambda o: o[9]),
    # The option follows the 20-octet header: type, length, then the field.
    ('IPv4 SEC level', _ipv4_option(SEC, 'level'),
     'pcapkit.const.ipv4.classification_level:ClassificationLevel', 'Top_Secret', 8, lambda o: o[22]),
    ('IPv4 RTRALT alert', _ipv4_option(RTRALT, 'alert'), 'pcapkit.const.ipv4.router_alert:RouterAlert',
     'Reserved_65535', 16, lambda o: int.from_bytes(o[22:24], 'big')),
    ('IPv4 QS func', _ipv4_option(QS, 'func'), 'pcapkit.const.ipv4.qs_function:QSFunction',
     'Report_of_Approved_Rate', 4, lambda o: o[22] >> 4),
    # IPX Packet Type follows Checksum, Packet Length and Transport Control.
    ('IPX.make type', _ipx, 'pcapkit.const.ipx.packet:Packet', 'NCP', 8, lambda o: o[5]),
    ('ICMPv4.make type', _icmpv4, 'pcapkit.const.icmp.type:Type', 'Destination_Unreachable', 8,
     lambda o: o[0]),
    ('ICMPv6.make type', _icmpv6, 'pcapkit.const.icmpv6.type:Type', 'Echo_Reply', 8, lambda o: o[0]),
    ('IGMP.make type', _igmpv2, 'pcapkit.const.igmp.type:Type', 'IGMPv2_Leave_Group', 8, lambda o: o[0]),
    ('IGMPv3.make type', _igmpv3, 'pcapkit.const.igmp.type:Type', 'IGMPv3_Membership_Report', 8,
     lambda o: o[0]),
    # RFC 3376 section 4.2: the first group record follows the 8-octet header.
    ('IGMPv3 group record record_type', _igmpv3_record, 'pcapkit.const.igmp.record_type:RecordType',
     'BLOCK_OLD_SOURCES', 8, lambda o: o[8]),
)


def member(row: 'tuple') -> 'object':
    """The member a row builds with."""
    module, name = row[2].split(':')
    return getattr(getattr(importlib.import_module(module), name), row[3])


class MakeCodeTests(unittest.TestCase):
    """Each row's field takes the member or its code, and refuses anything else."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def assertRefused(self, build: 'object', value: 'object') -> None:
        """``build(value)`` raises a ProtocolError, rather than building or raising another error."""
        from pcapkit.utilities.exceptions import ProtocolError

        try:
            octets = build(value)  # type: ignore[operator]
        except ProtocolError:
            return
        except Exception as exc:  # pylint: disable=broad-except
            self.fail(f'{value!r} raised {type(exc).__name__}, not ProtocolError: {exc}')
        self.fail(f'{value!r} was accepted, building {octets.hex()}')

    def test_a_code_too_wide_is_refused(self) -> None:
        for row in ROWS:
            with self.subTest(row=row[0], value=1 << row[4]):
                self.assertRefused(row[1], 1 << row[4])

    def test_a_bool_is_refused_for_a_field_wider_than_one_bit(self) -> None:
        for row in ROWS:
            if row[4] == 1:
                continue
            with self.subTest(row=row[0]):
                self.assertRefused(row[1], True)

    def test_a_bool_is_one_for_a_one_bit_field(self) -> None:
        one_bit = [row for row in ROWS if row[4] == 1]
        self.assertEqual([row[0] for row in one_bit],
                         ['IPv4.make tos_del', 'IPv4.make tos_thr', 'IPv4.make tos_rel'])
        for row in one_bit:
            with self.subTest(row=row[0]):
                self.assertEqual(row[1](True), row[1](1))
                self.assertEqual(row[5](row[1](True)), 1)

    def test_a_name_is_refused(self) -> None:
        for row in ROWS:
            with self.subTest(row=row[0], name=row[3]):
                self.assertRefused(row[1], row[3])

    def test_a_member_and_its_code_build_the_same_octets(self) -> None:
        for row in ROWS:
            code = member(row)
            with self.subTest(row=row[0], member=code):
                octets = row[1](code)
                self.assertEqual(octets, row[1](int(code)))  # type: ignore[call-overload]
                self.assertEqual(row[5](octets), int(code))  # type: ignore[call-overload]


class OptionTypeTests(unittest.TestCase):
    """The type of an IPv4 option takes a member or a code it can carry, nothing else."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _builders(self) -> 'dict[str, object]':
        """A builder for each form ``options`` takes a type in."""
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.internet.ipv4 import IPv4

        def pair(value: 'object') -> 'bytes':
            return _ipv4(options=[(value, {'data': b'\xa5\xa5'})])

        octets = pair(255)
        options = IPv4(io.BytesIO(octets), len(octets)).info.options
        _, item = list(options.items(multi=True))[0]
        return {'pair': pair, 'parsed': lambda value: _ipv4(options=OrderedMultiDict([(value, item)]))}

    def test_a_type_the_field_cannot_carry_is_refused(self) -> None:
        # #2594: checked as an 8-bit field before the EOOL and NOP skip reads it.
        from pcapkit.utilities.exceptions import ProtocolError

        for form, build in self._builders().items():
            for value in (1 << 8, -1, True, 'EOOL'):
                with self.subTest(form=form, value=value):
                    try:
                        octets = build(value)  # type: ignore[operator]
                    except ProtocolError as error:
                        self.assertEqual(str(error), f'IPv4: invalid option type: {value!r}')
                    except Exception as error:  # pylint: disable=broad-except
                        self.fail(f'{value!r} raised {type(error).__name__}: {error}')
                    else:
                        self.fail(f'{value!r} was accepted, building {octets.hex()}')

    def test_the_widest_type_builds_parses_back_and_rebuilds(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4

        for form, build in self._builders().items():
            for value in (255, OptionNumber.get(255)):
                with self.subTest(form=form, value=value):
                    octets = build(value)  # type: ignore[operator]
                    # the type octet follows the 20-octet header
                    self.assertEqual(octets[20], 255)
                    info = IPv4(io.BytesIO(octets), len(octets)).info
                    self.assertEqual([int(key) for key in info.options][0], 255)
                    self.assertEqual(IPv4.from_data(info).data.hex(), octets.hex())


if __name__ == '__main__':
    unittest.main()
