# -*- coding: utf-8 -*-
"""``make()`` resolves an enum member name given as :obj:`str`.

GitHub issue #1210: the ``make()`` signatures declare enum arguments as
``Enum | StdlibEnum | AenumEnum | str | int``, but
:meth:`~pcapkit.protocols.protocol.ProtocolBase._make_index` raised
:exc:`~pcapkit.utilities.exceptions.ProtocolNotImplemented` for a :obj:`str`
unless a ``*_namespace`` was passed. A member name now resolves against the
enumeration class of the argument's default value, and builds the same bytes
as the member itself and as its integer value.

Every case builds its own packet in memory and reads no capture. Classes are
imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, so they belong to the live
:mod:`pcapkit` import.

"""

import importlib
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any


def _attr(path: 'str') -> 'Any':
    module, _, name = path.rpartition('.')
    return getattr(importlib.import_module(module), name)


def _tcp_alternate_checksum(**kwargs: 'Any') -> 'Any':
    option = _attr('pcapkit.const.tcp.option.Option')
    return _attr('pcapkit.protocols.transport.tcp.TCP')(
        options=[(option.TCP_Alternate_Checksum_Request, kwargs)],
    )


#: One ``make()`` per protocol family:
#: (protocol class or builder, argument, enum class, non-default member).
CASES = {
    'link/ethernet': ('pcapkit.protocols.link.ethernet.Ethernet', 'type',
                      'pcapkit.const.reg.ethertype.EtherType', 'Internet_Protocol_version_6'),
    'link/l2tpv2': ('pcapkit.protocols.link.l2tpv2.L2TPv2', 'type',
                    'pcapkit.const.l2tp.type.Type', 'Control'),
    'internet/ipv4': ('pcapkit.protocols.internet.ipv4.IPv4', 'protocol',
                      'pcapkit.const.reg.transtype.TransType', 'TCP'),
    'transport/tcp': (_tcp_alternate_checksum, 'algorithm',
                      'pcapkit.const.tcp.checksum.Checksum', 'Checksum_16_bit_Fletcher_s_algorithm'),
    'application/ospf': ('pcapkit.protocols.application.ospf.OSPF', 'type',
                         'pcapkit.const.ospf.packet.Packet', 'Database_Description'),
    'misc/pcap': ('pcapkit.protocols.misc.pcap.header.Header', 'network',
                  'pcapkit.const.reg.linktype.LinkType', 'RAW'),
}


class TestMakeIndexStr(unittest.TestCase):
    """Pin member-name resolution in ``_make_index`` across families."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_member_name_matches_member_and_int(self) -> None:
        for case, (maker, arg, enum_path, member) in CASES.items():
            with self.subTest(case=case):
                build = _attr(maker) if isinstance(maker, str) else maker
                value = getattr(_attr(enum_path), member)

                expected = build(**{arg: value}).data
                self.assertEqual(build(**{arg: member}).data, expected)
                self.assertEqual(build(**{arg: int(value)}).data, expected)
                # the member is not the default, so the name was not ignored
                self.assertNotEqual(build().data, expected)

    def test_unknown_name_still_raises(self) -> None:
        exc = _attr('pcapkit.utilities.exceptions.ProtocolNotImplemented')
        ethernet = _attr('pcapkit.protocols.link.ethernet.Ethernet')
        with self.assertRaises(exc):
            ethernet(type='No_Such_EtherType')

    def test_unknown_name_falls_back_to_default(self) -> None:
        ethernet = _attr('pcapkit.protocols.link.ethernet.Ethernet')
        proto = ethernet(type='No_Such_EtherType', type_default=0x1234)
        self.assertEqual(proto.data[12:14], b'\x12\x34')

    def test_explicit_namespace_wins(self) -> None:
        ethernet = _attr('pcapkit.protocols.link.ethernet.Ethernet')
        # the name is also an EtherType member, but the namespace decides
        proto = ethernet(type='Internet_Protocol_version_6',
                         type_namespace={'Internet_Protocol_version_6': 0x1234},
                         type_reversed=True)
        self.assertEqual(proto.data[12:14], b'\x12\x34')

    def test_shared_name_with_one_meaning_resolves(self) -> None:
        ipv4 = _attr('pcapkit.protocols.internet.ipv4.IPv4')
        tos_del = _attr('pcapkit.const.ipv4.tos_del.ToSDelay')
        tos_thr = _attr('pcapkit.const.ipv4.tos_thr.ToSThroughput')
        tos_rel = _attr('pcapkit.const.ipv4.tos_rel.ToSReliability')

        expected = ipv4(tos_del=tos_del.NORMAL, tos_thr=tos_thr.NORMAL).data
        self.assertEqual(ipv4(tos_del='NORMAL', tos_thr='NORMAL').data, expected)
        # an equal but distinct string object, so the match is not by identity
        self.assertEqual(ipv4(tos_del='NORMAL', tos_thr=''.join(['NOR', 'MAL'])).data, expected)

        expected = ipv4(tos_thr=tos_thr.HIGH, tos_rel=tos_rel.HIGH).data
        self.assertEqual(ipv4(tos_thr='HIGH', tos_rel='HIGH').data, expected)
        self.assertNotEqual(ipv4().data, expected)

    def test_shared_name_with_two_meanings_raises(self) -> None:
        enum = importlib.import_module('enum')
        exc = _attr('pcapkit.utilities.exceptions.ProtocolNotImplemented')
        protocol = _attr('pcapkit.protocols.protocol.ProtocolBase')

        left = enum.IntEnum('Left', {'Shared': 1})
        right = enum.IntEnum('Right', {'Shared': 2})

        class Pair(protocol):  # type: ignore[misc,valid-type]
            def make_pair(self, a: 'Any' = left.Shared, a_namespace: 'Any' = None,
                          b: 'Any' = right.Shared, b_namespace: 'Any' = None) -> 'int':
                return self._make_index(a, namespace=a_namespace)

        with self.assertRaisesRegex(exc, r"ambiguous member name 'Shared'.*"
                                         r"pass a_namespace= or b_namespace= explicitly"):
            Pair.make_pair(Pair, a='Shared', b='Shared')
        # an explicit namespace on the other argument removes the ambiguity
        self.assertEqual(Pair.make_pair(Pair, a='Shared', b='Shared', b_namespace=right), 1)

        # a real make(): ``LOW`` is a ToSDelay member but not a ToSThroughput one
        ipv4 = _attr('pcapkit.protocols.internet.ipv4.IPv4')
        with self.assertRaisesRegex(exc, r"ambiguous member name 'LOW'.*"
                                         r"pass tos_del_namespace= or tos_thr_namespace= explicitly"):
            ipv4(tos_del='LOW', tos_thr='LOW')

    def test_without_inferable_enum_still_raises(self) -> None:
        exc = _attr('pcapkit.utilities.exceptions.ProtocolNotImplemented')
        protocol = _attr('pcapkit.protocols.protocol.ProtocolBase')
        # called outside any ``make()``, so there is no argument to infer from
        with self.assertRaises(exc):
            protocol._make_index('Internet_Protocol_version_6')

        # ``status`` defaults to ``None``, so its enum cannot be inferred
        http = _attr('pcapkit.protocols.application.httpv1.HTTP')
        with self.assertRaises(exc):
            http(status='OK')


if __name__ == '__main__':
    unittest.main()
