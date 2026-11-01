# -*- coding: utf-8 -*-
"""``make()`` resolves an enum member name given as :obj:`str`.

GitHub issue #1210: the ``make()`` signatures declare enum arguments as
``Enum | StdlibEnum | AenumEnum | str | int``, but without the fix
:meth:`~pcapkit.protocols.protocol.ProtocolBase._make_index` raises
:exc:`~pcapkit.utilities.exceptions.ProtocolNotImplemented` for a :obj:`str`
unless a ``*_namespace`` is passed. A member name resolves against the
enumeration class of the argument's default value, and builds the same bytes
as the member itself and as its integer value.

GitHub issue #2356 is the other half: an argument carrying an optional field
defaults to :data:`None`, which is no enumeration member, so there is nothing
for that inference to read. Such a maker names its enumeration at the
:meth:`~pcapkit.protocols.protocol.ProtocolBase._make_index` call instead, and
:data:`NONE_DEFAULT_CASES` carries one case per argument that does.

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


def _ipv6_option(protocol: 'str', option: 'str') -> 'Any':
    """A builder putting one option into an IPv6 extension header.

    Args:
        protocol: import path of the extension header class
        option: :class:`~pcapkit.const.ipv6.option.Option` member name

    Returns:
        A callable taking the option's own keywords and returning the built
        header, so that an option argument is reached the way ``make()``
        reaches it.

    """
    def build(**kwargs: 'Any') -> 'Any':
        code = getattr(_attr('pcapkit.const.ipv6.option.Option'), option)
        transtype = _attr('pcapkit.const.reg.transtype.TransType')
        return _attr(protocol)(options=[(code, kwargs)],
                               next=transtype.IPv6_NoNxt, payload=b'')
    return build


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


#: One ``make()`` per argument whose own default is :data:`None`, so that no enum
#: default is there for the namespace to be inferred from (#2356): (builder,
#: argument, enum class, member, the other keywords the option needs). Each
#: member is one the maker would not have arrived at on its own, so a name that
#: went unresolved cannot pass as a name that resolved.
NONE_DEFAULT_CASES = {
    'internet/hopopt MPL': (_ipv6_option('pcapkit.protocols.internet.hopopt.HOPOPT', 'MPL_Option'),
                            'seed_type', 'pcapkit.const.ipv6.seed_id.SeedID',
                            'SEEDID_64_BIT_UNSIGNED_INTEGER', {'seed': 5, 'seq': 7}),
    'internet/ipv6_opts MPL': (_ipv6_option('pcapkit.protocols.internet.ipv6_opts.IPv6_Opts', 'MPL_Option'),
                               'seed_type', 'pcapkit.const.ipv6.seed_id.SeedID',
                               'SEEDID_64_BIT_UNSIGNED_INTEGER', {'seed': 5, 'seq': 7}),
    'internet/hopopt SMF_DPD': (_ipv6_option('pcapkit.protocols.internet.hopopt.HOPOPT', 'SMF_DPD'),
                                'tid_type', 'pcapkit.const.ipv6.tagger_id.TaggerID',
                                'DEFAULT', {'tid': b'\x0a\x0b\x0c\x0d', 'id': b'\xaa\xbb'}),
    'internet/ipv6_opts SMF_DPD': (_ipv6_option('pcapkit.protocols.internet.ipv6_opts.IPv6_Opts', 'SMF_DPD'),
                                   'tid_type', 'pcapkit.const.ipv6.tagger_id.TaggerID',
                                   'DEFAULT', {'tid': b'\x0a\x0b\x0c\x0d', 'id': b'\xaa\xbb'}),
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

    def test_member_name_resolves_where_the_argument_defaults_to_none(self) -> None:
        """An argument whose own default is :data:`None` resolves a name too. See #2356.

        The namespace is inferred from the enumeration class of the argument's
        default value, which an argument defaulting to :data:`None` -- because
        the field it carries is optional -- does not have. Such a maker names
        its enumeration at the call instead, so that a member name resolves
        without the caller also passing a ``*_namespace``.
        """
        for case, (build, arg, enum_path, member, extra) in NONE_DEFAULT_CASES.items():
            with self.subTest(case=case):
                value = getattr(_attr(enum_path), member)

                expected = build(**extra, **{arg: value}).data
                self.assertEqual(build(**extra, **{arg: member}).data, expected)
                self.assertEqual(build(**extra, **{arg: int(value)}).data, expected)
                # the maker derives the field from its siblings when the argument
                # is not given, and derives a different value here
                self.assertNotEqual(build(**extra).data, expected)

    def test_http_status_member_name_resolves(self) -> None:
        """An HTTP/1.* status code resolves from its member name. See #2356.

        ``status`` defaults to :data:`None`, since a response has a status where
        a request has a method and a URI, so its namespace is named at the call.
        :meth:`~pcapkit.protocols.protocol.ProtocolBase._make_index` yields the
        member's integer, and a start line built from the integer carries no
        reason phrase; only the member itself brings one along.
        """
        http = _attr('pcapkit.protocols.application.httpv1.HTTPv1')
        status_code = _attr('pcapkit.const.http.status_code.StatusCode')

        self.assertEqual(http(status='CODE_404').data, http(status=404).data)
        self.assertEqual(http(status='CODE_404').data, b'HTTP/1.1 404 \r\n\r\n')
        self.assertEqual(http(status=status_code.CODE_404).data, b'HTTP/1.1 404 Not Found\r\n\r\n')

    def test_unknown_name_still_raises(self) -> None:
        exc = _attr('pcapkit.utilities.exceptions.ProtocolNotImplemented')
        ethernet = _attr('pcapkit.protocols.link.ethernet.Ethernet')
        with self.assertRaises(exc):
            ethernet(type='No_Such_EtherType')

        # a named namespace resolves a member name, not an arbitrary string: an
        # HTTP status code member is spelled ``CODE_404``, so ``'OK'`` is none
        http = _attr('pcapkit.protocols.application.httpv1.HTTPv1')
        with self.assertRaises(exc):
            http(status='OK')

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

    def test_shared_name_with_two_meanings_resolves_per_argument(self) -> None:
        # the per-argument resolution of #1308; see test_protocol_make_unit
        enum = importlib.import_module('enum')
        exc = _attr('pcapkit.utilities.exceptions.ProtocolNotImplemented')
        protocol = _attr('pcapkit.protocols.protocol.ProtocolBase')

        left = enum.IntEnum('Left', {'Shared': 1})
        right = enum.IntEnum('Right', {'Shared': 2})

        class Pair(protocol):  # type: ignore[misc,valid-type]
            def make_pair(self, a: 'Any' = left.Shared, a_namespace: 'Any' = None,
                          b: 'Any' = right.Shared, b_namespace: 'Any' = None) -> 'int':
                return self._make_index(a, namespace=a_namespace)

        self.assertEqual(Pair.make_pair(Pair, a='Shared', b='Shared'), 1)
        self.assertEqual(Pair.make_pair(Pair, a='Shared', b='Shared', b_namespace=right), 1)

        # a real make(): ``LOW`` is a ToSDelay member but not a ToSThroughput one,
        # so ``tos_thr`` alone fails to resolve it
        ipv4 = _attr('pcapkit.protocols.internet.ipv4.IPv4')
        with self.assertRaisesRegex(exc, r"protocol 'LOW' not implemented"):
            ipv4(tos_del='LOW', tos_thr='LOW')

    def test_without_inferable_enum_still_raises(self) -> None:
        exc = _attr('pcapkit.utilities.exceptions.ProtocolNotImplemented')
        protocol = _attr('pcapkit.protocols.protocol.ProtocolBase')
        # called outside any ``make()``, so there is no argument to infer from
        with self.assertRaises(exc):
            protocol._make_index('Internet_Protocol_version_6')

        # an argument defaulting to ``None`` carries no enum to infer from, so a
        # maker that names none at the call leaves the name unresolvable
        class OptionalArgument(protocol):  # type: ignore[misc,valid-type]
            def make_optional(self, arg: 'Any' = None, arg_namespace: 'Any' = None) -> 'int':
                return self._make_index(arg, namespace=arg_namespace)

        with self.assertRaises(exc):
            OptionalArgument.make_optional(OptionalArgument, arg='Internet_Protocol_version_6')


if __name__ == '__main__':
    unittest.main()
