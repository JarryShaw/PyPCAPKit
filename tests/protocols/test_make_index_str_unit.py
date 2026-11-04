# -*- coding: utf-8 -*-
"""``make()`` refuses a member name, and ``resolve_index`` resolves one.

GitHub issue #2594. The owner ruled, in review of #2593 (which closes #2489), that a
``make()`` field holding an enumeration takes the member or an :class:`int`,
resolved with the enumeration's ``get``, and that nothing inside ``make()`` turns a
:obj:`str` into a member. Each case below is a field a name could be inferred for
through the calling frame, from the argument's own default (#1210) or from an
enumeration the maker named where that default is :data:`None` (#2356). Each pins
both halves of the rule: the name is refused with
:exc:`~pcapkit.utilities.exceptions.ProtocolError`, and
:meth:`~pcapkit.protocols.protocol.ProtocolBase.resolve_index` turns it into what
``make()`` takes, building the same octets as the member and as its integer value.

:class:`TestMakeIndex` and :class:`TestResolveIndex` pin the two helpers themselves:
the range check :meth:`~pcapkit.protocols.protocol.ProtocolBase._make_index` carries
for every caller (#2617), and the keyword group taken explicitly.
:class:`TestMakePort` pins the same check on the transport ports.

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
    return _attr('pcapkit.protocols.transport.tcp.protocol.TCP')(
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


#: One ``make()`` per protocol family, each an argument whose default is a member:
#: (protocol class or builder, argument, enum class, non-default member, the
#: other keywords the maker needs).
CASES = {
    'link/ethernet': ('pcapkit.protocols.link.ethernet.protocol.Ethernet', 'type',
                      'pcapkit.const.reg.ethertype.EtherType', 'Internet_Protocol_version_6', {}),
    'link/l2tpv2': ('pcapkit.protocols.link.l2tpv2.protocol.L2TPv2', 'type',
                    'pcapkit.const.l2tp.type.Type', 'Control', {}),
    'internet/ipv4': ('pcapkit.protocols.internet.ipv4.protocol.IPv4', 'protocol',
                      'pcapkit.const.reg.transtype.TransType', 'TCP', {}),
    'transport/tcp': (_tcp_alternate_checksum, 'algorithm',
                      'pcapkit.const.tcp.checksum.Checksum', 'Checksum_16_bit_Fletcher_s_algorithm', {}),
    'application/ospf': ('pcapkit.protocols.application.ospf.protocol.OSPF', 'type',
                         'pcapkit.const.ospf.packet.Packet', 'Database_Description', {}),
    'misc/pcap': ('pcapkit.protocols.misc.pcap.header.protocol.Header', 'network',
                  'pcapkit.const.reg.linktype.LinkType', 'RAW', {}),
    # arguments defaulting to None, whose maker named the enumeration at the call
    # for a name to resolve against (#2356)
    'internet/hopopt MPL': (_ipv6_option('pcapkit.protocols.internet.hopopt.protocol.HOPOPT', 'MPL_Option'),
                            'seed_type', 'pcapkit.const.ipv6.seed_id.SeedID',
                            'SEEDID_64_BIT_UNSIGNED_INTEGER', {'seed': 5, 'seq': 7}),
    'internet/ipv6_opts MPL': (_ipv6_option('pcapkit.protocols.internet.ipv6_opts.protocol.IPv6_Opts', 'MPL_Option'),
                               'seed_type', 'pcapkit.const.ipv6.seed_id.SeedID',
                               'SEEDID_64_BIT_UNSIGNED_INTEGER', {'seed': 5, 'seq': 7}),
    'internet/hopopt SMF_DPD': (_ipv6_option('pcapkit.protocols.internet.hopopt.protocol.HOPOPT', 'SMF_DPD'),
                                'tid_type', 'pcapkit.const.ipv6.tagger_id.TaggerID',
                                'DEFAULT', {'tid': b'\x0a\x0b\x0c\x0d', 'id': b'\xaa\xbb'}),
    'internet/ipv6_opts SMF_DPD': (_ipv6_option('pcapkit.protocols.internet.ipv6_opts.protocol.IPv6_Opts', 'SMF_DPD'),
                                   'tid_type', 'pcapkit.const.ipv6.tagger_id.TaggerID',
                                   'DEFAULT', {'tid': b'\x0a\x0b\x0c\x0d', 'id': b'\xaa\xbb'}),
}


class TestMakeRefusesNames(unittest.TestCase):
    """A member name given to ``make()`` is refused; ``resolve_index`` resolves it."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_member_name_is_refused(self) -> None:
        exc = _attr('pcapkit.utilities.exceptions.ProtocolError')
        for case, (maker, arg, _, member, extra) in CASES.items():
            with self.subTest(case=case):
                build = _attr(maker) if isinstance(maker, str) else maker
                with self.assertRaises(exc):
                    build(**extra, **{arg: member})

    def test_resolved_name_matches_member_and_int(self) -> None:
        protocol = _attr('pcapkit.protocols.protocol.Protocol')
        for case, (maker, arg, enum_path, member, extra) in CASES.items():
            with self.subTest(case=case):
                build = _attr(maker) if isinstance(maker, str) else maker
                namespace = _attr(enum_path)
                value = getattr(namespace, member)

                expected = build(**extra, **{arg: value}).data
                resolved = protocol.resolve_index(member, namespace=namespace)
                self.assertIs(resolved, value)
                self.assertEqual(build(**extra, **{arg: resolved}).data, expected)
                self.assertEqual(build(**extra, **{arg: int(value)}).data, expected)
                # the member is not what the maker builds on its own
                self.assertNotEqual(build(**extra).data, expected)

    def test_http_status_name_is_refused(self) -> None:
        """``status`` defaults to :data:`None`, as a request carries none (#2356)."""
        exc = _attr('pcapkit.utilities.exceptions.ProtocolError')
        http = _attr('pcapkit.protocols.application.httpv1.protocol.HTTPv1')
        status_code = _attr('pcapkit.const.http.status_code.StatusCode')
        protocol = _attr('pcapkit.protocols.protocol.Protocol')

        with self.assertRaises(exc):
            http(status='CODE_404')
        resolved = protocol.resolve_index('CODE_404', namespace=status_code)
        self.assertEqual(http(status=resolved).data, http(status=status_code.CODE_404).data)

    def test_removed_keywords_are_refused(self) -> None:
        exc = _attr('pcapkit.utilities.exceptions.UnsupportedCall')
        ethernet = _attr('pcapkit.protocols.link.ethernet.protocol.Ethernet')
        for keyword, value in (('type_default', 0x1234), ('type_namespace', {0x1234: 'X'}),
                               ('type_reversed', True)):
            with self.subTest(keyword=keyword):
                with self.assertRaises(exc):
                    ethernet(**{keyword: value})


class TestMakeIndex(unittest.TestCase):
    """``_make_index`` resolves a member or a code, range-checked (#2594, #2617)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _raw(self) -> 'Any':
        return _attr('pcapkit.protocols.misc.raw.protocol.Raw')(b'')

    def test_member_and_code_resolve_to_the_member(self) -> None:
        transtype = _attr('pcapkit.const.reg.transtype.TransType')
        raw = self._raw()
        self.assertIs(raw._make_index(transtype.TCP, transtype, bits=8, name='protocol'), transtype.TCP)
        self.assertIs(raw._make_index(6, transtype, bits=8, name='protocol'), transtype.TCP)
        self.assertIs(raw._make_index(255, transtype, bits=8, name='protocol'), transtype(255))

    def test_a_member_of_another_enumeration_resolves_by_value(self) -> None:
        transtype = _attr('pcapkit.const.reg.transtype.TransType')
        ethertype = _attr('pcapkit.const.reg.ethertype.EtherType')
        member = ethertype.get(6)
        self.assertIs(self._raw()._make_index(member, transtype, bits=8, name='protocol'), transtype.TCP)

    def test_refusals(self) -> None:
        exc = _attr('pcapkit.utilities.exceptions.ProtocolError')
        transtype = _attr('pcapkit.const.reg.transtype.TransType')
        raw = self._raw()
        for value in ('TCP', 'tcp', b'\x06', True, False, 256, -1, 6.0, None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(exc, r'^Raw: invalid protocol: '):
                    raw._make_index(value, transtype, bits=8, name='protocol')

    def test_bool_passes_a_one_bit_field(self) -> None:
        tos_del = _attr('pcapkit.const.ipv4.tos_del.ToSDelay')
        raw = self._raw()
        self.assertIs(raw._make_index(True, tos_del, bits=1, name='delay'), tos_del(1))
        self.assertIs(raw._make_index(False, tos_del, bits=1, name='delay'), tos_del(0))

    def test_the_field_width_decides_the_refusal(self) -> None:
        # the field's ten bits decide, not StatusCode's own 0-999 range: a code
        # the field carries and the enumeration refuses comes back as the int
        exc = _attr('pcapkit.utilities.exceptions.ProtocolError')
        status_code = _attr('pcapkit.const.http.status_code.StatusCode')
        raw = self._raw()
        self.assertIs(raw._make_index(404, status_code, bits=10, name='status'), status_code.CODE_404)
        # an unassigned code resolves to the member the registry builds for it
        self.assertIsInstance(raw._make_index(999, status_code, bits=10, name='status'), status_code)
        code = raw._make_index(1023, status_code, bits=10, name='status')
        self.assertIs(type(code), int)
        self.assertEqual(code, 1023)
        with self.assertRaisesRegex(exc, r'^Raw: invalid status: 1024$'):
            raw._make_index(1024, status_code, bits=10, name='status')

    def test_a_closed_enumeration_keeps_a_code_its_field_carries(self) -> None:
        # HIP's Transport mode IDs are 0 to 3 in a 16-bit field (#2692 review)
        transport = _attr('pcapkit.const.hip.transport.Transport')
        raw = self._raw()
        with self.assertRaises(ValueError):
            transport.get(1000)
        code = raw._make_index(1000, transport, bits=16, name='mode ID')
        self.assertIs(type(code), int)
        self.assertEqual(code, 1000)

    def test_a_code_no_member_holds_is_kept(self) -> None:
        # in EtherType's range but in no member's, as an unassigned code a parse
        # keeps: it is written as given, so the capture rebuilds as it was
        ethertype = _attr('pcapkit.const.reg.ethertype.EtherType')
        raw = self._raw()
        with self.assertRaises(ValueError):
            ethertype.get(0x1234)
        code = raw._make_index(0x1234, ethertype, bits=16, name='EtherType')
        self.assertIs(type(code), int)
        self.assertEqual(code, 0x1234)

    def test_alias_prefixes_the_message(self) -> None:
        exc = _attr('pcapkit.utilities.exceptions.ProtocolError')
        transtype = _attr('pcapkit.const.reg.transtype.TransType')
        with self.assertRaisesRegex(exc, r'^IPv4: invalid protocol: 256$'):
            self._raw()._make_index(256, transtype, bits=8, name='protocol', alias='IPv4')


class TestMakePort(unittest.TestCase):
    """A port the 16-bit field cannot carry raises ``ProtocolError`` (#2594, #2617)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_port_refusals(self) -> None:
        exc = _attr('pcapkit.utilities.exceptions.ProtocolError')
        for path in ('pcapkit.protocols.transport.tcp.protocol.TCP', 'pcapkit.protocols.transport.udp.protocol.UDP'):
            protocol = _attr(path)
            for keyword in ('srcport', 'dstport'):
                for value in (1 << 16, -1, 'http', True):
                    with self.subTest(protocol=protocol.__name__, keyword=keyword, value=value):
                        with self.assertRaisesRegex(exc, rf'^{protocol.__name__}: invalid port: '):
                            protocol(**{keyword: value})

    def test_widest_port_builds(self) -> None:
        tcp = _attr('pcapkit.protocols.transport.tcp.protocol.TCP')
        self.assertEqual(tcp(srcport=0xFFFF).data[:2], b'\xff\xff')


class TestResolveIndex(unittest.TestCase):
    """``resolve_index`` takes the name, default, namespace and reversed group explicitly (#2594)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_enumeration_name(self) -> None:
        protocol = _attr('pcapkit.protocols.protocol.Protocol')
        ethertype = _attr('pcapkit.const.reg.ethertype.EtherType')
        self.assertIs(protocol.resolve_index('Address_Resolution_Protocol', namespace=ethertype),
                      ethertype.Address_Resolution_Protocol)

    def test_dict_namespace(self) -> None:
        protocol = _attr('pcapkit.protocols.protocol.Protocol')
        self.assertEqual(protocol.resolve_index('spam', namespace={99: 'spam'}), 99)
        self.assertEqual(protocol.resolve_index('spam', namespace={'spam': 99}, reversed=True), 99)

    def test_member_and_code_pass_through(self) -> None:
        protocol = _attr('pcapkit.protocols.protocol.Protocol')
        transtype = _attr('pcapkit.const.reg.transtype.TransType')
        self.assertIs(protocol.resolve_index(transtype.TCP, namespace=transtype), transtype.TCP)
        self.assertEqual(protocol.resolve_index(7, namespace=transtype), 7)

    def test_miss_falls_back_to_default(self) -> None:
        protocol = _attr('pcapkit.protocols.protocol.Protocol')
        ethertype = _attr('pcapkit.const.reg.ethertype.EtherType')
        self.assertEqual(protocol.resolve_index('No_Such_EtherType', 0x1234, namespace=ethertype), 0x1234)
        self.assertEqual(protocol.resolve_index('eggs', 7, namespace={99: 'spam'}), 7)
        self.assertEqual(protocol.resolve_index('eggs', 7, namespace=object()), 7)  # type: ignore[arg-type]

    def test_miss_without_default_raises(self) -> None:
        exc = _attr('pcapkit.utilities.exceptions.ProtocolNotImplemented')
        protocol = _attr('pcapkit.protocols.protocol.Protocol')
        ethertype = _attr('pcapkit.const.reg.ethertype.EtherType')
        for namespace in (ethertype, {99: 'spam'}, object()):
            with self.subTest(namespace=namespace):
                with self.assertRaisesRegex(exc, r"^'eggs' is not a name in "):
                    protocol.resolve_index('eggs', namespace=namespace)

    def test_inherited_by_every_protocol(self) -> None:
        ethernet = _attr('pcapkit.protocols.link.ethernet.protocol.Ethernet')
        ethertype = _attr('pcapkit.const.reg.ethertype.EtherType')
        code = ethernet.resolve_index('Address_Resolution_Protocol', namespace=ethertype)
        self.assertEqual(ethernet(type=code).data[12:14], b'\x08\x06')


if __name__ == '__main__':
    unittest.main()
