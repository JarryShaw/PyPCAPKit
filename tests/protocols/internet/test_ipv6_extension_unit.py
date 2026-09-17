from __future__ import annotations

import datetime
import importlib.util
import io
from ipaddress import ip_address
import types
import unittest
from unittest import mock

from tests._support import purge_modules, time_limit

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class DummyDict(dict):
    __getattr__ = dict.__getitem__


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPv6ExtensionUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _assert_extension_accessors_blocked(self, protocol_cls: type) -> None:
        from pcapkit.utilities.exceptions import UnsupportedCall

        inst = object.__new__(protocol_cls)
        inst._extf = True

        with self.assertRaises(UnsupportedCall):
            _ = inst.payload
        with self.assertRaises(UnsupportedCall):
            _ = inst.protocol
        with self.assertRaises(UnsupportedCall):
            _ = inst.protochain

    def test_hopopt_extension_blocks_direct_accessors(self) -> None:
        from pcapkit.protocols.internet.hopopt import HOPOPT

        self._assert_extension_accessors_blocked(HOPOPT)

    def test_ipv6_opts_extension_blocks_direct_accessors(self) -> None:
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        self._assert_extension_accessors_blocked(IPv6_Opts)

    def test_ipv6_route_extension_blocks_direct_accessors(self) -> None:
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route

        self._assert_extension_accessors_blocked(IPv6_Route)

    def test_ipv6_frag_extension_blocks_direct_accessors(self) -> None:
        from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag

        self._assert_extension_accessors_blocked(IPv6_Frag)

    def test_hopopt_register_option_warns_on_overwrite(self) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.protocols.internet.hopopt import HOPOPT

        original = HOPOPT.__dict__['__option__'][Option.Pad1]
        try:
            with mock.patch('pcapkit.protocols.internet.hopopt.warn') as warn:
                HOPOPT.register_option(Option.Pad1, 'pad')
            warn.assert_called_once()
            self.assertEqual(HOPOPT.__dict__['__option__'][Option.Pad1], 'pad')
        finally:
            HOPOPT.__dict__['__option__'][Option.Pad1] = original

    def test_ipv6_opts_register_option_warns_on_overwrite(self) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        original = IPv6_Opts.__dict__['__option__'][Option.Pad1]
        try:
            with mock.patch('pcapkit.protocols.internet.ipv6_opts.warn') as warn:
                IPv6_Opts.register_option(Option.Pad1, 'pad')
            warn.assert_called_once()
            self.assertEqual(IPv6_Opts.__dict__['__option__'][Option.Pad1], 'pad')
        finally:
            IPv6_Opts.__dict__['__option__'][Option.Pad1] = original

    def test_ipv6_route_register_routing_warns_on_overwrite(self) -> None:
        from pcapkit.const.ipv6.routing import Routing
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route

        original = IPv6_Route.__dict__['__routing__'][Routing.Source_Route]
        try:
            with mock.patch('pcapkit.protocols.internet.ipv6_route.warn') as warn:
                IPv6_Route.register_routing(Routing.Source_Route, 'src')
            warn.assert_called_once()
            self.assertEqual(IPv6_Route.__dict__['__routing__'][Routing.Source_Route], 'src')
        finally:
            IPv6_Route.__dict__['__routing__'][Routing.Source_Route] = original

    def test_ipv6_frag_index_length_and_make_data(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag

        data = DummyDict(
            next=TransType.TCP,
            offset=16,
            mf=True,
            id=99,
            __next_type__=None,
        )
        proto = object.__new__(IPv6_Frag)

        self.assertEqual(IPv6_Frag.__index__(), TransType.IPv6_Frag)
        self.assertEqual(proto.__length_hint__(), 8)
        values = IPv6_Frag._make_data(data)
        self.assertEqual(values['next'], TransType.TCP)
        # ``data.offset`` is in octets while ``make`` takes on-wire 8-octet units,
        # so 16 octets is written back as 2 units
        self.assertEqual(values['offset'], 2)
        self.assertEqual(values['mf'], True)
        self.assertEqual(values['id'], 99)
        self.assertIn('payload', values)

    def test_hopopt_index_length_and_make_data(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.hopopt import HOPOPT

        options = ['pad']
        data = DummyDict(next=TransType.UDP, options=options, __next_type__=None)
        proto = object.__new__(HOPOPT)

        self.assertEqual(HOPOPT.__index__(), TransType.HOPOPT)
        self.assertEqual(proto.__length_hint__(), 2)
        values = HOPOPT._make_data(data)
        self.assertEqual(values['next'], TransType.UDP)
        self.assertEqual(values['options'], options)
        self.assertIn('payload', values)

    def test_ipv6_opts_index_length_and_make_data(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        options = ['pad']
        data = DummyDict(next=TransType.UDP, options=options, __next_type__=None)
        proto = object.__new__(IPv6_Opts)

        self.assertEqual(IPv6_Opts.__index__(), TransType.IPv6_Opts)
        self.assertEqual(proto.__length_hint__(), 2)
        values = IPv6_Opts._make_data(data)
        self.assertEqual(values['next'], TransType.UDP)
        self.assertEqual(values['options'], options)
        self.assertIn('payload', values)

    def test_ipv6_route_index_length_and_make_data(self) -> None:
        from pcapkit.const.ipv6.routing import Routing
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route

        data = DummyDict(
            next=TransType.UDP,
            type=Routing.Source_Route,
            seg_left=1,
            length=24,
            __next_type__=None,
        )
        proto = object.__new__(IPv6_Route)
        proto._info = data

        self.assertEqual(IPv6_Route.__index__(), TransType.IPv6_Route)
        self.assertEqual(proto.__length_hint__(), 4)
        self.assertEqual(proto.length, 24)
        values = IPv6_Route._make_data(data)
        self.assertEqual(values['next'], TransType.UDP)
        self.assertEqual(values['type'], Routing.Source_Route)
        self.assertEqual(values['seg_left'], 1)
        self.assertIs(values['data'], data)
        self.assertIn('payload', values)

    def test_ipv6_frag_read_make_and_properties(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag
        from pcapkit.protocols.schema.internet.ipv6_frag import IPv6_Frag as Schema_IPv6_Frag

        proto = object.__new__(IPv6_Frag)
        proto.__header__ = Schema_IPv6_Frag(
            next=TransType.TCP,
            flags={'offset': 12, 'mf': 1},
            id=0x12345678,
            payload=b'data',
        )
        proto._data = b'\x00' * 12
        proto.__cached__ = {}
        proto._extf = False
        proto._next = 'payload'
        proto._protos = ['TCP']

        self.assertEqual(proto.name, 'Fragment Header for IPv6')
        self.assertEqual(proto.alias, 'IPv6-Frag')
        self.assertEqual(proto.length, 8)
        self.assertEqual(proto.payload, 'payload')
        self.assertEqual(proto.protocol, 'TCP')
        self.assertEqual(proto.protochain, ['TCP'])
        data = proto.read(extension=True)
        self.assertEqual(data.next, TransType.TCP)
        # the schema's ``offset`` is the raw 13-bit on-wire field, a count of
        # 8-octet units (:rfc:`8200#section-4.5`); ``Data_IPv6_Frag.offset`` is in
        # octets, like ``Data_IPv4.offset``, so 12 units becomes 96 octets
        self.assertEqual(proto.__header__.flags['offset'], 12)
        self.assertEqual(data.offset, 96)
        self.assertTrue(data.mf)
        self.assertEqual(data.id, 0x12345678)
        # ``_make_data`` must undo the scaling, so that data -> make round trips
        self.assertEqual(IPv6_Frag._make_data(data)['offset'], 12)

        with mock.patch.object(IPv6_Frag, '_decode_next_layer', return_value='decoded') as decode:
            self.assertEqual(proto.read(length=12), 'decoded')
        decode.assert_called_once()

        schema = proto.make(next=TransType.UDP, offset=2, mf=True, id=7, payload=b'udp')
        self.assertEqual(schema.next, TransType.UDP)
        self.assertEqual(schema.flags['offset'], 2)
        self.assertTrue(schema.flags['mf'])
        self.assertEqual(schema.id, 7)

        with mock.patch.object(Internet, '__post_init__', return_value=None) as post_init:
            post_proto = object.__new__(IPv6_Frag)
            post_proto.__post_init__(extension=True, custom=True)
        self.assertTrue(post_proto._extf)
        post_init.assert_called_once()

    def test_ipv6_route_readers_and_constructors_cover_registered_types(self) -> None:
        from pcapkit.const.ipv6.routing import Routing
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.data.internet import ipv6_route as route_data
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route
        from pcapkit.protocols.schema.internet import ipv6_route as route_schema
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(IPv6_Route)
        route_type = Routing.get(250)
        header = types.SimpleNamespace(next=TransType.TCP, length=1, type=route_type, seg_left=0)

        unknown = proto._read_data_type_none(route_schema.UnknownType(data=b'abcd'), header=header)
        self.assertEqual(unknown.data, b'abcd')
        self.assertEqual(unknown.length, 16)

        src_header = types.SimpleNamespace(next=TransType.TCP, length=24,
                                           type=Routing.Source_Route, seg_left=1)
        src = proto._read_data_type_src(
            route_schema.SourceRoute(ip=['2001:db8::1']),
            header=src_header,
        )
        self.assertEqual(str(src.ip[0]), '2001:db8::1')
        with self.assertRaises(ProtocolError):
            proto._read_data_type_src(route_schema.SourceRoute(ip=[]), header=header)

        type2_header = types.SimpleNamespace(next=TransType.TCP, length=24,
                                             type=Routing.Type_2_Routing_Header, seg_left=1)
        type2 = proto._read_data_type_2(route_schema.Type2(ip='2001:db8::2'), header=type2_header)
        self.assertEqual(str(type2.ip), '2001:db8::2')
        with self.assertRaises(ProtocolError):
            proto._read_data_type_2(route_schema.Type2(ip='2001:db8::2'), header=header)

        rpl_schema = route_schema.RPL(cmpr_i=0, cmpr_e=0, pad={'pad_len': 0}, addresses=[])
        object.__setattr__(rpl_schema, 'ip', (ip_address('2001:db8::3'),))
        rpl_header = types.SimpleNamespace(next=TransType.TCP, length=16,
                                           type=Routing.RPL_Source_Route_Header, seg_left=1)
        rpl = proto._read_data_type_rpl(rpl_schema, header=rpl_header)
        self.assertEqual(str(rpl.ip[0]), '2001:db8::3')
        with self.assertRaises(ProtocolError):
            proto._read_data_type_rpl(rpl_schema, header=header)

        self.assertEqual(proto._make_data_type_none(route_type, data=b'ab').data, b'ab\x00\x00')
        self.assertEqual(proto._make_data_type_none(
            route_type,
            route_data.UnknownType(next=TransType.TCP, length=16, type=route_type, seg_left=0, data=b'xy'),
        ).data, b'xy\x00\x00')
        self.assertEqual(str(proto._make_data_type_src(
            Routing.Source_Route,
            ip=['2001:db8::4'],
        ).ip[0]), '2001:db8::4')
        self.assertEqual(str(proto._make_data_type_src(
            Routing.Source_Route,
            route_data.SourceRoute(next=TransType.TCP, length=24, type=Routing.Source_Route,
                                   seg_left=1, ip=(ip_address('2001:db8::5'),)),
        ).ip[0]), '2001:db8::5')
        self.assertEqual(str(proto._make_data_type_2(
            Routing.Type_2_Routing_Header,
            ip='2001:db8::6',
        ).ip), '2001:db8::6')
        self.assertEqual(str(proto._make_data_type_2(
            Routing.Type_2_Routing_Header,
            route_data.Type2(next=TransType.TCP, length=24, type=Routing.Type_2_Routing_Header,
                             seg_left=1, ip=ip_address('2001:db8::7')),
        ).ip), '2001:db8::7')

        rpl_plain = proto._make_data_type_rpl(
            Routing.RPL_Source_Route_Header,
            ip=['2001:db8::8'],
        )
        self.assertEqual(rpl_plain.cmpr_i, 0)
        rpl_compressed = proto._make_data_type_rpl(
            Routing.RPL_Source_Route_Header,
            dst=ip_address('2001:db8::ffff'),
            ip=['2001:db8::1', '2001:db8::2'],
        )
        self.assertGreaterEqual(rpl_compressed.cmpr_i, 0)
        rpl_from_data = proto._make_data_type_rpl(
            Routing.RPL_Source_Route_Header,
            route_data.RPL(next=TransType.TCP, length=16, type=Routing.RPL_Source_Route_Header,
                           seg_left=1, cmpr_i=1, cmpr_e=2, pad=0,
                           ip=(ip_address('2001:db8::9'),)),
        )
        self.assertEqual(rpl_from_data.cmpr_i, 1)

    def test_ipv6_route_read_make_registry_and_property_edges(self) -> None:
        from pcapkit.const.ipv6.routing import Routing
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.data.internet import ipv6_route as route_data
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.internet.ipv6_route import IPv6_Route
        from pcapkit.protocols.schema.internet import ipv6_route as route_schema
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(IPv6_Route)
        proto._info = DummyDict(length=24)
        proto._extf = False
        proto._next = 'payload'
        proto._protos = ['TCP']

        self.assertEqual(proto.name, 'Routing Header for IPv6')
        self.assertEqual(proto.alias, 'IPv6-Route')
        self.assertEqual(proto.length, 24)
        self.assertEqual(proto.payload, 'payload')
        self.assertEqual(proto.protocol, 'TCP')
        self.assertEqual(proto.protochain, ['TCP'])

        proto.__header__ = route_schema.IPv6_Route(
            next=TransType.TCP,
            length=24,
            type=Routing.Source_Route,
            seg_left=1,
            data=route_schema.SourceRoute(ip=['2001:db8::1']),
            payload=b'data',
        )
        proto._data = b'\x00' * 208
        proto.__cached__ = {}
        route = proto.read(extension=True)
        self.assertEqual(route.next, TransType.TCP)
        self.assertEqual(route.type, Routing.Source_Route)
        self.assertEqual(str(route.ip[0]), '2001:db8::1')
        with mock.patch.object(IPv6_Route, '_decode_next_layer', return_value='decoded') as decode:
            self.assertEqual(proto.read(length=208), 'decoded')
        decode.assert_called_once()

        made_bytes = proto.make(type=Routing.Source_Route, data=b'abcd')
        self.assertEqual(made_bytes.length, 1)
        self.assertEqual(made_bytes.data, b'abcd')
        made_dict = proto.make(type=Routing.Source_Route, data={'ip': ['2001:db8::2']})
        self.assertEqual(made_dict.type, Routing.Source_Route)
        made_model = proto.make(
            type=Routing.Type_2_Routing_Header,
            data=route_data.Type2(next=TransType.TCP, length=24,
                                  type=Routing.Type_2_Routing_Header,
                                  seg_left=1,
                                  ip=ip_address('2001:db8::3')),
        )
        self.assertEqual(made_model.type, Routing.Type_2_Routing_Header)
        made_schema = proto.make(
            type=Routing.Type_2_Routing_Header,
            data=route_schema.Type2(ip='2001:db8::4'),
        )
        self.assertEqual(made_schema.length, 3)
        with self.assertRaises(ProtocolError):
            proto.make(data=object())

        route_type = Routing.get(251)
        routing_map = IPv6_Route.__dict__['__routing__']
        original = routing_map.get(route_type)

        def parse_route(packet: types.SimpleNamespace, *,
                        header: types.SimpleNamespace) -> route_data.UnknownType:
            return route_data.UnknownType(next=header.next, length=8,
                                          type=header.type, seg_left=header.seg_left,
                                          data=packet.data)

        def make_route(type_: Routing, route: route_data.UnknownType | None = None, *,
                       dst: object = None, value: bytes = b'') -> route_schema.Type2:
            return route_schema.Type2(ip='2001:db8::5')

        try:
            IPv6_Route.register_routing(route_type, (parse_route, make_route))
            proto.__header__ = types.SimpleNamespace(
                next=TransType.UDP,
                length=1,
                type=route_type,
                seg_left=0,
                data=types.SimpleNamespace(data=b'custom'),
            )
            self.assertEqual(proto.read(extension=True).data, b'custom')
            self.assertEqual(proto.make(type=route_type, data={'value': b'custom'}).type, route_type)
        finally:
            if original is None:
                routing_map.pop(route_type, None)
            else:
                routing_map[route_type] = original

        self.assertEqual(proto._make_data_type_none(Routing.get(252), data=b'abcd').data, b'abcd')
        rpl_bytes = proto._make_data_type_rpl(
            Routing.RPL_Source_Route_Header,
            dst=ip_address('2001:db8::ffff'),
            ip=[
                ip_address('2001:db8::1').packed,
                ip_address('2001:db8::2').packed,
            ],
        )
        self.assertGreaterEqual(rpl_bytes.cmpr_i, 0)
        self.assertGreaterEqual(rpl_bytes.cmpr_e, 0)

        with mock.patch.object(Internet, '__post_init__', return_value=None) as post_init:
            post_proto = object.__new__(IPv6_Route)
            post_proto.__post_init__(extension=True, custom=True)
        self.assertTrue(post_proto._extf)
        post_init.assert_called_once()

    def _assert_option_header_read_make_and_registry_edges(self, protocol_cls: type) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.schema.internet import hopopt as hopopt_schema
        from pcapkit.protocols.schema.internet import ipv6_opts as opts_schema
        from pcapkit.utilities.exceptions import ProtocolError

        schema = hopopt_schema if protocol_cls.__name__ == 'HOPOPT' else opts_schema
        header_cls = getattr(schema, protocol_cls.__name__)
        read_options = '_read_hopopt_options' if protocol_cls.__name__ == 'HOPOPT' else '_read_ipv6_opts'
        make_options = '_make_hopopt_options' if protocol_cls.__name__ == 'HOPOPT' else '_make_ipv6_opts'
        expected_name = ('IPv6 Hop-by-Hop Options' if protocol_cls.__name__ == 'HOPOPT'
                         else 'Destination Options for IPv6')

        proto = object.__new__(protocol_cls)
        proto._info = DummyDict(length=8)
        proto._extf = False
        proto._next = 'payload'
        proto._protos = ['UDP']

        self.assertEqual(proto.name, expected_name)
        if protocol_cls.__name__ == 'IPv6_Opts':
            self.assertEqual(proto.alias, 'IPv6-Opts')
        self.assertEqual(proto.length, 8)
        self.assertEqual(proto.payload, 'payload')
        self.assertEqual(proto.protocol, 'UDP')
        self.assertEqual(proto.protochain, ['UDP'])

        proto.__header__ = header_cls(
            next=TransType.UDP,
            len=0,
            options=[],
            payload=b'data',
        )
        proto._data = b'\x00' * 8
        proto.__cached__ = {}
        empty_options = OrderedMultiDict()
        with mock.patch.object(proto, read_options, return_value=empty_options) as reader:
            ext_data = proto.read(extension=True)
        reader.assert_called_once_with(6)
        self.assertEqual(ext_data.next, TransType.UDP)
        self.assertEqual(ext_data.length, 8)
        self.assertIs(ext_data.options, empty_options)

        with mock.patch.object(proto, read_options, return_value=empty_options):
            with mock.patch.object(protocol_cls, '_decode_next_layer', return_value='decoded') as decode:
                self.assertEqual(proto.read(length=8), 'decoded')
        decode.assert_called_once()

        # NOTE: "No options" is not the same as "no options area". The header is at
        # least (0 + 1) * 8 = 8 octets and 2 of those are the fixed part, so the
        # remaining 6 have to be padding options -- an empty options list is not a
        # thing that can go on the wire, and asserting for one here used to pass
        # only because ``make`` emitted a 2-octet header while declaring 8.
        made_empty = proto.make(next=TransType.TCP)
        self.assertEqual(made_empty.next, TransType.TCP)
        self.assertEqual(made_empty.len, 0)
        self.assertEqual([type(item).__name__ for item in made_empty.options], ['PadOption'])
        self.assertEqual(len(bytes(made_empty)), 8)

        made_with_option = proto.make(
            next=TransType.UDP,
            options=[(Option.Tunnel_Encapsulation_Limit, {'limit': 1})],
        )
        self.assertEqual(made_with_option.next, TransType.UDP)
        self.assertGreaterEqual(made_with_option.len, 0)
        self.assertGreater(len(made_with_option.options), 0)

        custom = Option.get(250)
        option_map = protocol_cls.__dict__['__option__']
        original = option_map.get(custom)

        def parse_option(packet: types.SimpleNamespace, *,
                         options: OrderedMultiDict) -> types.SimpleNamespace:
            return types.SimpleNamespace(type=packet.type, data=packet.data)

        def make_option(code: Option, opt: object = None, *,
                        value: bytes = b'') -> object:
            if opt is not None:
                value = opt.data
            return schema.UnassignedOption(type=code, len=len(value), data=value)

        try:
            protocol_cls.register_option(custom, (parse_option, make_option))
            proto.__header__ = types.SimpleNamespace(
                options=[
                    schema.UnassignedOption(type=custom, len=2, data=b'xx'),
                ],
            )
            parsed = getattr(proto, read_options)(4)
            self.assertEqual(parsed[custom].data, b'xx')
            with self.assertRaises(ProtocolError):
                getattr(proto, read_options)(5)

            made_list, list_len = getattr(proto, make_options)([
                (custom, {'value': b'yy'}),
            ])
            self.assertEqual(made_list[0].data, b'yy')
            self.assertGreaterEqual(list_len, 4)

            option_dict = OrderedMultiDict([
                (custom, types.SimpleNamespace(data=b'zz')),
            ])
            made_dict, dict_len = getattr(proto, make_options)(option_dict)
            self.assertEqual(made_dict[0].data, b'zz')
            self.assertGreaterEqual(dict_len, 4)
        finally:
            if original is None:
                option_map.pop(custom, None)
            else:
                option_map[custom] = original

        with mock.patch.object(Internet, '__post_init__', return_value=None) as post_init:
            post_proto = object.__new__(protocol_cls)
            post_proto.__post_init__(extension=True, custom=True)
        self.assertTrue(post_proto._extf)
        post_init.assert_called_once()

    def test_hopopt_read_make_registry_and_property_edges(self) -> None:
        from pcapkit.protocols.internet.hopopt import HOPOPT

        self._assert_option_header_read_make_and_registry_edges(HOPOPT)

    def test_ipv6_opts_read_make_registry_and_property_edges(self) -> None:
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        self._assert_option_header_read_make_and_registry_edges(IPv6_Opts)

    def _assert_option_data_model_constructor_edges(self, protocol_cls: type) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.const.ipv6.qs_function import QSFunction
        from pcapkit.const.ipv6.router_alert import RouterAlert
        from pcapkit.const.ipv6.seed_id import SeedID
        from pcapkit.const.ipv6.smf_dpd_mode import SMFDPDMode
        from pcapkit.const.ipv6.tagger_id import TaggerID
        from pcapkit.protocols.data.internet import hopopt as hopopt_data
        from pcapkit.protocols.data.internet import ipv6_opts as opts_data
        from pcapkit.utilities.exceptions import ProtocolError

        data = hopopt_data if protocol_cls.__name__ == 'HOPOPT' else opts_data
        proto = object.__new__(protocol_cls)
        base = {
            'action': 0,
            'change': False,
        }

        self.assertEqual(proto._make_opt_none(
            Option.get(250),
            data.UnassignedOption(type=Option.get(250), length=4, data=b'data', **base),
        ).data, b'data')
        self.assertEqual(proto._make_opt_tun(
            Option.Tunnel_Encapsulation_Limit,
            data.TunnelEncapsulationLimitOption(type=Option.Tunnel_Encapsulation_Limit,
                                                length=3, limit=9, **base),
        ).limit, 9)
        self.assertEqual(proto._make_opt_ra(
            Option.Router_Alert,
            data.RouterAlertOption(type=Option.Router_Alert, length=4,
                                   value=RouterAlert.Datagram_contains_a_Multicast_Listener_Discovery_message,
                                   **base),
        ).alert, RouterAlert.Datagram_contains_a_Multicast_Listener_Discovery_message)

        calipso = data.CALIPSOOption(type=Option.CALIPSO, length=10, domain=7,
                                     cmpt_len=4, level=3, checksum=b'\x01\x02',
                                     **base)
        calipso.__update__([('cmpt_bitmap', b'\xaa')])
        self.assertEqual(proto._make_opt_calipso(Option.CALIPSO, calipso).bitmap, b'\xaa')

        smf_ident = data.SMFIdentificationBasedDPDOption(
            type=Option.SMF_DPD,
            length=4,
            dpd_type=SMFDPDMode.I_DPD,
            tid_type=TaggerID.NULL,
            tid_len=0,
            tid=None,
            id=b'id',
            **base,
        )
        self.assertEqual(proto._make_opt_smf_dpd(Option.SMF_DPD, smf_ident).id, b'id')
        self.assertEqual(proto._make_opt_smf_dpd(
            Option.SMF_DPD,
            mode=SMFDPDMode.I_DPD,
            tid=b'abcde',
            id=b'id',
        ).info['type'], TaggerID.DEFAULT)
        self.assertEqual(proto._make_opt_smf_dpd(
            Option.SMF_DPD,
            mode=SMFDPDMode.I_DPD,
            tid=b'',
            id=b'id',
        ).info['type'], TaggerID.NULL)
        with self.assertRaises(ProtocolError):
            proto._make_opt_smf_dpd(Option.SMF_DPD, mode=2)

        with mock.patch(f'{protocol_cls.__module__}.warn') as warn:
            pdm = proto._make_opt_pdm(
                Option.PDM,
                data.PDMOption(type=Option.PDM, length=12, scaledtlr=0,
                               scaledtls=0, psntp=1, psnlr=2,
                               deltatlr=1 << 300, deltatls=1 << 301,
                               **base),
            )
        self.assertGreater(pdm.scaledtlr, 0)
        self.assertEqual(warn.call_count, 2)

        qs_req = proto._make_opt_qs(
            Option.Quick_Start,
            data.QuickStartRequestOption(type=Option.Quick_Start,
                                         length=8,
                                         func=QSFunction.Quick_Start_Request,
                                         rate=80,
                                         ttl=datetime.timedelta(seconds=5),
                                         nonce=3,
                                         **base),
        )
        self.assertEqual(qs_req.ttl, 5)
        self.assertEqual(proto._make_opt_qs(
            Option.Quick_Start,
            data.QuickStartReportOption(type=Option.Quick_Start,
                                        length=8,
                                        func=QSFunction.Report_of_Approved_Rate,
                                        rate=80,
                                        nonce=4,
                                        **base),
        ).nonce['nonce'], 4)
        with self.assertRaises(ProtocolError):
            proto._make_opt_qs(Option.Quick_Start, func=1)

        rpl = proto._make_opt_rpl(
            Option.RPL_Option_0x63,
            data.RPLOption(type=Option.RPL_Option_0x63, length=6,
                           flags=data.RPLFlags(down=True, rank_err=True, fwd_err=False),
                           id=5, rank=6, **base),
        )
        self.assertTrue(rpl.flags['down'])
        mpl = proto._make_opt_mpl(
            Option.MPL_Option,
            data.MPLOption(type=Option.MPL_Option, length=4,
                           seed_type=SeedID.SEEDID_16_BIT_UNSIGNED_INTEGER,
                           flags=data.MPLFlags(max=True, drop=False),
                           seq=7, seed_id=8, **base),
        )
        self.assertEqual(mpl.seed, 8)
        self.assertEqual(proto._make_opt_ilnp(
            Option.ILNP_Nonce,
            data.ILNPOption(type=Option.ILNP_Nonce, length=10, nonce=9, **base),
        ).nonce, 9)
        self.assertEqual(proto._make_opt_lio(
            Option.Line_Identification_Option,
            data.LineIdentificationOption(type=Option.Line_Identification_Option,
                                          length=5, line_id_len=3,
                                          line_id=b'abc', **base),
        ).id, b'abc')
        self.assertEqual(proto._make_opt_jumbo(
            Option.Jumbo_Payload,
            data.JumboPayloadOption(type=Option.Jumbo_Payload, length=6,
                                    jumbo_len=9000, **base),
        ).jumbo_len, 9000)
        self.assertEqual(str(proto._make_opt_home(
            Option.Home_Address,
            data.HomeAddressOption(type=Option.Home_Address, length=18,
                                   address=ip_address('2001:db8::1'), **base),
        ).addr), '2001:db8::1')
        self.assertTrue(proto._make_opt_ip_dff(
            Option.IP_DFF,
            data.IPDFFOption(type=Option.IP_DFF, length=4, version=1,
                             flags=data.DFFFlags(dup=True, ret=False),
                             seq=10, **base),
        ).flags['dup'])

    def test_hopopt_data_model_constructors_cover_existing_options(self) -> None:
        from pcapkit.protocols.internet.hopopt import HOPOPT

        self._assert_option_data_model_constructor_edges(HOPOPT)

    def test_ipv6_opts_data_model_constructors_cover_existing_options(self) -> None:
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        self._assert_option_data_model_constructor_edges(IPv6_Opts)

    def _assert_option_constructors_cover_branchy_values(self, protocol_cls: type) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.const.ipv6.qs_function import QSFunction
        from pcapkit.const.ipv6.router_alert import RouterAlert
        from pcapkit.const.ipv6.smf_dpd_mode import SMFDPDMode
        from pcapkit.const.ipv6.tagger_id import TaggerID
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.data.internet import hopopt as hopopt_data
        from pcapkit.protocols.data.internet import ipv6_opts as opts_data
        from pcapkit.protocols.schema.internet import hopopt as hopopt_schema
        from pcapkit.protocols.schema.internet import ipv6_opts as opts_schema
        from pcapkit.utilities.exceptions import ProtocolError

        data = hopopt_data if protocol_cls.__name__ == 'HOPOPT' else opts_data
        schema = hopopt_schema if protocol_cls.__name__ == 'HOPOPT' else opts_schema
        proto = object.__new__(protocol_cls)
        base = {'action': 0, 'change': False}

        calipso = proto._make_opt_calipso(Option.CALIPSO, domain=1, level=2,
                                          checksum=b'\x01\x02', bitmap=b'\xaa\xbb')
        self.assertEqual(calipso.to_dict()['len'], 10)
        self.assertEqual(calipso.to_dict()['cmpt_len'], 2)
        self.assertEqual(calipso.to_dict()['bitmap'], b'\xaa\xbb')

        with mock.patch(f'{protocol_cls.__module__}.warn') as warn:
            self.assertEqual(proto._make_opt_pad(Option.Pad1, length=1).to_dict()['type'], Option.PadN)
            self.assertEqual(proto._make_opt_pad(Option.PadN, length=0).to_dict()['type'], Option.Pad1)
        self.assertEqual(warn.call_count, 2)

        ident = proto._make_opt_smf_dpd(Option.SMF_DPD, mode=SMFDPDMode.I_DPD,
                                        tid=ip_address('192.0.2.1'), id=b'id')
        self.assertEqual(ident.to_dict()['info']['type'], TaggerID.IPv4)
        self.assertEqual(ident.to_dict()['tid'], b'\xc0\x00\x02\x01')
        self.assertEqual(ident.to_dict()['id'], b'id')
        self.assertEqual(proto._make_opt_smf_dpd(
            Option.SMF_DPD,
            mode=SMFDPDMode.I_DPD,
            tid=ip_address('192.0.2.2').packed,
            id=b'id',
        ).to_dict()['info']['type'], TaggerID.IPv4)
        self.assertEqual(proto._make_opt_smf_dpd(
            Option.SMF_DPD,
            mode=SMFDPDMode.I_DPD,
            tid=ip_address('2001:db8::1').packed,
            id=b'id',
        ).to_dict()['info']['type'], TaggerID.IPv6)
        self.assertEqual(proto._make_opt_smf_dpd(
            Option.SMF_DPD,
            mode=SMFDPDMode.I_DPD,
            tid=ip_address('2001:db8::2'),
            id=b'id',
        ).to_dict()['info']['type'], TaggerID.IPv6)
        with mock.patch(f'{protocol_cls.__module__}.ipaddress.ip_address',
                        return_value=types.SimpleNamespace(version=5)):
            self.assertEqual(proto._make_opt_smf_dpd(
                Option.SMF_DPD,
                mode=SMFDPDMode.I_DPD,
                tid=b'\x01',
                id=b'id',
            ).to_dict()['info']['type'], TaggerID.DEFAULT)
        with self.assertRaises(ProtocolError):
            proto._make_opt_smf_dpd(
                Option.SMF_DPD,
                mode=SMFDPDMode.I_DPD,
                tid=types.SimpleNamespace(version=5),
                id=b'id',
            )

        hashed = proto._make_opt_smf_dpd(Option.SMF_DPD, mode=SMFDPDMode.H_DPD, hav=b'\x01\x02\x03')
        self.assertEqual(hashed.to_dict()['hav'], b'\x81\x02\x03')

        mpl_cases = [
            (None, 2),
            (0xffff, 4),
            (0xffffffffffffffff, 10),
            (0xffffffffffffffffffffffffffffffff, 18),
        ]
        for seed, length in mpl_cases:
            self.assertEqual(proto._make_opt_mpl(Option.MPL_Option, seed=seed).to_dict()['len'], length)

        with self.assertRaises(ProtocolError):
            proto._make_opt_mpl(Option.MPL_Option, seed=1 << 128)

        report = proto._make_opt_qs(Option.Quick_Start, func=QSFunction.Report_of_Approved_Rate,
                                    rate=80, nonce=7)
        self.assertEqual(report.to_dict()['flags']['func'], QSFunction.Report_of_Approved_Rate)
        self.assertEqual(report.to_dict()['flags']['rate'], 1)
        self.assertEqual(report.to_dict()['nonce']['nonce'], 7)

        make_options = (proto._make_hopopt_options if hasattr(proto, '_make_hopopt_options')
                        else proto._make_ipv6_opts)

        self.assertEqual(proto._make_opt_none(Option.get(251), data=b'raw').data, b'raw')
        self.assertEqual(proto._make_opt_ra(
            Option.Router_Alert,
            alert=RouterAlert.Datagram_contains_RSVP_message,
        ).alert, RouterAlert.Datagram_contains_RSVP_message)
        with mock.patch(f'{protocol_cls.__module__}.warn') as warn:
            pdm = proto._make_opt_pdm(Option.PDM, psntp=1, psnlr=2,
                                      deltatlr=32, deltatls=64)
        self.assertEqual(pdm.scaledtlr, 0)
        self.assertEqual(warn.call_count, 0)
        self.assertTrue(proto._make_opt_rpl(
            Option.RPL_Option_0x63,
            down=True,
            rank_err=True,
            fwd_err=False,
            id=1,
            rank=2,
        ).flags['down'])
        self.assertEqual(proto._make_opt_ilnp(Option.ILNP_Nonce, nonce=9).nonce, 9)
        self.assertEqual(proto._make_opt_lio(
            Option.Line_Identification_Option,
            id=b'line',
        ).id, b'line')
        self.assertEqual(proto._make_opt_jumbo(Option.Jumbo_Payload, len=123456).jumbo_len, 123456)
        self.assertEqual(str(proto._make_opt_home(
            Option.Home_Address,
            addr=ip_address('2001:db8::3'),
        ).addr), '2001:db8::3')
        self.assertTrue(proto._make_opt_ip_dff(
            Option.IP_DFF,
            version=1,
            dup=True,
            ret=False,
            seq=3,
        ).flags['dup'])

        # NOTE: The lengths below are the length of the *options area*, and the two
        # octets of the fixed header precede it, so a well-formed options area is 6
        # octets short of a multiple of 8 -- never a multiple of 8 itself. Each
        # assertion is followed by the octet count that justifies it, since these
        # numbers used to be 6 too large (or to account padding that was emitted two
        # octets longer than it was counted as).

        options, total_length = make_options([
            b'\x00',
            bytes([Option.CALIPSO]) + b'123456789',
        ])
        # 10 octets of CALIPSO + a 4-octet PadN = 14; 2 + 14 = 16 = 2 * 8
        self.assertEqual(total_length, 14)
        self.assertEqual([type(item).__name__ if not isinstance(item, bytes) else 'bytes' for item in options],
                         ['bytes', 'PadOption'])
        schema_options, schema_length = make_options([
            schema.UnassignedOption(type=Option.get(252), len=6, data=b'abcdef'),
            schema.PadOption(type=Option.Pad1, len=0),
            (Option.PadN, {}),
        ])
        # the 8-octet option + a 6-octet PadN = 14; 2 + 14 = 16 = 2 * 8
        self.assertEqual(schema_length, 14)
        self.assertEqual(type(schema_options[0]).__name__, 'UnassignedOption')

        # NOTE: Two ``Pad1`` options are emitted when the shortfall is exactly 2
        # octets, i.e. when ``2 + opt_len`` is 6 past a multiple of 8. That is a
        # 4-octet option, not the 6-octet one this case used to pass -- 2 + 6 is
        # already aligned and now needs no padding at all.
        pad1_options, pad1_length = make_options([
            bytes([Option.CALIPSO]) + b'123',
        ])
        # 4 octets of CALIPSO + two 1-octet Pad1 = 6; 2 + 6 = 8
        self.assertEqual(pad1_length, 6)
        self.assertEqual([type(item).__name__ if not isinstance(item, bytes) else 'bytes'
                          for item in pad1_options], ['bytes', 'PadOption', 'PadOption'])

        # NOTE: Likewise, the option that needs no padding is the 6-octet one; the
        # 8-octet option this case used to pass leaves 2 + 8 = 10 and now draws 6
        # octets of padding.
        no_pad_options, no_pad_length = make_options([
            bytes([Option.CALIPSO]) + b'12345',
        ])
        # 6 octets of CALIPSO, nothing else; 2 + 6 = 8
        self.assertEqual(no_pad_length, 6)
        self.assertEqual(no_pad_options, [bytes([Option.CALIPSO]) + b'12345'])

        dict_options, dict_length = make_options(OrderedMultiDict([
            (Option.Pad1, data.PadOption(type=Option.Pad1, length=1, **base)),
            (Option.Tunnel_Encapsulation_Limit,
             data.TunnelEncapsulationLimitOption(type=Option.Tunnel_Encapsulation_Limit,
                                                 length=3, limit=3, **base)),
            (Option.get(253), data.UnassignedOption(type=Option.get(253),
                                                    length=8, data=b'abcdef', **base)),
            (Option.get(254), data.UnassignedOption(type=Option.get(254),
                                                    length=6, data=b'abcd', **base)),
        ]))
        # 3 (tun) + 3 (PadN) + 8 + 6 + 1 + 1 (two Pad1) = 22; 2 + 22 = 24 = 3 * 8
        self.assertEqual(dict_length, 22)
        self.assertEqual(type(dict_options[0]).__name__, 'TunnelEncapsulationLimitOption')
        self.assertEqual(type(dict_options[-3]).__name__, 'UnassignedOption')

        # every options area the constructor produces has to leave the whole header
        # a multiple of 8 octets long, and to account for exactly what it emitted
        for label, (built, built_len) in {
                'bytes + padn': (options, total_length),
                'schema + padn': (schema_options, schema_length),
                'two pad1': (pad1_options, pad1_length),
                'no padding': (no_pad_options, no_pad_length),
                'from dict': (dict_options, dict_length),
        }.items():
            with self.subTest(options=label):
                emitted = b''.join(item if isinstance(item, bytes) else item.pack()
                                   for item in built)
                self.assertEqual(len(emitted), built_len)
                self.assertEqual((built_len + 2) % 8, 0)

    def test_hopopt_option_constructors_cover_branchy_values(self) -> None:
        from pcapkit.protocols.internet.hopopt import HOPOPT

        self._assert_option_constructors_cover_branchy_values(HOPOPT)

    def test_ipv6_opts_option_constructors_cover_branchy_values(self) -> None:
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        self._assert_option_constructors_cover_branchy_values(IPv6_Opts)

    def _assert_option_readers_cover_branchy_values(self, protocol_cls: type) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.const.ipv6.qs_function import QSFunction
        from pcapkit.const.ipv6.router_alert import RouterAlert
        from pcapkit.const.ipv6.seed_id import SeedID
        from pcapkit.const.ipv6.smf_dpd_mode import SMFDPDMode
        from pcapkit.const.ipv6.tagger_id import TaggerID
        from pcapkit.corekit.fields.field import NoValue
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.schema.internet import hopopt as hopopt_schema
        from pcapkit.protocols.schema.internet import ipv6_opts as opts_schema
        from pcapkit.utilities.exceptions import ProtocolError

        schema = hopopt_schema if protocol_cls.__name__ == 'HOPOPT' else opts_schema
        proto = object.__new__(protocol_cls)
        options = OrderedMultiDict()

        def assert_bad(reader, option_schema) -> None:
            with self.assertRaises(ProtocolError):
                reader(option_schema, options=options)

        self.assertEqual(proto._read_opt_type(Option.IP_DFF), (3, True))

        unknown = proto._read_opt_none(
            schema.UnassignedOption(type=Option.get(30), len=2, data=b'xy'),
            options=options,
        )
        self.assertEqual(unknown.data, b'xy')
        self.assertEqual(proto._read_opt_pad(schema.PadOption(type=Option.Pad1, len=0),
                                             options=options).length, 1)
        self.assertEqual(proto._read_opt_pad(schema.PadOption(type=Option.PadN, len=4),
                                             options=options).length, 6)
        self.assertEqual(proto._read_opt_tun(
            schema.TunnelEncapsulationLimitOption(type=Option.Tunnel_Encapsulation_Limit,
                                                  len=1, limit=7),
            options=options,
        ).limit, 7)
        self.assertEqual(proto._read_opt_ra(
            schema.RouterAlertOption(type=Option.Router_Alert, len=2,
                                     alert=RouterAlert.Datagram_contains_RSVP_message),
            options=options,
        ).value, RouterAlert.Datagram_contains_RSVP_message)

        calipso = proto._read_opt_calipso(
            schema.CALIPSOOption(type=Option.CALIPSO, len=16, domain=1, cmpt_len=2,
                                 level=3, checksum=b'\x01\x02', bitmap=b'abcdefgh'),
            options=options,
        )
        self.assertEqual(calipso.cmpt_len, 8)
        self.assertEqual(bytes(calipso.cmpt_bitmap), b'abcdefgh')
        self.assertFalse(hasattr(proto._read_opt_calipso(
            schema.CALIPSOOption(type=Option.CALIPSO, len=8, domain=1, cmpt_len=0,
                                 level=3, checksum=b'\x01\x02', bitmap=b''),
            options=options,
        ), 'cmpt_bitmap'))

        ident = schema.SMFIdentificationBasedDPDOption(
            type=Option.SMF_DPD,
            len=7,
            test={'mode': SMFDPDMode.I_DPD},
            info={'mode': 0, 'type': TaggerID.IPv4, 'len': 3},
            tid=ip_address('192.0.2.1'),
            id=b'id',
        )
        object.__setattr__(ident, 'mode', SMFDPDMode.I_DPD)
        ident_data = proto._read_opt_smf_dpd(ident, options=options)
        self.assertEqual(ident_data.tid_type, TaggerID.IPv4)
        self.assertEqual(str(ident_data.tid), '192.0.2.1')

        hashed = schema.SMFHashBasedDPDOption(type=Option.SMF_DPD, len=3, hav=b'\x81\x02\x03')
        object.__setattr__(hashed, 'mode', SMFDPDMode.H_DPD)
        self.assertEqual(proto._read_opt_smf_dpd(hashed, options=options).hav, b'\x81\x02\x03')

        pdm = proto._read_opt_pdm(
            schema.PDMOption(type=Option.PDM, len=10, scaledtlr=1, scaledtls=2,
                             psntp=3, psnlr=4, deltatlr=5, deltatls=6),
            options=options,
        )
        self.assertEqual(pdm.deltatlr, 10)
        self.assertEqual(pdm.deltatls, 24)

        qs_request = schema.QuickStartRequestOption(
            type=Option.Quick_Start,
            len=6,
            flags={'func': QSFunction.Quick_Start_Request, 'rate': 1},
            ttl=7,
            nonce={'nonce': 3},
        )
        object.__setattr__(qs_request, 'func', QSFunction.Quick_Start_Request)
        qs_req = proto._read_opt_qs(qs_request, options=options)
        self.assertEqual(qs_req.rate, 80.0)
        self.assertEqual(qs_req.ttl, datetime.timedelta(seconds=7))

        qs_report = schema.QuickStartReportOption(
            type=Option.Quick_Start,
            len=6,
            flags={'func': QSFunction.Report_of_Approved_Rate, 'rate': 1},
            nonce={'nonce': 3},
        )
        object.__setattr__(qs_report, 'func', QSFunction.Report_of_Approved_Rate)
        qs_rep = proto._read_opt_qs(qs_report, options=options)
        self.assertEqual(qs_rep.rate, 80.0)
        self.assertEqual(qs_rep.nonce, 3)

        rpl = proto._read_opt_rpl(
            schema.RPLOption(type=Option.RPL_Option_0x63, len=4,
                             flags={'down': 1, 'rank_err': 0, 'fwd_err': 1},
                             id=9, rank=10),
            options=options,
        )
        self.assertTrue(rpl.flags.down)
        self.assertTrue(rpl.flags.fwd_err)

        source_seed = schema.MPLOption(type=Option.MPL_Option, len=2,
                                       flags={'type': SeedID.IPV6_SOURCE_ADDRESS,
                                              'max': 1, 'drop': 0},
                                       seq=1)
        object.__setattr__(source_seed, 'seed', NoValue)
        self.assertIsNone(proto._read_opt_mpl(source_seed, options=options).seed_id)

        for seed_type, length, seed in [
            (SeedID.SEEDID_16_BIT_UNSIGNED_INTEGER, 4, 0xffff),
            (SeedID.SEEDID_64_BIT_UNSIGNED_INTEGER, 10, 0xffffffffffffffff),
            (SeedID.SEEDID_128_BIT_UNSIGNED_INTEGER, 18, 0xffffffffffffffffffffffffffffffff),
        ]:
            mpl = proto._read_opt_mpl(
                schema.MPLOption(type=Option.MPL_Option, len=length,
                                 flags={'type': seed_type, 'max': 0, 'drop': 1},
                                 seq=7, seed=seed),
                options=options,
            )
            self.assertEqual(mpl.seed_type, seed_type)
            self.assertEqual(mpl.seed_id, seed)

        self.assertEqual(proto._read_opt_ilnp(
            schema.ILNPOption(type=Option.ILNP_Nonce, len=4, nonce=123),
            options=options,
        ).nonce, 123)
        lio = proto._read_opt_lio(
            schema.LineIdentificationOption(type=Option.Line_Identification_Option,
                                            len=4, id_len=3, id=b'abc'),
            options=options,
        )
        self.assertEqual(lio.line_id, b'abc')
        self.assertEqual(proto._read_opt_jumbo(
            schema.JumboPayloadOption(type=Option.Jumbo_Payload, len=4, jumbo_len=65536),
            options=options,
        ).jumbo_len, 65536)
        self.assertEqual(str(proto._read_opt_home(
            schema.HomeAddressOption(type=Option.Home_Address, len=16, addr='2001:db8::1'),
            options=options,
        ).address), '2001:db8::1')
        dff = proto._read_opt_ip_dff(
            schema.IPDFFOption(type=Option.IP_DFF, len=2,
                               flags={'ver': 1, 'dup': 1, 'ret': 0}, seq=77),
            options=options,
        )
        self.assertEqual(dff.version, 1)
        self.assertTrue(dff.flags.dup)

        proto.__header__ = types.SimpleNamespace(options=[
            proto._make_opt_pad(Option.Pad1, length=0),
            proto._make_opt_tun(Option.Tunnel_Encapsulation_Limit, limit=7),
        ])
        read_options = proto._read_hopopt_options if protocol_cls.__name__ == 'HOPOPT' else proto._read_ipv6_opts
        parsed = read_options(4)
        self.assertEqual(list(parsed.keys()), [Option.Pad1, Option.Tunnel_Encapsulation_Limit])
        with self.assertRaises(ProtocolError):
            read_options(5)

        assert_bad(proto._read_opt_pad, schema.PadOption(type=Option.Tunnel_Encapsulation_Limit, len=1))
        assert_bad(proto._read_opt_pad, schema.PadOption(type=Option.Pad1, len=1))
        assert_bad(proto._read_opt_pad, schema.PadOption(type=Option.PadN, len=0))
        assert_bad(proto._read_opt_tun, schema.TunnelEncapsulationLimitOption(
            type=Option.Tunnel_Encapsulation_Limit, len=2, limit=7,
        ))
        assert_bad(proto._read_opt_ra, schema.RouterAlertOption(
            type=Option.Router_Alert, len=1,
            alert=RouterAlert.Datagram_contains_RSVP_message,
        ))
        assert_bad(proto._read_opt_calipso, schema.CALIPSOOption(
            type=Option.CALIPSO, len=7, domain=1, cmpt_len=0,
            level=3, checksum=b'\x01\x02', bitmap=b'',
        ))
        assert_bad(proto._read_opt_calipso, schema.CALIPSOOption(
            type=Option.CALIPSO, len=8, domain=1, cmpt_len=1,
            level=3, checksum=b'\x01\x02', bitmap=b'abcd',
        ))
        bad_smf = schema.SMFHashBasedDPDOption(type=Option.SMF_DPD, len=3, hav=b'\x81\x02\x03')
        object.__setattr__(bad_smf, 'mode', 2)
        assert_bad(proto._read_opt_smf_dpd, bad_smf)
        assert_bad(proto._read_opt_pdm, schema.PDMOption(
            type=Option.PDM, len=9, scaledtlr=1, scaledtls=2,
            psntp=3, psnlr=4, deltatlr=5, deltatls=6,
        ))
        assert_bad(proto._read_opt_qs, schema.QuickStartRequestOption(
            type=Option.Quick_Start, len=5,
            flags={'func': QSFunction.Quick_Start_Request, 'rate': 1},
            ttl=7, nonce={'nonce': 3},
        ))
        qs_unknown = schema.QuickStartRequestOption(
            type=Option.Quick_Start,
            len=6,
            flags={'func': QSFunction.Quick_Start_Request, 'rate': 1},
            ttl=7,
            nonce={'nonce': 3},
        )
        object.__setattr__(qs_unknown, 'func', QSFunction.get(1))
        assert_bad(proto._read_opt_qs, qs_unknown)
        assert_bad(proto._read_opt_rpl, schema.RPLOption(
            type=Option.RPL_Option_0x63, len=3,
            flags={'down': 1, 'rank_err': 0, 'fwd_err': 1},
            id=9, rank=10,
        ))
        assert_bad(proto._read_opt_mpl, schema.MPLOption(
            type=Option.MPL_Option, len=1,
            flags={'type': SeedID.IPV6_SOURCE_ADDRESS, 'max': 0, 'drop': 0},
            seq=1,
        ))
        assert_bad(proto._read_opt_mpl, schema.MPLOption(
            type=Option.MPL_Option, len=4,
            flags={'type': SeedID.IPV6_SOURCE_ADDRESS, 'max': 0, 'drop': 0},
            seq=1,
        ))
        assert_bad(proto._read_opt_mpl, schema.MPLOption(
            type=Option.MPL_Option, len=5,
            flags={'type': SeedID.SEEDID_16_BIT_UNSIGNED_INTEGER, 'max': 0, 'drop': 0},
            seq=1, seed=1,
        ))
        assert_bad(proto._read_opt_mpl, schema.MPLOption(
            type=Option.MPL_Option, len=8,
            flags={'type': SeedID.SEEDID_64_BIT_UNSIGNED_INTEGER, 'max': 0, 'drop': 0},
            seq=1, seed=1,
        ))
        assert_bad(proto._read_opt_mpl, schema.MPLOption(
            type=Option.MPL_Option, len=10,
            flags={'type': SeedID.SEEDID_128_BIT_UNSIGNED_INTEGER, 'max': 0, 'drop': 0},
            seq=1, seed=1,
        ))
        assert_bad(proto._read_opt_mpl, schema.MPLOption(
            type=Option.MPL_Option, len=2,
            flags={'type': 'Bogus_Seed_For_Test', 'max': 0, 'drop': 0},
            seq=1,
        ))
        assert_bad(proto._read_opt_jumbo, schema.JumboPayloadOption(
            type=Option.Jumbo_Payload, len=3, jumbo_len=65536,
        ))
        assert_bad(proto._read_opt_home, schema.HomeAddressOption(
            type=Option.Home_Address, len=15, addr='2001:db8::1',
        ))
        assert_bad(proto._read_opt_ip_dff, schema.IPDFFOption(
            type=Option.IP_DFF, len=3,
            flags={'ver': 1, 'dup': 1, 'ret': 0}, seq=77,
        ))

    def test_hopopt_option_readers_cover_branchy_values(self) -> None:
        from pcapkit.protocols.internet.hopopt import HOPOPT

        self._assert_option_readers_cover_branchy_values(HOPOPT)

    def test_ipv6_opts_option_readers_cover_branchy_values(self) -> None:
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        self._assert_option_readers_cover_branchy_values(IPv6_Opts)

    def _assert_option_schema_helpers_and_post_process_branches(self, schema: types.ModuleType) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.const.ipv6.qs_function import QSFunction
        from pcapkit.const.ipv6.seed_id import SeedID
        from pcapkit.const.ipv6.smf_dpd_mode import SMFDPDMode
        from pcapkit.const.ipv6.tagger_id import TaggerID
        from pcapkit.corekit.fields.ipaddress import IPv4AddressField, IPv6AddressField
        from pcapkit.corekit.fields.misc import NoValueField, SchemaField
        from pcapkit.corekit.fields.strings import BytesField
        from pcapkit.utilities.exceptions import FieldValueError

        self.assertEqual(schema.mpl_opt_seed_id_len({'flags': {'type': 0}}), 0)
        self.assertEqual(schema.mpl_opt_seed_id_len({'flags': {'type': 1}}), 2)
        self.assertEqual(schema.mpl_opt_seed_id_len({'flags': {'type': 2}}), 8)
        self.assertEqual(schema.mpl_opt_seed_id_len({'flags': {'type': 3}}), 16)
        with self.assertRaises(FieldValueError):
            schema.mpl_opt_seed_id_len({'flags': {'type': 4}})

        for mode in (SMFDPDMode.I_DPD, SMFDPDMode.H_DPD):
            field = schema.smf_dpd_data_selector({'test': {'mode': mode, 'len': 4}})
            self.assertIsInstance(field, SchemaField)
        original_smf = schema.SMFDPDOption.registry[SMFDPDMode.I_DPD]
        try:
            schema.SMFDPDOption.registry[SMFDPDMode.I_DPD] = None
            with self.assertRaises(FieldValueError):
                schema.smf_dpd_data_selector({'test': {'mode': SMFDPDMode.I_DPD, 'len': 4}})
        finally:
            schema.SMFDPDOption.registry[SMFDPDMode.I_DPD] = original_smf

        null_pkt = {'info': {'type': TaggerID.NULL, 'len': 0}}
        self.assertIsInstance(schema.smf_i_dpd_tid_selector(null_pkt), NoValueField)
        self.assertEqual(null_pkt['info']['type'], TaggerID.NULL)
        with self.assertRaises(FieldValueError):
            schema.smf_i_dpd_tid_selector({'info': {'type': TaggerID.NULL, 'len': 1}})

        self.assertIsInstance(schema.smf_i_dpd_tid_selector(
            {'info': {'type': TaggerID.IPv4, 'len': 3}},
        ), IPv4AddressField)
        with self.assertRaises(FieldValueError):
            schema.smf_i_dpd_tid_selector({'info': {'type': TaggerID.IPv4, 'len': 4}})

        self.assertIsInstance(schema.smf_i_dpd_tid_selector(
            {'info': {'type': TaggerID.IPv6, 'len': 15}},
        ), IPv6AddressField)
        with self.assertRaises(FieldValueError):
            schema.smf_i_dpd_tid_selector({'info': {'type': TaggerID.IPv6, 'len': 16}})

        self.assertIsInstance(schema.smf_i_dpd_tid_selector(
            {'info': {'type': TaggerID.DEFAULT, 'len': 2}},
        ), BytesField)

        for func in (QSFunction.Quick_Start_Request, QSFunction.Report_of_Approved_Rate):
            field = schema.quick_start_data_selector({'flags': {'func': func}})
            self.assertIsInstance(field, SchemaField)
        original_qs = schema.QuickStartOption.registry[QSFunction.Quick_Start_Request]
        try:
            schema.QuickStartOption.registry[QSFunction.Quick_Start_Request] = None
            with self.assertRaises(FieldValueError):
                schema.quick_start_data_selector({'flags': {'func': QSFunction.Quick_Start_Request}})
        finally:
            schema.QuickStartOption.registry[QSFunction.Quick_Start_Request] = original_qs

        pad1 = schema.PadOption(type=Option.Pad1, len=99)
        self.assertEqual(pad1.post_process({}).len, 0)
        padn = schema.PadOption(type=Option.PadN, len=3)
        self.assertEqual(padn.post_process({}).len, 3)

        ident_kwargs = {
            'type': Option.SMF_DPD,
            'len': 2,
            'info': {'mode': 0, 'type': TaggerID.NULL, 'len': 0},
            'id': b'id',
        }
        if schema.__name__.endswith('ipv6_opts'):
            ident_kwargs['test'] = {'mode': SMFDPDMode.I_DPD}
        ident = schema.SMFIdentificationBasedDPDOption(**ident_kwargs)
        self.assertIs(ident.post_process({}), ident)
        self.assertEqual(ident.mode, SMFDPDMode.I_DPD)
        wrapper = schema._SMFDPDOption(test={'mode': SMFDPDMode.I_DPD, 'len': 2}, data=ident)
        self.assertIs(wrapper.post_process({}), ident)

        hashed = schema.SMFHashBasedDPDOption(type=Option.SMF_DPD, len=3, hav=b'abc')
        self.assertIs(hashed.post_process({}), hashed)
        self.assertEqual(hashed.mode, SMFDPDMode.H_DPD)

        request = schema.QuickStartRequestOption(
            type=Option.Quick_Start,
            len=6,
            flags={'func': QSFunction.Quick_Start_Request, 'rate': 1},
            ttl=7,
            nonce={'nonce': 3},
        )
        quick = schema._QuickStartOption(flags={'func': QSFunction.Quick_Start_Request}, data=request)
        self.assertIs(quick.post_process({}), request)
        self.assertEqual(request.func, QSFunction.Quick_Start_Request)

        src = ip_address('2001:db8::1')
        source_seed = schema.MPLOption(type=Option.MPL_Option, len=2,
                                       flags={'type': SeedID.IPV6_SOURCE_ADDRESS,
                                              'max': 0, 'drop': 0},
                                       seq=1)
        self.assertIs(source_seed.post_process({'src': src}).seed, src)
        integer_seed = schema.MPLOption(type=Option.MPL_Option, len=4,
                                        flags={'type': SeedID.SEEDID_16_BIT_UNSIGNED_INTEGER,
                                               'max': 0, 'drop': 0},
                                        seq=1, seed=5)
        self.assertEqual(integer_seed.post_process({}).seed, 5)

    def test_hopopt_schema_helpers_and_post_process_branches(self) -> None:
        from pcapkit.protocols.schema.internet import hopopt as hopopt_schema

        self._assert_option_schema_helpers_and_post_process_branches(hopopt_schema)

    def test_ipv6_opts_schema_helpers_and_post_process_branches(self) -> None:
        from pcapkit.protocols.schema.internet import ipv6_opts as opts_schema

        self._assert_option_schema_helpers_and_post_process_branches(opts_schema)

    def test_ipv6_route_schema_selector_and_rpl_post_process_branches(self) -> None:
        from pcapkit.const.ipv6.routing import Routing
        from pcapkit.corekit.fields.misc import SchemaField
        from pcapkit.protocols.schema.internet import ipv6_route as route_schema

        field = route_schema.ipv6_route_data_selector({'type': Routing.Source_Route, 'length': 3})
        self.assertIsInstance(field, SchemaField)

        first = ip_address('2001:db8::1')
        second = ip_address('2001:db8::2')
        full = route_schema.RPL(cmpr_i=0, cmpr_e=0, pad={'pad_len': 0},
                                addresses=first.packed + second.packed)
        full.post_process({})
        self.assertEqual([str(item) for item in full.ip], ['2001:db8::1', '2001:db8::2'])

        suffixes = first.packed[8:] + second.packed[8:]
        compressed = route_schema.RPL(cmpr_i=8, cmpr_e=8, pad={'pad_len': 0}, addresses=suffixes)
        compressed.post_process({})
        self.assertEqual(compressed.ip, [first.packed[8:], second.packed[8:]])

        with_dst = route_schema.RPL(cmpr_i=8, cmpr_e=8, pad={'pad_len': 0}, addresses=suffixes)
        with_dst.post_process({'dst': ip_address('2001:db8::ffff')})
        self.assertEqual([str(item) for item in with_dst.ip], ['2001:db8::1', '2001:db8::2'])

    def _assert_padding_options_parse_from_the_wire(self, protocol_cls: type) -> None:
        """A ``Pad1`` option must consume exactly one octet, wherever it sits.

        Per :rfc:`8200#section-4.2` the two padding options do not share a wire
        shape: ``Pad1`` is a lone type octet with no ``Opt Data Len`` field at
        all, while ``PadN`` is a type octet, a length octet, and that many data
        octets. Reading a length octet that is not there consumes the *next*
        option's type byte instead, so every case below puts something after
        the padding -- which is what made the defect visible.

        The header is ``next`` = 59 (``IPv6-NoNxt``) with a header extension
        length of 0, i.e. an 8-octet header whose options area is the 6 octets
        that follow. A parse that mis-sizes any one option therefore also fails
        the ``counter != length`` check at the end of the option loop.

        """
        from pcapkit.const.ipv6.option import Option

        header = b'\x3b\x00'
        cases = (
            ('pad1 then padn',
             b'\x00' + b'\x01\x03\x00\x00\x00',
             [(Option.Pad1, 1), (Option.PadN, 5)]),
            ('pad1 then a real option then pad1',
             b'\x00' + b'\x05\x02\x00\x00' + b'\x00',
             [(Option.Pad1, 1), (Option.Router_Alert, 4), (Option.Pad1, 1)]),
            ('six pad1 in a row',
             b'\x00' * 6,
             [(Option.Pad1, 1)] * 6),
            ('pad1 as the final octet',
             b'\x01\x03\x00\x00\x00' + b'\x00',
             [(Option.PadN, 5), (Option.Pad1, 1)]),
            ('padn is unaffected',
             b'\x01\x04\x00\x00\x00\x00',
             [(Option.PadN, 6)]),
            ('pad1 run then a minimal padn',
             b'\x00\x00\x00' + b'\x01\x01\x00',
             [(Option.Pad1, 1), (Option.Pad1, 1), (Option.Pad1, 1), (Option.PadN, 3)]),
        )

        for name, options, expected in cases:
            with self.subTest(case=name):
                raw = header + options
                proto = protocol_cls(raw, extension=True)

                self.assertEqual(proto.info.length, 8)
                self.assertEqual(
                    [(code, opt.length) for code, opt in proto.info.options.items(multi=True)],
                    expected,
                )

                # the reader and the writer must agree: repacking the parsed
                # schema has to give back the very bytes it was read from
                self.assertEqual(bytes(proto.__header__), raw)

    def test_hopopt_padding_options_parse_from_the_wire(self) -> None:
        from pcapkit.protocols.internet.hopopt import HOPOPT

        self._assert_padding_options_parse_from_the_wire(HOPOPT)

    def test_ipv6_opts_padding_options_parse_from_the_wire(self) -> None:
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        self._assert_padding_options_parse_from_the_wire(IPv6_Opts)

    def _assert_smf_dpd_options_parse_from_the_wire(self, protocol_cls: type) -> None:
        """A hash-based ``SMF_DPD`` option must consume exactly what it declares.

        Per :rfc:`6621#section-8.1` the option is an ``Option Type`` octet, an
        ``Opt Data Len`` octet, and ``Opt Data Len`` further octets whose first
        bit is the DPD mode -- set, here, for hash-based DPD, so that the whole of
        the hash assist value is the ``Opt Data Len`` octets. Two things have to
        hold for that to read correctly, and each case below breaks if either
        does not: the declared length has to be read from the ``Opt Data Len``
        octet, and the area handed to the mode schema has to be two octets wider
        than it, since that schema parses the option header itself.

        The first case is #431's reproducer verbatim. On the pristine tree it does
        not fail, it never returns -- 15 seconds of CPU with no exception and no
        diagnostic -- so every case runs under a deadline: a regression here has
        to fail the suite rather than wedge it.

        """
        from pcapkit.const.ipv6.option import Option
        from pcapkit.const.ipv6.smf_dpd_mode import SMFDPDMode

        cases = (
            ('#431: hash-based DPD of length 3, then a pad1',
             b'\x3b\x00' + b'\x08\x03\x81\x02\x03' + b'\x00',
             [(Option.SMF_DPD, 5), (Option.Pad1, 1)],
             [b'\x81\x02\x03']),
            ('hash-based DPD filling the option area',
             b'\x3b\x00' + b'\x08\x04\x81\x02\x03\x04',
             [(Option.SMF_DPD, 6)],
             [b'\x81\x02\x03\x04']),
            ('two hash-based DPD options back to back',
             b'\x3b\x01' + b'\x08\x02\x81\x01' + b'\x08\x02\x81\x02' + b'\x00' * 6,
             [(Option.SMF_DPD, 4), (Option.SMF_DPD, 4)] + [(Option.Pad1, 1)] * 6,
             [b'\x81\x01', b'\x81\x02']),
        )

        for name, raw, expected, expected_hav in cases:
            with self.subTest(case=name):
                with time_limit(5):
                    proto = protocol_cls(raw, extension=True)

                options = list(proto.info.options.items(multi=True))

                self.assertEqual(proto.info.length, len(raw))
                self.assertEqual([(code, opt.length) for code, opt in options], expected)

                # every octet of the option area has to be accounted for by an
                # option, which is what the mis-sized read got wrong
                self.assertEqual(sum(length for _, length in expected), len(raw) - 2)

                self.assertEqual(
                    [opt.hav for code, opt in options if code == Option.SMF_DPD],
                    expected_hav,
                )
                self.assertEqual(
                    [opt.dpd_type for code, opt in options if code == Option.SMF_DPD],
                    [SMFDPDMode.H_DPD] * len(expected_hav),
                )

                # the reader and the writer must agree: repacking the parsed
                # schema has to give back the very bytes it was read from
                self.assertEqual(bytes(proto.__header__), raw)

    def test_hopopt_smf_dpd_options_parse_from_the_wire(self) -> None:
        from pcapkit.protocols.internet.hopopt import HOPOPT

        self._assert_smf_dpd_options_parse_from_the_wire(HOPOPT)

    def test_ipv6_opts_smf_dpd_options_parse_from_the_wire(self) -> None:
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        self._assert_smf_dpd_options_parse_from_the_wire(IPv6_Opts)

    def _assert_identification_based_dpd_options_parse_from_the_wire(self, protocol_cls: type) -> None:
        """The other ``SMF_DPD`` mode, which sizes itself from a TaggerID.

        Identification-based DPD reaches the same mis-sized read by a different
        route: its length comes from ``Opt Data Len`` too, but the octets it
        covers are a TaggerID whose own width comes from the ``TidLen`` nibble
        [:rfc:`6621#section-8.1`], so a wrong ``Opt Data Len`` mis-sizes the
        identifier rather than the whole option. Both cases below hang the
        pristine tree exactly as the hash-based ones do.

        Only the option itself is asserted, not the padding after it: HOPOPT and
        IPv6-Opts disagree on how much of the option area an
        ``SMFIdentificationBasedDPDOption`` leaves over, because the IPv6-Opts
        schema carries an extra forward-matched octet which
        :attr:`Schema.__buffer__ <pcapkit.protocols.schema.schema.Schema.__buffer__>`
        records although the stream never consumes it. That is its own
        ``len(data)``-is-not-consumed defect, distinct from the one #431 is about,
        and pinning either count here would bless one of the two.

        """
        from pcapkit.const.ipv6.option import Option
        from pcapkit.const.ipv6.smf_dpd_mode import SMFDPDMode
        from pcapkit.const.ipv6.tagger_id import TaggerID

        cases = (
            ('null taggerID, two-octet identifier',
             b'\x3b\x00' + b'\x08\x03\x00\x01\x02' + b'\x00',
             5, TaggerID.NULL, 0, None, b'\x01\x02'),
            ('four-octet taggerID, one-octet identifier',
             b'\x3b\x01' + b'\x08\x06\x13\x0a\x00\x00\x01\xff' + b'\x00' * 6,
             8, TaggerID.DEFAULT, 3, b'\x0a\x00\x00\x01', b'\xff'),
        )

        for name, raw, length, tid_type, tid_len, tid, identifier in cases:
            with self.subTest(case=name):
                with time_limit(5):
                    proto = protocol_cls(raw, extension=True)

                option = next(opt for code, opt in proto.info.options.items(multi=True)
                              if code == Option.SMF_DPD)

                self.assertEqual(option.length, length)
                self.assertEqual(option.dpd_type, SMFDPDMode.I_DPD)
                self.assertEqual(option.tid_type, tid_type)
                self.assertEqual(option.tid_len, tid_len)
                self.assertEqual(option.tid, tid)
                self.assertEqual(option.id, identifier)

                self.assertEqual(bytes(proto.__header__), raw)

    def test_hopopt_identification_based_dpd_options_parse_from_the_wire(self) -> None:
        from pcapkit.protocols.internet.hopopt import HOPOPT

        self._assert_identification_based_dpd_options_parse_from_the_wire(HOPOPT)

    def test_ipv6_opts_identification_based_dpd_options_parse_from_the_wire(self) -> None:
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        self._assert_identification_based_dpd_options_parse_from_the_wire(IPv6_Opts)

    def _assert_a_truncated_option_area_is_diagnosed(self, protocol_cls: type) -> None:
        """An option area with nothing behind it is an error, not a hang.

        The simplest form of #431, and the one that needs no option schema at all:
        a header extension length of 1 declares a 14-octet option area, and the
        two octets given here are the whole header. The option loop reads ``b''``
        for every field, which decodes the type octet as 0 -- ``Pad1`` in this
        registry, not an end-of-option-list -- so it appends a phantom one-octet
        ``Pad1``, subtracts the zero octets it actually read, and goes round
        again forever.

        Note that this is registry-dependent, and IPv4, TCP and PCAP-NG behave
        differently on purpose: 0 is the end-of-option-list code there, so the
        loop's ``eool`` break has always absorbed a truncated area and reported
        the rest as padding. Their tolerance is pinned in their own tests.

        """
        from pcapkit.utilities.exceptions import FieldValueError

        for name, raw in (
            ('no option octets at all', b'\x3b\x01'),
            ('four of fourteen octets', b'\x3b\x01' + b'\x01\x02\x00\x00'),
        ):
            with self.subTest(case=name):
                with self.assertRaisesRegex(FieldValueError, 'consumed no data'):
                    with time_limit(5):
                        protocol_cls(raw, len(raw), extension=True)

    def test_hopopt_truncated_option_area_is_diagnosed(self) -> None:
        from pcapkit.protocols.internet.hopopt import HOPOPT

        self._assert_a_truncated_option_area_is_diagnosed(HOPOPT)

    def test_ipv6_opts_truncated_option_area_is_diagnosed(self) -> None:
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        self._assert_a_truncated_option_area_is_diagnosed(IPv6_Opts)

    def _assert_padding_option_schema_sizes_itself(self, protocol_cls: type) -> None:
        """The padding option schema, on its own.

        :func:`~pcapkit.protocols.schema.internet.hopopt.pad_opt_data_len` is
        the whole of the read-side fix, so it is tested directly as well as
        through a parse: it has to read a skipped conditional field -- which is
        recorded as :data:`~pcapkit.corekit.fields.field.NoValue`, not omitted --
        as zero padding octets rather than passing it on to
        :class:`~pcapkit.corekit.fields.strings.PaddingField`.

        """
        from pcapkit.const.ipv6.option import Option
        from pcapkit.corekit.fields.field import NoValue
        from pcapkit.protocols.schema.internet import hopopt as hopopt_schema
        from pcapkit.protocols.schema.internet import ipv6_opts as opts_schema

        schema = hopopt_schema if protocol_cls.__name__ == 'HOPOPT' else opts_schema

        self.assertEqual(schema.pad_opt_data_len({}), 0)
        self.assertEqual(schema.pad_opt_data_len({'len': NoValue}), 0)
        self.assertEqual(schema.pad_opt_data_len({'len': None}), 0)
        self.assertEqual(schema.pad_opt_data_len({'len': 4}), 4)

        # a Pad1 option on its own: one octet read, and the octet after it left
        # alone for whatever comes next
        stream = io.BytesIO(b'\x00\x2a')
        pad1 = schema.PadOption.unpack(stream, 2, {})
        self.assertEqual(pad1.type, Option.Pad1)
        self.assertEqual(pad1.len, 0)
        self.assertEqual(len(pad1), 1)
        self.assertEqual(bytes(pad1), b'\x00')
        self.assertEqual(stream.tell(), 1)

        # a PadN option still spans its length octet plus that many data octets
        stream = io.BytesIO(b'\x01\x02\xaa\xbb\xcc')
        padn = schema.PadOption.unpack(stream, 5, {})
        self.assertEqual(padn.type, Option.PadN)
        self.assertEqual(padn.len, 2)
        self.assertEqual(len(padn), 4)
        self.assertEqual(bytes(padn), b'\x01\x02\xaa\xbb')
        self.assertEqual(stream.tell(), 4)

    def _assert_constructed_header_round_trips(self, protocol_cls: type) -> None:
        """Construction has to produce a header that parses back to itself.

        Constructing one of these protocols packs the header and immediately
        re-parses the bytes, so any disagreement between the declared
        ``Hdr Ext Len`` and the octets actually emitted surfaces here as a
        :exc:`~pcapkit.utilities.exceptions.ProtocolError` from :meth:`read`.
        Every case below therefore both exercises the padding branches and
        proves that ``(hdr_ext_len + 1) * 8`` is the real length of the header.

        The option lengths are chosen for the padding they draw: the whole
        header, its two fixed octets included, has to be a multiple of 8, so an
        option of ``8n + 5`` octets needs a single ``Pad1``, one of ``8n + 4``
        needs two, and anything else needs a ``PadN``.

        """
        from pcapkit.const.ipv6.option import Option
        from pcapkit.const.reg.transtype import TransType

        cases = (
            # a 5-octet option leaves one octet, which only a Pad1 can fill
            ('one pad1', [(Option.get(250), {'data': b'abc'})], 8,
             [(Option.get(250), 5), (Option.Pad1, 1)]),
            # a 4-octet option leaves two, i.e. two Pad1 rather than a PadN
            ('two pad1', [(Option.Router_Alert, {'alert': 0})], 8,
             [(Option.Router_Alert, 4), (Option.Pad1, 1), (Option.Pad1, 1)]),
            # three or more spare octets are a PadN, whose own two octets of
            # overhead have to come out of the padding it is asked to occupy
            ('padn', [(Option.Tunnel_Encapsulation_Limit, {'limit': 3})], 8,
             [(Option.Tunnel_Encapsulation_Limit, 3), (Option.PadN, 3)]),
            # an option that already lands on the boundary draws no padding
            ('no padding', [(Option.Jumbo_Payload, {'jumbo_len': 70000})], 8,
             [(Option.Jumbo_Payload, 6)]),
            # more than one option, each aligned in turn
            ('two options', [(Option.Tunnel_Encapsulation_Limit, {'limit': 3}),
                             (Option.Router_Alert, {'alert': 0})], 16,
             [(Option.Tunnel_Encapsulation_Limit, 3), (Option.PadN, 3),
              (Option.Router_Alert, 4), (Option.PadN, 4)]),
            # an option needing more than 8 octets of its own
            ('long option', [(Option.Home_Address, {'addr': '2001:db8::3'})], 24,
             [(Option.Home_Address, 18), (Option.PadN, 4)]),
            # no options at all is 6 octets of padding, not an empty header
            ('no options', [], 8, [(Option.PadN, 6)]),
        )

        for name, options, size, expected in cases:
            with self.subTest(case=name):
                built = protocol_cls(next=TransType.IPv6_NoNxt, options=list(options))
                raw = bytes(built)

                self.assertEqual(len(raw), size)
                self.assertEqual(len(raw) % 8, 0)
                # the declared length and the emitted length must be the same
                self.assertEqual((raw[1] + 1) * 8, len(raw))

                parsed = protocol_cls(raw, extension=True)
                self.assertEqual(parsed.info.length, size)
                self.assertEqual(
                    [(code, opt.length)
                     for code, opt in parsed.info.options.items(multi=True)],
                    expected,
                )
                self.assertEqual(bytes(parsed.__header__), raw)

    def test_hopopt_padding_option_schema_sizes_itself(self) -> None:
        from pcapkit.protocols.internet.hopopt import HOPOPT

        self._assert_padding_option_schema_sizes_itself(HOPOPT)

    def test_ipv6_opts_padding_option_schema_sizes_itself(self) -> None:
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        self._assert_padding_option_schema_sizes_itself(IPv6_Opts)

    def test_hopopt_constructed_header_round_trips(self) -> None:
        from pcapkit.protocols.internet.hopopt import HOPOPT

        self._assert_constructed_header_round_trips(HOPOPT)

    def test_ipv6_opts_constructed_header_round_trips(self) -> None:
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        self._assert_constructed_header_round_trips(IPv6_Opts)

    def test_option_registries_are_not_clobbered_by_a_nested_enum_registry(self) -> None:
        """Option type 0 must resolve to the padding option in every module.

        An :class:`~pcapkit.protocols.schema.schema.EnumSchema` subclass that
        does not declare its own ``__enum__`` shares its parent's registry, so
        registering *its* subclasses writes into the parent's key space. The
        quick-start options are keyed by
        :class:`~pcapkit.const.ipv6.qs_function.QSFunction`, whose members are
        ``0`` and ``8``, so a shared registry silently overwrites option types
        ``0`` (``Pad1``) and ``8`` (``SMF_DPD``) -- and the failure is silent
        because a missing ``__enum__`` is not an error, it just merges two
        registries whose key spaces happen to overlap.

        :rfc:`8200#section-4.2` defines ``Pad1`` for both the Hop-by-Hop Options
        and the Destination Options header, so it must resolve in both.

        """
        from pcapkit.const.ipv6.option import Option as Enum_Option
        from pcapkit.const.ipv6.qs_function import QSFunction as Enum_QSFunction
        from pcapkit.protocols.schema.internet import hopopt as hopopt_schema
        from pcapkit.protocols.schema.internet import ipv6_opts as opts_schema

        # the two enum values that collide with option types when unscoped
        self.assertEqual(Enum_QSFunction.Quick_Start_Request.value, 0)
        self.assertEqual(Enum_QSFunction.Report_of_Approved_Rate.value, 8)
        self.assertEqual(Enum_Option.Pad1.value, 0)
        self.assertEqual(Enum_Option.PadN.value, 1)

        for module in (hopopt_schema, opts_schema):
            with self.subTest(module=module.__name__.rsplit('.', 1)[-1]):
                option = module.Option
                quick_start = module.QuickStartOption

                # the quick-start registry must be its own, not the option one
                self.assertIsNot(quick_start.__enum__, option.__enum__)
                self.assertIn('__enum__', vars(quick_start))

                # snapshot the registries: they are ``defaultdict``s, so reading a
                # missing key through them would insert it
                options = dict(option.registry)
                functions = dict(quick_start.registry)

                # option type 0 (Pad1) and 1 (PadN) both resolve to PadOption
                self.assertIs(options[Enum_Option.Pad1], module.PadOption)
                self.assertIs(options[Enum_Option.PadN], module.PadOption)
                # option type 8 (SMF_DPD) must not be the quick-start report either
                self.assertIsNot(options[Enum_Option.SMF_DPD], module.QuickStartReportOption)

                # and the quick-start functions resolve inside their own registry
                self.assertIs(functions[Enum_QSFunction.Quick_Start_Request],
                              module.QuickStartRequestOption)
                self.assertIs(functions[Enum_QSFunction.Report_of_Approved_Rate],
                              module.QuickStartReportOption)

    def test_ipv6_opts_and_hopopt_option_registries_agree(self) -> None:
        """The two modules describe the same option space and must map it alike.

        ``hopopt`` and ``ipv6_opts`` are near-identical by construction, so the
        cheapest guard against one drifting from the other is to compare their
        registries key for key. The registry collision this catches came about
        from exactly one line present in one module and missing in the other.

        """
        from pcapkit.protocols.schema.internet import hopopt as hopopt_schema
        from pcapkit.protocols.schema.internet import ipv6_opts as opts_schema

        hopopt_options = dict(hopopt_schema.Option.registry)
        opts_options = dict(opts_schema.Option.registry)
        self.assertEqual(set(hopopt_options), set(opts_options))

        for key in sorted(hopopt_options, key=int):
            with self.subTest(option=int(key)):
                self.assertEqual(hopopt_options[key].__name__, opts_options[key].__name__)


if __name__ == '__main__':
    unittest.main()
