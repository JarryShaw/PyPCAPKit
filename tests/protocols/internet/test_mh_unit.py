from __future__ import annotations

import datetime
from ipaddress import ip_address, ip_network
import importlib.util
from types import SimpleNamespace
import unittest
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class DummyDict(dict):
    __getattr__ = dict.__getitem__


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class MHUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_mh_index_length_and_make_data(self) -> None:
        from pcapkit.const.mh.packet import Packet
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.mh import MH

        data = DummyDict(
            next=TransType.UDP,
            type=Packet.Binding_Refresh_Request,
            chksum=b'\x12\x34',
            __next_type__=None,
        )
        proto = object.__new__(MH)

        self.assertEqual(MH.__index__(), TransType.Mobility_Header)
        self.assertEqual(proto.__length_hint__(), 6)
        values = MH._make_data(data)
        self.assertEqual(values['next'], TransType.UDP)
        self.assertEqual(values['type'], Packet.Binding_Refresh_Request)
        self.assertEqual(values['chksum'], b'\x12\x34')
        self.assertIs(values['data'], data)
        self.assertIn('payload', values)

    def test_mh_register_message_warns_on_overwrite(self) -> None:
        from pcapkit.const.mh.packet import Packet
        from pcapkit.protocols.internet.mh import MH

        original = MH.__dict__['__message__'][Packet.Binding_Refresh_Request]
        try:
            with mock.patch('pcapkit.protocols.internet.mh.warn') as warn:
                MH.register_message(Packet.Binding_Refresh_Request, 'brr')
            warn.assert_called_once()
            self.assertEqual(MH.__dict__['__message__'][Packet.Binding_Refresh_Request], 'brr')
        finally:
            MH.__dict__['__message__'][Packet.Binding_Refresh_Request] = original

    def test_mh_register_option_warns_on_overwrite(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh import MH

        original = MH.__dict__['__option__'][Option.Pad1]
        try:
            with mock.patch('pcapkit.protocols.internet.mh.warn') as warn:
                MH.register_option(Option.Pad1, 'pad')
            warn.assert_called_once()
            self.assertEqual(MH.__dict__['__option__'][Option.Pad1], 'pad')
        finally:
            MH.__dict__['__option__'][Option.Pad1] = original

    def test_mh_register_extension_warns_on_overwrite(self) -> None:
        from pcapkit.const.mh.cga_extension import CGAExtension
        from pcapkit.protocols.internet.mh import MH

        original = MH.__dict__['__extension__'][CGAExtension.Multi_Prefix]
        try:
            with mock.patch('pcapkit.protocols.internet.mh.warn') as warn:
                MH.register_extension(CGAExtension.Multi_Prefix, 'multiprefix')
            warn.assert_called_once()
            self.assertEqual(MH.__dict__['__extension__'][CGAExtension.Multi_Prefix], 'multiprefix')
        finally:
            MH.__dict__['__extension__'][CGAExtension.Multi_Prefix] = original

    def test_mh_read_make_properties_and_extension_accessors(self) -> None:
        from pcapkit.const.mh.packet import Packet
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.protocols.schema.internet.mh import BindingRefreshRequestMessage
        from pcapkit.protocols.schema.internet.mh import MH as Schema_MH
        from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

        proto = object.__new__(MH)
        proto._info = DummyDict(length=16)
        proto._extf = False
        proto.__header__ = Schema_MH(
            next=TransType.UDP,
            length=1,
            type=Packet.Binding_Refresh_Request,
            chksum=b'\x12\x34',
            data=BindingRefreshRequestMessage(options=[]),
            payload=b'',
        )
        proto._data = b'\x00' * 16
        proto.__cached__ = {}

        self.assertEqual(proto.name, 'Mobility Header')
        self.assertEqual(proto.length, 16)
        self.assertEqual(proto.read(extension=True).type, Packet.Binding_Refresh_Request)
        self.assertEqual(proto.read(length=16, extension=True).type, Packet.Binding_Refresh_Request)
        with mock.patch.object(MH, '_decode_next_layer', return_value='decoded') as decode:
            self.assertEqual(proto.read(), 'decoded')
        decode.assert_called_once()

        made_bytes = proto.make(type=Packet.Binding_Refresh_Request, data=b'\x00\x00')
        self.assertEqual(made_bytes.length, 0)
        made_dict = proto.make(type=Packet.Binding_Refresh_Request, data={'options': []})
        self.assertEqual(made_dict.type, Packet.Binding_Refresh_Request)
        made_schema = proto.make(type=Packet.Binding_Refresh_Request,
                                 data=BindingRefreshRequestMessage(options=[]))
        self.assertEqual(made_schema.type, Packet.Binding_Refresh_Request)
        with self.assertRaises(ProtocolError):
            proto.make(data=object())

        proto._extf = True
        with self.assertRaises(UnsupportedCall):
            _ = proto.payload
        with self.assertRaises(UnsupportedCall):
            _ = proto.protocol
        with self.assertRaises(UnsupportedCall):
            _ = proto.protochain

    def test_mh_message_readers_and_constructors_cover_known_types(self) -> None:
        from pcapkit.const.mh.binding_error import BindingError
        from pcapkit.const.mh.packet import Packet
        from pcapkit.const.mh.status_code import StatusCode
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.mh import MH

        proto = object.__new__(MH)
        proto._read_mh_options = mock.Mock(return_value='opts')
        proto._make_mh_options = mock.Mock(return_value=['made'])

        def header(type_: Packet) -> SimpleNamespace:
            return SimpleNamespace(next=TransType.UDP, length=2, type=type_, chksum=b'\x12\x34')

        unknown = proto._read_msg_unknown(SimpleNamespace(data=b'raw'), header=header(Packet.get(250)))
        self.assertEqual(unknown.data, b'raw')
        self.assertEqual(proto._read_msg_brr(SimpleNamespace(options=[]),
                                             header=header(Packet.Binding_Refresh_Request)).options, 'opts')
        self.assertEqual(proto._read_msg_hoti(SimpleNamespace(cookie=b'12345678', options=[]),
                                              header=header(Packet.Home_Test_Init)).cookie, b'12345678')
        self.assertEqual(proto._read_msg_coti(SimpleNamespace(cookie=b'abcdefgh', options=[]),
                                              header=header(Packet.Care_of_Test_Init)).cookie, b'abcdefgh')
        hot = proto._read_msg_hot(SimpleNamespace(nonce_index=1, cookie=b'12345678',
                                                  token=b'abcdefgh', options=[]),
                                  header=header(Packet.Home_Test))
        self.assertEqual(hot.token, b'abcdefgh')
        cot = proto._read_msg_cot(SimpleNamespace(nonce_index=2, cookie=b'12345678',
                                                  token=b'ABCDEFGH', options=[]),
                                  header=header(Packet.Care_of_Test))
        self.assertEqual(cot.nonce_index, 2)
        bu = proto._read_msg_bu(SimpleNamespace(seq=3, flags={'A': 1, 'H': 1, 'L': 0, 'K': 1},
                                                lifetime=4, options=[]),
                                header=header(Packet.Binding_Update))
        self.assertTrue(bu.ack)
        self.assertEqual(bu.lifetime, datetime.timedelta(seconds=16))
        ba = proto._read_msg_ba(SimpleNamespace(status=StatusCode.Reason_unspecified,
                                                flags={'K': 1}, seq=4, lifetime=5,
                                                options=[]),
                                header=header(Packet.Binding_Acknowledgement))
        self.assertTrue(ba.key_mngt)
        self.assertEqual(ba.lifetime, datetime.timedelta(seconds=20))
        be = proto._read_msg_be(SimpleNamespace(status=BindingError.Unrecognized_MH_Type_value,
                                                home=ip_address('2001:db8::1'),
                                                options=[]),
                                header=header(Packet.Binding_Error))
        self.assertEqual(str(be.home), '2001:db8::1')

        self.assertEqual(proto._make_msg_unknown(None, data=b'xx').data, b'xx')
        self.assertEqual(proto._make_msg_unknown(SimpleNamespace(data=b'yy')).data, b'yy')
        self.assertEqual(proto._make_msg_brr(None, options=[]).options, ['made'])
        self.assertEqual(proto._make_msg_brr(SimpleNamespace(options=[])).options, ['made'])
        self.assertEqual(proto._make_msg_hoti(None, cookie=b'12345678', options=[]).cookie, b'12345678')
        self.assertEqual(proto._make_msg_hoti(SimpleNamespace(cookie=b'abcdefgh', options=[])).cookie, b'abcdefgh')
        self.assertEqual(proto._make_msg_coti(None, cookie=b'ABCDEFGH', options=[]).cookie, b'ABCDEFGH')
        self.assertEqual(proto._make_msg_coti(SimpleNamespace(cookie=b'87654321', options=[])).cookie, b'87654321')
        self.assertEqual(proto._make_msg_hot(None, nonce_index=7, cookie=b'12345678',
                                             token=b'abcdefgh', options=[]).nonce_index, 7)
        self.assertEqual(proto._make_msg_hot(SimpleNamespace(nonce_index=8, cookie=b'abcdefgh',
                                                             token=b'ABCDEFGH', options=[])).nonce_index, 8)
        self.assertEqual(proto._make_msg_cot(None, nonce_index=9, cookie=b'12345678',
                                             token=b'abcdefgh', options=[]).nonce_index, 9)
        self.assertEqual(proto._make_msg_cot(SimpleNamespace(nonce_index=10, cookie=b'abcdefgh',
                                                             token=b'ABCDEFGH', options=[])).nonce_index, 10)
        self.assertEqual(proto._make_msg_bu(None, seq=11, ack=True, home=True,
                                            lifetime=datetime.timedelta(seconds=9),
                                            options=[]).lifetime, 3)
        self.assertEqual(proto._make_msg_bu(SimpleNamespace(seq=12, ack=False, home=True,
                                                            lla_compat=True, key_mngt=False,
                                                            lifetime=datetime.timedelta(seconds=8),
                                                            options=[])).seq, 12)
        self.assertEqual(proto._make_msg_ba(None, status=StatusCode.Reason_unspecified,
                                            key_mngt=True, seq=13, lifetime=8,
                                            options=[]).seq, 13)
        self.assertEqual(proto._make_msg_ba(SimpleNamespace(status=StatusCode.Reason_unspecified,
                                                            key_mngt=False, seq=14,
                                                            lifetime=datetime.timedelta(seconds=8),
                                                            options=[])).seq, 14)
        self.assertEqual(str(proto._make_msg_be(None, status=BindingError.Unrecognized_MH_Type_value,
                                                home='2001:db8::2', options=[]).home), '2001:db8::2')
        self.assertEqual(str(proto._make_msg_be(SimpleNamespace(
            status=BindingError.Unknown_binding_for_Home_Address_destination_option,
            home=ip_address('2001:db8::3'),
            options=[],
        )).home), '2001:db8::3')

    def test_mh_option_readers_cover_known_options_and_guards(self) -> None:
        from pcapkit.const.mh.auth_subtype import AuthSubtype
        from pcapkit.const.mh.binding_error import BindingError
        from pcapkit.const.mh.cga_extension import CGAExtension
        from pcapkit.const.mh.cga_type import CGAType
        from pcapkit.const.mh.lla_code import LLACode
        from pcapkit.const.mh.mn_id_subtype import MNIDSubtype
        from pcapkit.const.mh.option import Option
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.protocols.schema.internet import mh as schema
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(MH)
        options = OrderedMultiDict()

        parsed = proto._read_mh_options([
            schema.PadOption(type=Option.Pad1, length=0),
            schema.BindingRefreshAdviceOption(type=Option.Binding_Refresh_Advice,
                                              length=2, interval=30),
        ])
        self.assertEqual(list(parsed.keys()), [Option.Pad1, Option.Binding_Refresh_Advice])

        self.assertEqual(proto._read_opt_none(
            schema.UnassignedOption(type=Option.get(250), length=2, data=b'xx'),
            options=options,
        ).data, b'xx')
        self.assertEqual(proto._read_opt_pad(schema.PadOption(type=Option.Pad1, length=0),
                                             options=options).length, 1)
        self.assertEqual(proto._read_opt_pad(schema.PadOption(type=Option.PadN, length=2),
                                             options=options).length, 4)
        for bad in [
            schema.PadOption(type=Option.Binding_Refresh_Advice, length=0),
            schema.PadOption(type=Option.Pad1, length=1),
            schema.PadOption(type=Option.PadN, length=0),
        ]:
            with self.assertRaises(ProtocolError):
                proto._read_opt_pad(bad, options=options)

        self.assertEqual(proto._read_opt_bra(
            schema.BindingRefreshAdviceOption(type=Option.Binding_Refresh_Advice,
                                              length=2, interval=7),
            options=options,
        ).interval, 7)
        self.assertEqual(str(proto._read_opt_aca(
            schema.AlternateCareofAddressOption(type=Option.Alternate_Care_of_Address,
                                                length=16, address='2001:db8::1'),
            options=options,
        ).address), '2001:db8::1')
        self.assertEqual(proto._read_opt_ni(
            schema.NonceIndicesOption(type=Option.Nonce_Indices, length=4, home=1, careof=2),
            options=options,
        ).careof, 2)
        self.assertEqual(proto._read_opt_bad(
            schema.AuthorizationDataOption(type=Option.Authorization_Data, length=8, data=b'12345678'),
            options=options,
        ).data, b'12345678')
        self.assertEqual(str(proto._read_opt_mnp(
            schema.MobileNetworkPrefixOption(type=Option.Mobile_Network_Prefix_Option,
                                             length=18, prefix_length=64,
                                             prefix='2001:db8::'),
            options=options,
        ).prefix), '2001:db8::/64')
        self.assertEqual(proto._read_opt_lla(
            schema.LinkLayerAddressOption(type=Option.Mobility_Header_Link_Layer_Address_option,
                                          length=7, code=LLACode.MH, lla=b'abcdef'),
            options=options,
        ).lla, b'abcdef')
        self.assertEqual(proto._read_opt_mn_id(
            schema.MNIDOption(type=Option.MN_ID_OPTION_TYPE, length=17,
                              subtype=MNIDSubtype.IPv6_Address,
                              identifier='2001:db8::2'),
            options=options,
        ).subtype, MNIDSubtype.IPv6_Address)
        self.assertEqual(proto._read_opt_auth(
            schema.AuthOption(type=Option.AUTH_OPTION_TYPE, length=7,
                              subtype=AuthSubtype.MN_HA, spi=99, data=b'ab'),
            options=options,
        ).spi, 99)
        mesg = SimpleNamespace(type=Option.MESG_ID_OPTION_TYPE, length=8,
                               timestamp=datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc),
                               seconds=1, fraction=2)
        self.assertEqual(proto._read_opt_mesg_id(mesg, options=options).ntp_timestamp.seconds, 1)
        self.assertEqual(proto._read_opt_cga_pr(
            schema.CGAParametersRequestOption(type=Option.CGA_Parameters_Request, length=0),
            options=options,
        ).length, 2)

        cga_param = SimpleNamespace(
            modifier=CGAType.Tag_086F_CA5E_10B2_00C9_9C8C_E001_6427_7C08,
            prefix=1,
            collision_count=1,
            public_key=b'key',
            extensions=[],
        )
        cga = proto._read_opt_cga_param(
            SimpleNamespace(type=Option.CGA_Parameters, length=1, parameters=[cga_param]),
            options=options,
        )
        self.assertEqual(cga.parameters[0].collision_count, 1)
        cga_param.collision_count = 3
        with self.assertRaises(ProtocolError):
            proto._read_opt_cga_param(SimpleNamespace(type=Option.CGA_Parameters,
                                                      length=1, parameters=[cga_param]),
                                      options=options)

        self.assertEqual(proto._read_opt_signature(
            schema.SignatureOption(type=Option.Signature, length=3, signature=b'sig'),
            options=options,
        ).signature, b'sig')
        self.assertEqual(proto._read_opt_phkt(
            schema.PermanentHomeKeygenTokenOption(type=Option.Permanent_Home_Keygen_Token,
                                                  length=3, token=b'tok'),
            options=options,
        ).token, b'tok')
        self.assertEqual(proto._read_opt_ct_init(
            schema.CareofTestInitOption(type=Option.Care_of_Test_Init, length=0),
            options=options,
        ).length, 2)
        self.assertEqual(proto._read_opt_ct(
            schema.CareofTestOption(type=Option.Care_of_Test, length=8, token=b'12345678'),
            options=options,
        ).token, b'12345678')

        ext = proto._read_cga_extensions([
            schema.UnknownExtension(type=CGAExtension.Exp_FFFD, length=2, data=b'xx'),
            schema.MultiPrefixExtension(type=CGAExtension.Multi_Prefix, length=20,
                                        flags={'P': 1}, prefixes=[1, 2]),
        ])
        self.assertEqual(list(ext.keys()), [CGAExtension.Exp_FFFD, CGAExtension.Multi_Prefix])
        self.assertEqual(proto._read_ext_none(
            schema.UnknownExtension(type=CGAExtension.Exp_FFFE, length=2, data=b'yy'),
            extensions=ext,
        ).data, b'yy')
        self.assertTrue(proto._read_ext_multiprefix(
            schema.MultiPrefixExtension(type=CGAExtension.Multi_Prefix, length=20,
                                        flags={'P': 1}, prefixes=[1]),
            extensions=ext,
        ).flag)

        invalid_cases = [
            (proto._read_opt_bra, schema.BindingRefreshAdviceOption(
                type=Option.Binding_Refresh_Advice, length=1, interval=7)),
            (proto._read_opt_aca, schema.AlternateCareofAddressOption(
                type=Option.Alternate_Care_of_Address, length=15, address='2001:db8::1')),
            (proto._read_opt_ni, schema.NonceIndicesOption(
                type=Option.Nonce_Indices, length=3, home=1, careof=2)),
            (proto._read_opt_bad, schema.AuthorizationDataOption(
                type=Option.Authorization_Data, length=7, data=b'1234567')),
            (proto._read_opt_mnp, schema.MobileNetworkPrefixOption(
                type=Option.Mobile_Network_Prefix_Option, length=17,
                prefix_length=64, prefix='2001:db8::')),
            (proto._read_opt_lla, schema.LinkLayerAddressOption(
                type=Option.Mobility_Header_Link_Layer_Address_option, length=7,
                code=LLACode.NAR, lla=b'abcdef')),
            (proto._read_opt_auth, schema.AuthOption(
                type=Option.AUTH_OPTION_TYPE, length=6,
                subtype=AuthSubtype.MN_HA, spi=99, data=b'a')),
            (proto._read_opt_mesg_id, mesg | {'length': 7} if isinstance(mesg, dict) else SimpleNamespace(
                type=Option.MESG_ID_OPTION_TYPE, length=7,
                timestamp=datetime.datetime.now(datetime.timezone.utc),
                seconds=1, fraction=2)),
            (proto._read_opt_cga_pr, schema.CGAParametersRequestOption(
                type=Option.CGA_Parameters_Request, length=1)),
            (proto._read_opt_ct_init, schema.CareofTestInitOption(
                type=Option.Care_of_Test_Init, length=1)),
            (proto._read_opt_ct, schema.CareofTestOption(
                type=Option.Care_of_Test, length=7, token=b'12345678')),
        ]
        for reader, bad_schema in invalid_cases:
            with self.assertRaises(ProtocolError):
                reader(bad_schema, options=options)

    def test_mh_option_constructors_cover_known_options_and_dispatch(self) -> None:
        from pcapkit.const.mh.auth_subtype import AuthSubtype
        from pcapkit.const.mh.cga_extension import CGAExtension
        from pcapkit.const.mh.cga_type import CGAType
        from pcapkit.const.mh.mn_id_subtype import MNIDSubtype
        from pcapkit.const.mh.option import Option
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.data.internet import mh as data
        from pcapkit.protocols.internet.mh import MH, NTPTimestamp
        from pcapkit.protocols.schema.internet import mh as schema
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(MH)
        self.assertEqual(proto._make_opt_none(Option.get(250), data=b'xx').data, b'xx')
        self.assertEqual(proto._make_opt_none(Option.get(250),
                                              data.UnassignedOption(type=Option.get(250),
                                                                    length=4,
                                                                    data=b'yy')).data, b'yy')
        with mock.patch('pcapkit.protocols.internet.mh.warn') as warn:
            self.assertEqual(proto._make_opt_pad(Option.Pad1, length=2).type, Option.PadN)
            self.assertEqual(proto._make_opt_pad(Option.PadN, length=0).type, Option.Pad1)
        self.assertEqual(warn.call_count, 2)

        self.assertEqual(proto._make_opt_bra(Option.Binding_Refresh_Advice, interval=9).interval, 9)
        self.assertEqual(str(proto._make_opt_aca(Option.Alternate_Care_of_Address,
                                                 address='2001:db8::1').address), '2001:db8::1')
        self.assertEqual(proto._make_opt_ni(Option.Nonce_Indices, home=1, careof=2).careof, 2)
        self.assertEqual(proto._make_opt_bad(Option.Authorization_Data, data=b'12345678').data, b'12345678')
        with self.assertRaises(ProtocolError):
            proto._make_opt_bad(Option.Authorization_Data, data=b'bad')
        self.assertEqual(str(proto._make_opt_mnp(Option.Mobile_Network_Prefix_Option,
                                                 prefix='2001:db8::/64').prefix), '2001:db8::')
        with self.assertRaises(ProtocolError):
            proto._make_opt_mnp(Option.Mobile_Network_Prefix_Option, prefix='192.0.2.0/24')
        self.assertEqual(proto._make_opt_lla(Option.Mobility_Header_Link_Layer_Address_option,
                                             address=b'abcdef').lla, b'abcdef')
        self.assertEqual(proto._make_opt_mn_id(Option.MN_ID_OPTION_TYPE,
                                               subtype=MNIDSubtype.IPv6_Address,
                                               identifier=ip_address('2001:db8::1')).length, 17)
        self.assertEqual(proto._make_opt_mn_id(Option.MN_ID_OPTION_TYPE,
                                               subtype=MNIDSubtype.NAI,
                                               identifier='node@example').length, 13)
        self.assertEqual(proto._make_opt_mn_id(Option.MN_ID_OPTION_TYPE,
                                               identifier=0x1234).length, 3)
        self.assertEqual(proto._make_opt_auth(Option.AUTH_OPTION_TYPE, subtype=AuthSubtype.MN_HA,
                                              spi=7, data=b'ab').spi, 7)
        with self.assertRaises(ProtocolError):
            proto._make_opt_auth(Option.AUTH_OPTION_TYPE, data=b'a')
        self.assertEqual(proto._make_opt_mesg_id(
            Option.MESG_ID_OPTION_TYPE,
            timestamp=NTPTimestamp(seconds=1, fraction=2),
        ).seconds, 1)
        self.assertGreater(proto._make_opt_mesg_id(
            Option.MESG_ID_OPTION_TYPE,
            interval=datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc),
        ).seconds, 2_208_988_800)
        self.assertEqual(proto._make_opt_cga_pr(Option.CGA_Parameters_Request).length, 0)

        cga_data = data.CGAParameter(
            modifier=CGAType.Tag_086F_CA5E_10B2_00C9_9C8C_E001_6427_7C08,
            prefix=1,
            collision_count=1,
            public_key=b'\x01\x01x',
            extensions=[],
        )
        self.assertGreaterEqual(proto._make_opt_cga_param(
            Option.CGA_Parameters,
            parameters=[b'raw', cga_data],
        ).length, 3)
        with self.assertRaises(ProtocolError):
            proto._make_opt_cga_param(Option.CGA_Parameters, parameters=[{'bad': True}])

        self.assertEqual(proto._make_opt_signature(Option.Signature, signature=b'sig').signature, b'sig')
        self.assertEqual(proto._make_opt_phkt(Option.Permanent_Home_Keygen_Token, token=b'tok').token, b'tok')
        self.assertEqual(proto._make_opt_ct_init(Option.Care_of_Test_Init).length, 0)
        self.assertEqual(proto._make_opt_ct(Option.Care_of_Test, token=b'12345678').token, b'12345678')

        option_list = proto._make_mh_options([
            b'\x00',
            schema.PadOption(type=Option.Pad1, length=0),
            (Option.Binding_Refresh_Advice, {'interval': 7}),
        ])
        self.assertEqual(len(option_list), 3)
        option_dict = OrderedMultiDict([
            (Option.Binding_Refresh_Advice,
             data.BindingRefreshAdviceOption(type=Option.Binding_Refresh_Advice,
                                              length=4, interval=11)),
        ])
        self.assertEqual(proto._make_mh_options(option_dict)[0].interval, 11)

        self.assertEqual(proto._make_ext_none(CGAExtension.Exp_FFFD, data=b'xx').data, b'xx')
        self.assertEqual(proto._make_ext_none(
            CGAExtension.Exp_FFFE,
            data.UnknownExtension(type=CGAExtension.Exp_FFFE, length=4, data=b'yy'),
        ).data, b'yy')
        self.assertTrue(proto._make_ext_multiprefix(
            CGAExtension.Multi_Prefix,
            flag=True,
            prefixes=[1, 2],
        ).flags['P'])
        self.assertTrue(proto._make_ext_multiprefix(
            CGAExtension.Multi_Prefix,
            data.MultiPrefixExtension(type=CGAExtension.Multi_Prefix,
                                      length=20, flag=True, prefixes=(3,)),
        ).flags['P'])
        ext_list, ext_len = proto._make_cga_extensions([
            b'\xff\xfd\x00\x02xx',
            schema.UnknownExtension(type=CGAExtension.Exp_FFFE, length=2, data=b'yy'),
            (CGAExtension.Multi_Prefix, {'flag': True, 'prefixes': [1]}),
        ])
        self.assertEqual(len(ext_list), 3)
        self.assertGreater(ext_len, 0)
        ext_dict = OrderedMultiDict([
            (CGAExtension.Exp_FFFF,
             data.UnknownExtension(type=CGAExtension.Exp_FFFF, length=4, data=b'zz')),
        ])
        self.assertEqual(proto._make_cga_extensions(ext_dict)[0][0].data, b'zz')

    def test_mh_callable_registry_data_model_and_property_edges(self) -> None:
        from pcapkit.const.mh.auth_subtype import AuthSubtype
        from pcapkit.const.mh.cga_extension import CGAExtension
        from pcapkit.const.mh.cga_type import CGAType
        from pcapkit.const.mh.lla_code import LLACode
        from pcapkit.const.mh.mn_id_subtype import MNIDSubtype
        from pcapkit.const.mh.option import Option
        from pcapkit.const.mh.packet import Packet
        from pcapkit.const.mh.status_code import StatusCode
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.data.internet import mh as data
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.internet.mh import MH, NTPTimestamp
        from pcapkit.protocols.schema.internet import mh as schema

        proto = object.__new__(MH)
        proto._extf = False
        proto._info = DummyDict(length=16)
        proto._data = b'\x00' * 16
        proto.__cached__ = {}
        proto._next = 'payload'
        proto._protos = ['UDP']

        self.assertEqual(proto.payload, 'payload')
        self.assertEqual(proto.protocol, 'UDP')
        self.assertEqual(proto.protochain, ['UDP'])

        with mock.patch.object(Internet, '__post_init__', return_value=None) as post_init:
            post_proto = object.__new__(MH)
            post_proto.__post_init__(extension=True, custom=True)
        self.assertTrue(post_proto._extf)
        post_init.assert_called_once()

        custom_packet = Packet.get(250)
        custom_option = Option.get(250)
        custom_extension = CGAExtension.get(0xfffc)
        message_map = MH.__dict__['__message__']
        option_map = MH.__dict__['__option__']
        extension_map = MH.__dict__['__extension__']
        original_message = message_map.get(custom_packet)
        original_option = option_map.get(custom_option)
        original_extension = extension_map.get(custom_extension)

        def parse_message(packet: SimpleNamespace, *, header: SimpleNamespace) -> SimpleNamespace:
            return SimpleNamespace(type=header.type, length=6, data=packet.data)

        def make_message(message: data.MH | None = None, *, value: bytes = b'') -> bytes:
            return message.data if message is not None else value

        def parse_option(packet: SimpleNamespace, *, options: OrderedMultiDict) -> data.UnassignedOption:
            return data.UnassignedOption(type=packet.type, length=len(packet.data), data=packet.data)

        def make_option(code: Option, option: data.UnassignedOption | None = None, *,
                        value: bytes = b'') -> schema.UnassignedOption:
            if option is not None:
                value = option.data
            return schema.UnassignedOption(type=code, length=len(value), data=value)

        def parse_extension(packet: schema.UnknownExtension, *,
                            extensions: OrderedMultiDict) -> data.UnknownExtension:
            return data.UnknownExtension(type=packet.type, length=packet.length, data=packet.data)

        def make_extension(code: CGAExtension, extension: data.UnknownExtension | None = None, *,
                           value: bytes = b'') -> schema.UnknownExtension:
            if extension is not None:
                value = extension.data
            return schema.UnknownExtension(type=code, length=len(value), data=value)

        try:
            with mock.patch('pcapkit.protocols.internet.mh.warn') as warn:
                MH.register_message(custom_packet, (parse_message, make_message))
                MH.register_option(custom_option, (parse_option, make_option))
                MH.register_extension(custom_extension, (parse_extension, make_extension))
            warn.assert_not_called()

            proto.__header__ = SimpleNamespace(
                next=TransType.UDP,
                type=custom_packet,
                data=SimpleNamespace(data=b'read'),
            )
            self.assertEqual(proto.read(extension=True).data, b'read')
            self.assertEqual(proto.make(type=custom_packet, data={'value': b'dict'}).data, b'dict')
            unknown_message = data.UnknownMessage(
                next=TransType.UDP,
                length=2,
                type=custom_packet,
                chksum=b'',
                data=b'model',
            )
            self.assertEqual(proto.make(type=custom_packet, data=unknown_message).data, b'model')

            parsed_options = proto._read_mh_options([
                SimpleNamespace(type=custom_option, data=b'opt'),
            ])
            self.assertEqual(parsed_options[custom_option].data, b'opt')
            self.assertEqual(proto._make_mh_options([
                (custom_option, {'value': b'list'}),
            ])[0].data, b'list')
            option_dict = OrderedMultiDict([
                (custom_option, data.UnassignedOption(type=custom_option, length=4, data=b'dict')),
            ])
            self.assertEqual(proto._make_mh_options(option_dict)[0].data, b'dict')

            parsed_extensions = proto._read_cga_extensions([
                schema.UnknownExtension(type=custom_extension, length=3, data=b'ext'),
            ])
            self.assertEqual(parsed_extensions[custom_extension].data, b'ext')
            self.assertEqual(proto._make_cga_extensions([
                (custom_extension, {'value': b'list'}),
            ])[0][0].data, b'list')
            extension_dict = OrderedMultiDict([
                (custom_extension, data.UnknownExtension(type=custom_extension, length=4, data=b'dict')),
            ])
            self.assertEqual(proto._make_cga_extensions(extension_dict)[0][0].data, b'dict')

            cga_data = data.CGAParameter(
                modifier=CGAType.Tag_086F_CA5E_10B2_00C9_9C8C_E001_6427_7C08,
                prefix=1,
                collision_count=1,
                public_key=b'\x01\x01x',
                extensions=[],
            )
            cga_schema = schema.CGAParameter(
                modifier=CGAType.Tag_086F_CA5E_10B2_00C9_9C8C_E001_6427_7C08,
                prefix=1,
                collision_count=1,
                public_key=b'\x01\x01y',
                extensions=[],
            )
            cga_schema_missing_test = schema.CGAParameter(
                modifier=CGAType.Tag_086F_CA5E_10B2_00C9_9C8C_E001_6427_7C08,
                prefix=1,
                collision_count=1,
                public_key=b'\x01\x01z',
                extensions=[],
            )
            cga_option = data.CGAParametersOption(
                type=Option.CGA_Parameters,
                length=28,
                parameters=(cga_data,),
            )
            self.assertEqual(proto._make_opt_cga_param(Option.CGA_Parameters).parameters, [])
            self.assertGreater(proto._make_opt_cga_param(Option.CGA_Parameters, cga_option).length, 0)
            self.assertGreater(proto._make_opt_cga_param(
                Option.CGA_Parameters,
                parameters=[cga_schema],
            ).length, 0)
            public_key_test = schema.CGAParameter.public_key_test
            try:
                delattr(schema.CGAParameter, 'public_key_test')
                self.assertGreater(proto._make_opt_cga_param(
                    Option.CGA_Parameters,
                    parameters=[cga_schema_missing_test],
                ).length, 0)
            finally:
                schema.CGAParameter.public_key_test = public_key_test

            self.assertEqual(proto._make_opt_pad(
                Option.Pad1,
                data.PadOption(type=Option.PadN, length=4),
            ).length, 4)
            self.assertEqual(str(proto._make_opt_aca(
                Option.Alternate_Care_of_Address,
                data.AlternateCareofAddressOption(type=Option.Alternate_Care_of_Address,
                                                  length=16,
                                                  address=ip_address('2001:db8::4')),
            ).address), '2001:db8::4')
            self.assertEqual(proto._make_opt_ni(
                Option.Nonce_Indices,
                data.NonceIndicesOption(type=Option.Nonce_Indices, length=4,
                                        home=7, careof=8),
            ).home, 7)
            self.assertEqual(proto._make_opt_bad(
                Option.Authorization_Data,
                data.AuthorizationDataOption(type=Option.Authorization_Data,
                                             length=8, data=b'12345678'),
            ).data, b'12345678')
            self.assertEqual(proto._make_opt_mnp(
                Option.Mobile_Network_Prefix_Option,
                data.MobileNetworkPrefixOption(type=Option.Mobile_Network_Prefix_Option,
                                               length=18,
                                               prefix=ip_network('2001:db8:1::/64')),
            ).prefix_length, 64)
            self.assertEqual(proto._make_opt_lla(
                Option.Mobility_Header_Link_Layer_Address_option,
                data.LinkLayerAddressOption(type=Option.Mobility_Header_Link_Layer_Address_option,
                                            length=7, code=LLACode.MH, lla=b'abcdef'),
            ).lla, b'abcdef')
            self.assertEqual(proto._make_opt_mn_id(
                Option.MN_ID_OPTION_TYPE,
                data.MNIDOption(type=Option.MN_ID_OPTION_TYPE,
                                length=17,
                                subtype=MNIDSubtype.IPv6_Address,
                                identifier=ip_address('2001:db8::5')),
            ).length, 17)
            self.assertEqual(proto._make_opt_auth(
                Option.AUTH_OPTION_TYPE,
                data.AuthOption(type=Option.AUTH_OPTION_TYPE,
                                length=7,
                                subtype=AuthSubtype.MN_HA,
                                spi=9,
                                data=b'ab'),
            ).spi, 9)
            self.assertEqual(proto._make_opt_mesg_id(
                Option.MESG_ID_OPTION_TYPE,
                data.MesgIDOption(type=Option.MESG_ID_OPTION_TYPE,
                                  length=8,
                                  timestamp=datetime.datetime(2026, 1, 1,
                                                              tzinfo=datetime.timezone.utc),
                                  ntp_timestamp=NTPTimestamp(seconds=1, fraction=2)),
            ).fraction, 2)
            self.assertEqual(proto._make_opt_signature(
                Option.Signature,
                data.SignatureOption(type=Option.Signature, length=3, signature=b'sig'),
            ).signature, b'sig')
            self.assertEqual(proto._make_opt_phkt(
                Option.Permanent_Home_Keygen_Token,
                data.PermanentHomeKeygenTokenOption(type=Option.Permanent_Home_Keygen_Token,
                                                    length=3, token=b'tok'),
            ).token, b'tok')
            self.assertEqual(proto._make_opt_ct(
                Option.Care_of_Test,
                data.CareofTestOption(type=Option.Care_of_Test, length=8, token=b'12345678'),
            ).token, b'12345678')

            self.assertEqual(proto._make_msg_ba(
                data.BindingAcknowledgementMessage(
                    next=TransType.UDP,
                    length=12,
                    type=Packet.Binding_Acknowledgement,
                    chksum=b'',
                    status=StatusCode.Reason_unspecified,
                    key_mngt=True,
                    seq=1,
                    lifetime=datetime.timedelta(seconds=8),
                    options=OrderedMultiDict(),
                ),
            ).seq, 1)
        finally:
            if original_message is None:
                message_map.pop(custom_packet, None)
            else:
                message_map[custom_packet] = original_message
            if original_option is None:
                option_map.pop(custom_option, None)
            else:
                option_map[custom_option] = original_option
            if original_extension is None:
                extension_map.pop(custom_extension, None)
            else:
                extension_map[custom_extension] = original_extension

    def test_mh_schema_selectors_and_option_post_process_branches(self) -> None:
        from pcapkit.const.mh.mn_id_subtype import MNIDSubtype
        from pcapkit.const.mh.option import Option
        from pcapkit.const.mh.packet import Packet
        from pcapkit.protocols.schema.internet import mh as schema

        message_field = schema.mh_data_selector({
            'type': Packet.Binding_Refresh_Request,
            'length': 1,
        })
        self.assertIs(message_field.schema, schema.BindingRefreshRequestMessage)
        self.assertEqual(message_field.length, 10)

        nai_field = schema.mn_id_selector({'subtype': MNIDSubtype.NAI, 'length': 4})
        self.assertEqual(type(nai_field).__name__, 'StringField')
        self.assertEqual(nai_field.length, 3)
        ip_field = schema.mn_id_selector({'subtype': MNIDSubtype.IPv6_Address, 'length': 17})
        self.assertEqual(type(ip_field).__name__, 'IPv6AddressField')
        raw_field = schema.mn_id_selector({'subtype': MNIDSubtype.IMSI, 'length': 4})
        self.assertEqual(type(raw_field).__name__, 'BytesField')
        self.assertEqual(raw_field.length, 3)

        pad1 = schema.PadOption(type=Option.Pad1, length=99)
        self.assertEqual(pad1.post_process({}).length, 0)
        padn = schema.PadOption(type=Option.PadN, length=3)
        self.assertEqual(padn.post_process({}).length, 3)

        mesg_id = schema.MesgIDOption(
            type=Option.MESG_ID_OPTION_TYPE,
            length=8,
            seconds=2_208_988_800,
            fraction=0,
        )
        mesg_id.post_process({})
        self.assertEqual(mesg_id.timestamp, datetime.datetime.fromtimestamp(
            0,
            tz=datetime.timezone.utc,
        ))


if __name__ == '__main__':
    unittest.main()
