from __future__ import annotations

import datetime
import io
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

            # NOTE: The data model's ``length`` is the whole option, the schema's is
            # its ``Option Length`` field. A 4-octet ``PadN`` spends 2 octets on its
            # type and length fields, so ``Option Length`` is 2 and the schema packs
            # back to the 4 octets the data model described. Asserting 4 here was
            # asserting the two-octet overshoot.
            remade = proto._make_opt_pad(
                Option.Pad1,
                data.PadOption(type=Option.PadN, length=4),
            )
            self.assertEqual(remade.length, 2)
            self.assertEqual(len(remade.pack()), 4)
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

    def test_mh_fmipv6_message_readers_and_constructors(self) -> None:
        from pcapkit.const.mh.handover_ack_status import HandoverACKStatus
        from pcapkit.const.mh.handover_initiate_status import HandoverInitiateStatus
        from pcapkit.const.mh.packet import Packet
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.mh import MH, FastBindingAcknowledgmentStatus

        proto = object.__new__(MH)
        proto._read_mh_options = mock.Mock(return_value='opts')
        proto._make_mh_options = mock.Mock(return_value=['made'])

        def header(type_: Packet) -> SimpleNamespace:
            return SimpleNamespace(next=TransType.UDP, length=5, type=type_, chksum=b'\x12\x34')

        # RFC 5568, section 6.2.2 -- FBU is identical to the RFC 6275 BU, so the
        # lifetime is carried in units of 4 seconds.
        fbu = proto._read_msg_fbu(SimpleNamespace(seq=0x1234,
                                                 flags={'A': 1, 'H': 1, 'L': 0, 'K': 1},
                                                 lifetime=10, options=[]),
                                  header=header(Packet.Fast_Binding_Update))
        self.assertEqual(fbu.seq, 0x1234)
        self.assertTrue(fbu.ack)
        self.assertTrue(fbu.home)
        self.assertFalse(fbu.lla_compat)
        self.assertTrue(fbu.key_mngt)
        self.assertEqual(fbu.lifetime, datetime.timedelta(seconds=40))
        self.assertEqual(fbu.options, 'opts')

        # RFC 5568, section 6.2.3 -- status 1 is "FBU accepted but NCoA is invalid",
        # which is *not* what StatusCode(1) means, hence the module-local enum.
        fback = proto._read_msg_fback(SimpleNamespace(status=1, flags={'K': 1}, seq=0x1234,
                                                     lifetime=10, options=[]),
                                     header=header(Packet.Fast_Binding_Acknowledgment))
        self.assertEqual(fback.status, 1)
        self.assertIs(fback.status,
                      FastBindingAcknowledgmentStatus.Fast_Binding_Update_accepted_but_NCoA_is_invalid)
        self.assertNotIsInstance(fback.status, type(HandoverACKStatus.Administratively_prohibited))
        self.assertTrue(fback.key_mngt)
        self.assertEqual(fback.seq, 0x1234)
        self.assertEqual(fback.lifetime, datetime.timedelta(seconds=40))

        # RFC 4068, section 6.3.3 -- two reserved octets, then mobility options.
        fna = proto._read_msg_fna(SimpleNamespace(options=[]),
                                  header=header(Packet.Fast_Neighbor_Advertisement))
        self.assertEqual(fna.options, 'opts')
        self.assertEqual(fna.type, Packet.Fast_Neighbor_Advertisement)

        # RFC 5096, section 3 -- opaque message data, no fields of its own.
        emh = proto._read_msg_emh(SimpleNamespace(data=b'\xde\xad\xbe\xef'),
                                  header=header(Packet.Experimental_Mobility_Header))
        self.assertEqual(emh.data, b'\xde\xad\xbe\xef')

        # RFC 5568, section 6.2.1.1 and RFC 5949, section 6.1.1.
        hi = proto._read_msg_hi(SimpleNamespace(
            seq=0x0102,
            flags={'S': 1, 'U': 0, 'P': 1, 'F': 0},
            code=HandoverInitiateStatus.FBU_whose_source_IP_address_is_not_PCoA,
            options=[],
        ), header=header(Packet.Handover_Initiate_Message))
        self.assertEqual(hi.seq, 0x0102)
        self.assertTrue(hi.assign)
        self.assertFalse(hi.buffer)
        self.assertTrue(hi.proxy)
        self.assertFalse(hi.forward)
        self.assertEqual(hi.code, HandoverInitiateStatus.FBU_whose_source_IP_address_is_not_PCoA)

        # RFC 5568, section 6.2.1.2 and RFC 5949, section 6.1.2.
        hack = proto._read_msg_hack(SimpleNamespace(
            seq=0x0102,
            flags={'U': 1, 'P': 0, 'F': 1},
            code=HandoverACKStatus.Handover_Accepted_NCoA_assigned,
            options=[],
        ), header=header(Packet.Handover_Acknowledge_Message))
        self.assertEqual(hack.seq, 0x0102)
        self.assertTrue(hack.buffer)
        self.assertFalse(hack.proxy)
        self.assertTrue(hack.forward)
        self.assertEqual(hack.code, HandoverACKStatus.Handover_Accepted_NCoA_assigned)

        # constructors, both from keyword arguments and from a data model
        made_fbu = proto._make_msg_fbu(None, seq=7, ack=True, home=True, key_mngt=True,
                                       lifetime=datetime.timedelta(seconds=40), options=[])
        self.assertEqual(made_fbu.seq, 7)
        self.assertEqual(made_fbu.lifetime, 10)
        self.assertEqual(made_fbu.flags, {'A': True, 'H': True, 'L': False, 'K': True})
        self.assertEqual(proto._make_msg_fbu(SimpleNamespace(
            seq=8, ack=False, home=True, lla_compat=True, key_mngt=False,
            lifetime=datetime.timedelta(seconds=8), options=[],
        )).seq, 8)

        made_fback = proto._make_msg_fback(None, status=131, key_mngt=True, seq=9, lifetime=40,
                                           options=[])
        self.assertEqual(made_fback.status, 131)
        self.assertEqual(made_fback.lifetime, 10)
        self.assertEqual(proto._make_msg_fback(
            None, status=FastBindingAcknowledgmentStatus.Insufficient_resources, options=[],
        ).status, 130)
        self.assertEqual(proto._make_msg_fback(
            None, status='Administratively_prohibited', options=[],
            status_namespace=FastBindingAcknowledgmentStatus,
        ).status, 129)
        self.assertEqual(proto._make_msg_fback(SimpleNamespace(
            status=FastBindingAcknowledgmentStatus.Fast_Binding_Update_accepted_but_NCoA_is_invalid,
            key_mngt=False, seq=10, lifetime=datetime.timedelta(seconds=8), options=[],
        )).seq, 10)

        self.assertEqual(proto._make_msg_fna(None, options=[]).options, ['made'])
        self.assertEqual(proto._make_msg_fna(SimpleNamespace(options=[])).options, ['made'])

        self.assertEqual(proto._make_msg_emh(None).data, b'\x00\x00')
        self.assertEqual(proto._make_msg_emh(None, data=b'raw').data, b'raw')
        self.assertEqual(proto._make_msg_emh(SimpleNamespace(data=b'model')).data, b'model')

        made_hi = proto._make_msg_hi(None, seq=11, assign=True, buffer=False, proxy=True,
                                     forward=False, code=1, options=[])
        self.assertEqual(made_hi.seq, 11)
        self.assertEqual(made_hi.code, HandoverInitiateStatus.FBU_whose_source_IP_address_is_not_PCoA)
        self.assertEqual(made_hi.flags, {'S': True, 'U': False, 'P': True, 'F': False})
        self.assertEqual(proto._make_msg_hi(SimpleNamespace(
            seq=12, assign=False, buffer=True, proxy=False, forward=True,
            code=HandoverInitiateStatus.All_available_context_transferred, options=[],
        )).seq, 12)

        made_hack = proto._make_msg_hack(None, seq=13, buffer=True, proxy=False, forward=True,
                                         code=130, options=[])
        self.assertEqual(made_hack.seq, 13)
        self.assertEqual(made_hack.code, HandoverACKStatus.Insufficient_resources)
        self.assertEqual(made_hack.flags, {'U': True, 'P': False, 'F': True})
        self.assertEqual(proto._make_msg_hack(SimpleNamespace(
            seq=14, buffer=False, proxy=True, forward=False,
            code=HandoverACKStatus.Handover_Accepted_use_PCoA, options=[],
        )).seq, 14)

    def test_mh_fmipv6_option_readers_constructors_and_guards(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.data.internet import mh as data
        from pcapkit.protocols.internet.mh import MH, IPv6AddressPrefixCode
        from pcapkit.protocols.schema.internet import mh as schema
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(MH)
        options = OrderedMultiDict()

        # RFC 5096, section 4 -- opaque experimental data.
        exp = proto._read_opt_exp(
            schema.ExperimentalMobilityOption(type=Option.Experimental_Mobility_Option,
                                              length=6, data=b'\x01\x02\x03\x04\x05\x06'),
            options=options,
        )
        self.assertEqual(exp.data, b'\x01\x02\x03\x04\x05\x06')
        self.assertEqual(exp.length, 8)

        # RFC 5568, section 6.4.5 -- the option length counts the authenticator only,
        # so the reported total length is 6 bytes longer (2 header + 4 SPI).
        badf = proto._read_opt_badf(
            schema.BADFOption(type=Option.Binding_Authorization_Data_for_FMIPv6,
                              length=12, spi=0xdeadbeef, data=bytes(range(12))),
            options=options,
        )
        self.assertEqual(badf.spi, 0xdeadbeef)
        self.assertEqual(badf.data, bytes(range(12)))
        self.assertEqual(badf.length, 18)

        # RFC 5568, section 6.4.2 (type corrected to 34 by errata ID 1816).
        apfx = proto._read_opt_ipv6_ap(
            schema.IPv6AddressPrefixOption(type=Option.Mobility_Header_IPv6_Address_Prefix,
                                           length=18, code=4, prefix_length=64,
                                           address='2001:db8:2::'),
            options=options,
        )
        self.assertEqual(apfx.code, 4)
        self.assertIs(apfx.code, IPv6AddressPrefixCode.NAR_Prefix)
        self.assertEqual(apfx.prefix_length, 64)
        self.assertEqual(str(apfx.address), '2001:db8:2::')
        self.assertEqual(apfx.length, 20)

        for reader, bad_schema in [
            # an authenticator of zero bytes cannot authenticate anything
            (proto._read_opt_badf, schema.BADFOption(
                type=Option.Binding_Authorization_Data_for_FMIPv6,
                length=0, spi=1, data=b'')),
            # the address/prefix option is a fixed 18 bytes of option data
            (proto._read_opt_ipv6_ap, schema.IPv6AddressPrefixOption(
                type=Option.Mobility_Header_IPv6_Address_Prefix,
                length=17, code=2, prefix_length=64, address='2001:db8:2::')),
            # "The value ranges from 0 to 128", RFC 5568, section 6.4.2
            (proto._read_opt_ipv6_ap, schema.IPv6AddressPrefixOption(
                type=Option.Mobility_Header_IPv6_Address_Prefix,
                length=18, code=2, prefix_length=129, address='2001:db8:2::')),
        ]:
            with self.assertRaises(ProtocolError):
                reader(bad_schema, options=options)

        self.assertEqual(proto._make_opt_exp(Option.Experimental_Mobility_Option,
                                             data=b'\x01\x02').length, 2)
        self.assertEqual(proto._make_opt_exp(
            Option.Experimental_Mobility_Option,
            data.ExperimentalMobilityOption(type=Option.Experimental_Mobility_Option,
                                            length=4, data=b'\x03\x04'),
        ).data, b'\x03\x04')

        made_badf = proto._make_opt_badf(Option.Binding_Authorization_Data_for_FMIPv6,
                                         spi=0xdeadbeef, data=bytes(range(12)))
        self.assertEqual(made_badf.length, 12)
        self.assertEqual(made_badf.spi, 0xdeadbeef)
        self.assertEqual(proto._make_opt_badf(
            Option.Binding_Authorization_Data_for_FMIPv6,
            data.BADFOption(type=Option.Binding_Authorization_Data_for_FMIPv6,
                            length=18, spi=7, data=bytes(range(12))),
        ).spi, 7)
        with self.assertRaises(ProtocolError):
            proto._make_opt_badf(Option.Binding_Authorization_Data_for_FMIPv6, data=b'')

        made_apfx = proto._make_opt_ipv6_ap(Option.Mobility_Header_IPv6_Address_Prefix,
                                            code=1, prefix_length=128, address='2001:db8:1::2')
        self.assertEqual(made_apfx.length, 18)
        self.assertEqual(made_apfx.code, 1)
        self.assertEqual(proto._make_opt_ipv6_ap(
            Option.Mobility_Header_IPv6_Address_Prefix,
            code=IPv6AddressPrefixCode.NAR_IP_address,
        ).code, 3)
        self.assertEqual(proto._make_opt_ipv6_ap(
            Option.Mobility_Header_IPv6_Address_Prefix, code='Old_Care_of_Address',
            code_namespace=IPv6AddressPrefixCode,
        ).code, 1)
        self.assertEqual(proto._make_opt_ipv6_ap(
            Option.Mobility_Header_IPv6_Address_Prefix,
            data.IPv6AddressPrefixOption(type=Option.Mobility_Header_IPv6_Address_Prefix,
                                         length=20, code=3, prefix_length=64,
                                         address=ip_address('2001:db8:3::')),
        ).code, 3)
        with self.assertRaises(ProtocolError):
            proto._make_opt_ipv6_ap(Option.Mobility_Header_IPv6_Address_Prefix,
                                    prefix_length=129)

    def test_mh_fmipv6_wire_format_matches_rfc(self) -> None:
        """Parse hand-written byte strings laid out straight from the RFC figures."""
        from pcapkit.const.mh.handover_ack_status import HandoverACKStatus
        from pcapkit.const.mh.handover_initiate_status import HandoverInitiateStatus
        from pcapkit.const.mh.lla_code import LLACode
        from pcapkit.const.mh.option import Option
        from pcapkit.const.mh.packet import Packet
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.mh import (MH, FastBindingAcknowledgmentStatus,
                                                   IPv6AddressPrefixCode)

        def parse(hexstr: str) -> object:
            raw = bytes.fromhex(hexstr)
            self.assertEqual(len(raw) % 8, 0, 'mobility header must be 8-octet aligned')
            return MH(io.BytesIO(raw), len(raw), extension=True).info

        badf_type = Option.Binding_Authorization_Data_for_FMIPv6
        apfx_type = Option.Mobility_Header_IPv6_Address_Prefix
        acoa_type = Option.Alternate_Care_of_Address
        mhlla_type = Option.Mobility_Header_Link_Layer_Address_option

        with self.subTest('FBU, RFC 5568 section 6.2.2'):
            fbu = parse(
                '1105' '08' '00' '1234'                          # next, hdr len, type, resv, cksum
                '1234' 'd000' '000a'                             # seq, A|H|L|K + resv, lifetime
                '0310' '20010db8000100000000000000000002'         # alternate care-of address
                '150c' 'deadbeef' '000102030405060708090a0b'      # BADF: SPI + authenticator
            )
            self.assertEqual(fbu.next, TransType.UDP)
            self.assertEqual(fbu.type, Packet.Fast_Binding_Update)
            self.assertEqual(fbu.length, 48)
            self.assertEqual(fbu.seq, 0x1234)
            self.assertTrue(fbu.ack)
            self.assertTrue(fbu.home)
            self.assertFalse(fbu.lla_compat)
            self.assertTrue(fbu.key_mngt)
            self.assertEqual(fbu.lifetime, datetime.timedelta(seconds=40))
            self.assertEqual(str(fbu.options[acoa_type].address), '2001:db8:1::2')
            self.assertEqual(fbu.options[badf_type].spi, 0xdeadbeef)
            self.assertEqual(fbu.options[badf_type].data, bytes(range(12)))
            self.assertEqual(fbu.options[badf_type].length, 18)

        with self.subTest('FBack, RFC 5568 section 6.2.3'):
            fback = parse(
                '1105' '09' '00' '1234'
                '01' '80' '1234' '000a'                          # status, K + resv, seq, lifetime
                '0310' '20010db8000100000000000000000002'
                '150c' '00000000' '000102030405060708090a0b'      # SPI 0: SEND-based handover key
            )
            self.assertEqual(fback.type, Packet.Fast_Binding_Acknowledgment)
            self.assertIs(
                fback.status,
                FastBindingAcknowledgmentStatus.Fast_Binding_Update_accepted_but_NCoA_is_invalid,
            )
            self.assertTrue(fback.key_mngt)
            self.assertEqual(fback.seq, 0x1234)
            self.assertEqual(fback.lifetime, datetime.timedelta(seconds=40))
            self.assertEqual(fback.options[badf_type].spi, 0)

        with self.subTest('FNA, RFC 4068 section 6.3.3'):
            fna = parse(
                '1102' '0a' '00' '1234'
                '0000'                                            # reserved
                '0707' '02' '001122334455'                         # MH-LLA, code 2 = LLA of the MN
                '0105' '0000000000'                                # PadN
            )
            self.assertEqual(fna.type, Packet.Fast_Neighbor_Advertisement)
            self.assertEqual(fna.length, 24)
            self.assertEqual(fna.options[mhlla_type].code, LLACode.MH)
            self.assertEqual(fna.options[mhlla_type].lla, b'\x00\x11\x22\x33\x44\x55')
            self.assertEqual(fna.options[Option.PadN].length, 7)

        with self.subTest('Experimental Mobility Header, RFC 5096 section 3'):
            emh = parse('1101' '0b' '00' '1234' '00010203040506070809')
            self.assertEqual(emh.type, Packet.Experimental_Mobility_Header)
            self.assertEqual(emh.length, 16)
            self.assertEqual(emh.data, bytes(range(10)))

        with self.subTest('HI, RFC 5568 section 6.2.1.1 / RFC 5949 section 6.1.1'):
            hi = parse(
                '1104' '0e' '00' '1234'
                '0102' 'c0' '01'                                   # seq, S|U|P|F + resv, code
                '2212' '02' '40' '20010db8000200000000000000000000'  # addr/prefix: new CoA, /64
                '0108' '0000000000000000'                           # PadN
            )
            self.assertEqual(hi.type, Packet.Handover_Initiate_Message)
            self.assertEqual(hi.length, 40)
            self.assertEqual(hi.seq, 0x0102)
            self.assertTrue(hi.assign)
            self.assertTrue(hi.buffer)
            self.assertFalse(hi.proxy)
            self.assertFalse(hi.forward)
            self.assertEqual(hi.code, HandoverInitiateStatus.FBU_whose_source_IP_address_is_not_PCoA)
            self.assertIs(hi.options[apfx_type].code, IPv6AddressPrefixCode.New_Care_of_Address)
            self.assertEqual(hi.options[apfx_type].prefix_length, 64)
            self.assertEqual(str(hi.options[apfx_type].address), '2001:db8:2::')
            self.assertEqual(hi.options[apfx_type].length, 20)

        with self.subTest('HAck, RFC 5568 section 6.2.1.2 / RFC 5949 section 6.1.2'):
            hack = parse(
                '1104' '0f' '00' '1234'
                '0102' 'a0' '02'                                   # seq, U|P|F + resv, code
                '2212' '02' '80' '20010db8000200000000000000000005'
                '0108' '0000000000000000'
            )
            self.assertEqual(hack.type, Packet.Handover_Acknowledge_Message)
            self.assertEqual(hack.seq, 0x0102)
            self.assertTrue(hack.buffer)
            self.assertFalse(hack.proxy)
            self.assertTrue(hack.forward)
            self.assertEqual(hack.code, HandoverACKStatus.Handover_Accepted_NCoA_assigned)
            self.assertEqual(hack.options[apfx_type].prefix_length, 128)
            self.assertEqual(str(hack.options[apfx_type].address), '2001:db8:2::5')

        with self.subTest('Experimental Mobility option, RFC 5096 section 4'):
            brr = parse('1101' '00' '00' '1234' '0000' '1206' '010203040506')
            exp = brr.options[Option.Experimental_Mobility_Option]
            self.assertEqual(exp.data, b'\x01\x02\x03\x04\x05\x06')
            self.assertEqual(exp.length, 8)

    def test_mh_fmipv6_round_trip_is_byte_identical(self) -> None:
        """``make`` then ``read`` then ``make`` again must reproduce the same bytes."""
        from pcapkit.const.mh.handover_ack_status import HandoverACKStatus
        from pcapkit.const.mh.handover_initiate_status import HandoverInitiateStatus
        from pcapkit.const.mh.option import Option
        from pcapkit.const.mh.packet import Packet
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.mh import (MH, FastBindingAcknowledgmentStatus,
                                                   IPv6AddressPrefixCode)

        badf_type = Option.Binding_Authorization_Data_for_FMIPv6
        apfx_type = Option.Mobility_Header_IPv6_Address_Prefix
        acoa_type = Option.Alternate_Care_of_Address
        mhlla_type = Option.Mobility_Header_Link_Layer_Address_option
        exp_type = Option.Experimental_Mobility_Option

        # NOTE: Every case below is 8-octet aligned and so draws no padding option,
        # which keeps these cases about the FMIPv6 message and option types. It used
        # to be a workaround as well: ``_make_opt_pad`` round-tripped a ``PadN`` data
        # model two octets too long, because it copied the data model's whole-option
        # ``length`` into the schema's ``Option Length`` field. That is fixed, and
        # ``test_mh_padding_option_data_model_round_trips`` covers it.
        cases = [
            ('FBU', Packet.Fast_Binding_Update, {
                'seq': 0x1234, 'ack': True, 'home': True, 'lla_compat': False,
                'key_mngt': True, 'lifetime': 40,
                'options': [(acoa_type, {'address': '2001:db8:1::2'}),
                            (badf_type, {'spi': 0xdeadbeef, 'data': bytes(range(12))})],
            }, {'seq': 0x1234, 'ack': True, 'home': True, 'lla_compat': False,
                'key_mngt': True, 'lifetime': datetime.timedelta(seconds=40)}),
            # the status goes in as an enum member and must come back as one
            ('FBack', Packet.Fast_Binding_Acknowledgment, {
                'status': FastBindingAcknowledgmentStatus.Incorrect_interface_identifier_length,
                'key_mngt': True, 'seq': 0x1234, 'lifetime': 40,
                'options': [(acoa_type, {'address': '2001:db8:1::2'}),
                            (badf_type, {'spi': 0, 'data': bytes(range(12))})],
            }, {'status': FastBindingAcknowledgmentStatus.Incorrect_interface_identifier_length,
                'key_mngt': True, 'seq': 0x1234,
                'lifetime': datetime.timedelta(seconds=40)}),
            # ... and as a bare integer, for a value the RFC leaves unassigned
            ('FBack, unassigned status', Packet.Fast_Binding_Acknowledgment, {
                'status': 77, 'key_mngt': False, 'seq': 1, 'lifetime': 4,
                'options': [(acoa_type, {'address': '2001:db8:1::3'}),
                            (badf_type, {'spi': 1, 'data': bytes(range(12))})],
            }, {'status': 77, 'key_mngt': False, 'seq': 1,
                'lifetime': datetime.timedelta(seconds=4)}),
            ('FNA', Packet.Fast_Neighbor_Advertisement, {
                'options': [(mhlla_type, {'address': b'\x00\x11\x22\x33\x44'})],
            }, {}),
            ('Experimental', Packet.Experimental_Mobility_Header, {
                'data': bytes(range(10)),
            }, {'data': bytes(range(10))}),
            ('HI', Packet.Handover_Initiate_Message, {
                'seq': 0x0102, 'assign': True, 'buffer': True, 'proxy': False,
                'forward': False,
                'code': HandoverInitiateStatus.FBU_whose_source_IP_address_is_not_PCoA,
                'options': [(apfx_type, {'code': IPv6AddressPrefixCode.New_Care_of_Address,
                                         'prefix_length': 64,
                                         'address': '2001:db8:2::'}),
                            (mhlla_type, {'address': b'\x00\x11\x22\x33\x44\x55\x66'})],
            }, {'seq': 0x0102, 'assign': True, 'buffer': True, 'proxy': False,
                'forward': False,
                'code': HandoverInitiateStatus.FBU_whose_source_IP_address_is_not_PCoA}),
            ('HAck', Packet.Handover_Acknowledge_Message, {
                'seq': 0x0102, 'buffer': True, 'proxy': False, 'forward': True,
                'code': HandoverACKStatus.Handover_Accepted_NCoA_assigned,
                'options': [(apfx_type, {'code': 2, 'prefix_length': 128,
                                         'address': '2001:db8:2::5'}),
                            (mhlla_type, {'address': b'\x00\x11\x22\x33\x44\x55\x66'})],
            }, {'seq': 0x0102, 'buffer': True, 'proxy': False, 'forward': True,
                'code': HandoverACKStatus.Handover_Accepted_NCoA_assigned}),
            ('Experimental option', Packet.Binding_Refresh_Request, {
                'options': [(exp_type, {'data': b'\x01\x02\x03\x04\x05\x06'})],
            }, {}),
        ]

        for name, packet_type, payload, expected in cases:
            with self.subTest(name):
                raw = bytes(MH(next=TransType.UDP, chksum=b'\x12\x34',
                               type=packet_type, data=payload))
                self.assertEqual(len(raw) % 8, 0)

                parsed = MH(io.BytesIO(raw), len(raw), extension=True).info
                self.assertEqual(parsed.type, packet_type)
                self.assertEqual(parsed.length, len(raw))
                for field, value in expected.items():
                    self.assertEqual(getattr(parsed, field), value, field)

                rebuilt = bytes(MH(next=parsed.next, type=parsed.type,
                                   chksum=parsed.chksum, data=parsed))
                self.assertEqual(rebuilt, raw)

    def test_mh_rfc5568_local_enums_cover_unregistered_value_sets(self) -> None:
        """:rfc:`5568` defines two value sets inline, with no IANA registry.

        Both are therefore enumerated in :mod:`pcapkit.protocols.internet.mh`
        itself rather than in :mod:`pcapkit.const.mh`, and both have to tolerate
        the values the RFC leaves unassigned -- a capture in the wild carries
        whatever it carries, so an unassigned code must parse rather than raise.
        """
        from pcapkit.const.mh.option import Option
        from pcapkit.const.mh.packet import Packet
        from pcapkit.const.mh.status_code import StatusCode
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.mh import (MH, FastBindingAcknowledgmentStatus,
                                                   IPv6AddressPrefixCode)

        apfx_type = Option.Mobility_Header_IPv6_Address_Prefix
        badf_type = Option.Binding_Authorization_Data_for_FMIPv6
        acoa_type = Option.Alternate_Care_of_Address
        mhlla_type = Option.Mobility_Header_Link_Layer_Address_option

        # The membership assertions come first: ``_missing_`` extends the class in
        # place, so any unassigned lookup below would otherwise show up here.
        with self.subTest('FBack status members, RFC 5568 section 6.2.3'):
            self.assertEqual(
                {int(member): member.name for member in FastBindingAcknowledgmentStatus},
                {0: 'Fast_Binding_Update_accepted',
                 1: 'Fast_Binding_Update_accepted_but_NCoA_is_invalid',
                 128: 'Reason_unspecified',
                 129: 'Administratively_prohibited',
                 130: 'Insufficient_resources',
                 131: 'Incorrect_interface_identifier_length'},
            )

        with self.subTest('address/prefix option code members, RFC 5568 section 6.4.2'):
            self.assertEqual(
                {int(member): member.name for member in IPv6AddressPrefixCode},
                {1: 'Old_Care_of_Address', 2: 'New_Care_of_Address',
                 3: 'NAR_IP_address', 4: 'NAR_Prefix'},
            )

        with self.subTest('the collision that rules out reusing StatusCode'):
            # RFC 6275 means something else by both of these, which is why the
            # registry enumeration cannot stand in for the RFC 5568 one.
            self.assertEqual(StatusCode.Accepted_but_prefix_discovery_necessary, 1)
            self.assertEqual(StatusCode.Home_registration_not_supported, 131)
            self.assertNotIsInstance(FastBindingAcknowledgmentStatus(1), StatusCode)
            self.assertNotIsInstance(FastBindingAcknowledgmentStatus(131), StatusCode)

        def fback(status: int) -> object:
            raw = bytes.fromhex(
                '1105' '09' '00' '1234'
                f'{status:02x}' '80' '1234' '000a'
                '0310' '20010db8000100000000000000000002'
                '150c' '00000000' '000102030405060708090a0b'
            )
            return MH(io.BytesIO(raw), len(raw), extension=True).info

        def handover_initiate(code: int) -> object:
            raw = bytes.fromhex(
                '1104' '0e' '00' '1234'
                '0102' 'c0' '01'
                '2212' f'{code:02x}' '40' '20010db8000200000000000000000000'
                '0108' '0000000000000000'
            )
            return MH(io.BytesIO(raw), len(raw), extension=True).info

        with self.subTest('assigned values parse to the right member'):
            for wire, member in [
                (0, FastBindingAcknowledgmentStatus.Fast_Binding_Update_accepted),
                (1, FastBindingAcknowledgmentStatus.Fast_Binding_Update_accepted_but_NCoA_is_invalid),
                (128, FastBindingAcknowledgmentStatus.Reason_unspecified),
                (129, FastBindingAcknowledgmentStatus.Administratively_prohibited),
                (130, FastBindingAcknowledgmentStatus.Insufficient_resources),
                (131, FastBindingAcknowledgmentStatus.Incorrect_interface_identifier_length),
            ]:
                self.assertIs(fback(wire).status, member, wire)

            for wire, member in [
                (1, IPv6AddressPrefixCode.Old_Care_of_Address),
                (2, IPv6AddressPrefixCode.New_Care_of_Address),
                (3, IPv6AddressPrefixCode.NAR_IP_address),
                (4, IPv6AddressPrefixCode.NAR_Prefix),
            ]:
                self.assertIs(handover_initiate(wire).options[apfx_type].code, member, wire)

        with self.subTest('unassigned values parse without raising'):
            # 2..127 is the unassigned half of the "accepted" range, 132..255 of
            # the "rejected" one; both must survive a parse.
            for wire in (2, 77, 127, 132, 255):
                status = fback(wire).status
                self.assertIsInstance(status, FastBindingAcknowledgmentStatus)
                self.assertEqual(status, wire)
                self.assertEqual(status.name, 'Unassigned_%d' % wire)

            # RFC 5568 assigns 1 through 4 only, so 0 and 5..255 are unassigned.
            for wire in (0, 5, 200, 255):
                code = handover_initiate(wire).options[apfx_type].code
                self.assertIsInstance(code, IPv6AddressPrefixCode)
                self.assertEqual(code, wire)
                self.assertEqual(code.name, 'Unassigned_%d' % wire)

        with self.subTest('out-of-octet values are still rejected'):
            for enum_cls in (FastBindingAcknowledgmentStatus, IPv6AddressPrefixCode):
                for value in (-1, 256):
                    with self.assertRaises(ValueError):
                        enum_cls(value)

        with self.subTest('get() backports string and integer lookups'):
            self.assertIs(FastBindingAcknowledgmentStatus.get(130),
                          FastBindingAcknowledgmentStatus.Insufficient_resources)
            self.assertIs(FastBindingAcknowledgmentStatus.get('Reason_unspecified'),
                          FastBindingAcknowledgmentStatus.Reason_unspecified)
            self.assertEqual(FastBindingAcknowledgmentStatus.get('Vendor_specific', 200), 200)
            self.assertIs(IPv6AddressPrefixCode.get(4), IPv6AddressPrefixCode.NAR_Prefix)
            self.assertIs(IPv6AddressPrefixCode.get('New_Care_of_Address'),
                          IPv6AddressPrefixCode.New_Care_of_Address)
            self.assertEqual(IPv6AddressPrefixCode.get('Vendor_specific', 201), 201)

        with self.subTest('make round trips both enums byte-identically'):
            for status, code in [
                (FastBindingAcknowledgmentStatus.Insufficient_resources,
                 IPv6AddressPrefixCode.NAR_Prefix),
                # unassigned on the wire, and handed in as a bare integer
                (99, 250),
            ]:
                fback_raw = bytes(MH(next=TransType.UDP, chksum=b'\x12\x34',
                                     type=Packet.Fast_Binding_Acknowledgment,
                                     data={'status': status, 'key_mngt': True, 'seq': 0x1234,
                                           'lifetime': 40,
                                           'options': [
                                               (acoa_type, {'address': '2001:db8:1::2'}),
                                               (badf_type, {'spi': 0,
                                                            'data': bytes(range(12))})]}))
                self.assertEqual(fback_raw[6], int(status))
                parsed = MH(io.BytesIO(fback_raw), len(fback_raw), extension=True).info
                self.assertIsInstance(parsed.status, FastBindingAcknowledgmentStatus)
                self.assertEqual(parsed.status, int(status))
                self.assertEqual(bytes(MH(next=parsed.next, type=parsed.type,
                                          chksum=parsed.chksum, data=parsed)), fback_raw)

                hi_raw = bytes(MH(next=TransType.UDP, chksum=b'\x12\x34',
                                  type=Packet.Handover_Initiate_Message,
                                  data={'seq': 0x0102, 'assign': True, 'buffer': True,
                                        'proxy': False, 'forward': False, 'code': 1,
                                        'options': [
                                            (apfx_type, {'code': code, 'prefix_length': 64,
                                                         'address': '2001:db8:2::'}),
                                            (mhlla_type,
                                             {'address': b'\x00\x11\x22\x33\x44\x55\x66'})]}))
                parsed = MH(io.BytesIO(hi_raw), len(hi_raw), extension=True).info
                self.assertIsInstance(parsed.options[apfx_type].code, IPv6AddressPrefixCode)
                self.assertEqual(parsed.options[apfx_type].code, int(code))
                self.assertEqual(bytes(MH(next=parsed.next, type=parsed.type,
                                          chksum=parsed.chksum, data=parsed)), hi_raw)

    def test_mh_message_flags_pack_each_bit_independently(self) -> None:
        """Regression test: a cleared flag must not be emitted as a set bit.

        :class:`~pcapkit.corekit.fields.strings.BitField` used to seed its per-bit
        buffer with NUL bytes and then truth-test it, so the ASCII ``b'0'`` written
        for a cleared bit read back as set and every named bit came out as ``1``
        regardless of the value handed in.
        """
        from pcapkit.const.mh.packet import Packet
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.mh import MH

        # A|H|L|K, one flag set at a time, c.f. RFC 5568 section 6.2.2.
        for flag, octets in [('ack', b'\x80\x00'), ('home', b'\x40\x00'),
                             ('lla_compat', b'\x20\x00'), ('key_mngt', b'\x10\x00')]:
            with self.subTest(flag):
                raw = bytes(MH(next=TransType.UDP, chksum=b'\x00\x00',
                               type=Packet.Fast_Binding_Update,
                               data={'seq': 0, 'ack': False, 'home': False,
                                     'lla_compat': False, 'key_mngt': False,
                                     flag: True, 'lifetime': 4, 'options': []}))
                self.assertEqual(raw[8:10], octets)

        # U|P|F of the HAck message, c.f. RFC 5949 section 6.1.2.
        for flag, octet in [('buffer', 0x80), ('proxy', 0x40), ('forward', 0x20)]:
            with self.subTest(flag):
                raw = bytes(MH(next=TransType.UDP, chksum=b'\x00\x00',
                               type=Packet.Handover_Acknowledge_Message,
                               data={'seq': 0, 'buffer': False, 'proxy': False,
                                     'forward': False, flag: True, 'code': 0,
                                     'options': []}))
                self.assertEqual(raw[8], octet)

    def test_mh_padding_options_parse_from_the_wire(self) -> None:
        """A ``Pad1`` option must consume exactly one octet, wherever it sits.

        Per :rfc:`6275#section-6.2.5` the two padding options do not share a wire
        shape: ``Pad1`` is a lone type octet with no ``Option Length`` field at
        all, while ``PadN`` is a type octet, a length octet, and that many data
        octets. Reading a length octet that is not there consumes the *next*
        option's type byte instead, so every case below puts something after the
        padding.

        The header is a Binding Refresh Request with ``Header Len`` 1, i.e. 16
        octets: 6 of fixed header, 2 of the message's own reserved field, and 8
        of mobility options.
        """
        from pcapkit.const.mh.option import Option
        from pcapkit.const.mh.packet import Packet
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.mh import MH

        header = b'\x3b\x01\x00\x00\x00\x00' + b'\x00\x00'
        cases = (
            ('pad1 then padn', b'\x00' + b'\x01\x05\x00\x00\x00\x00\x00',
             [(Option.Pad1, 1), (Option.PadN, 7)]),
            ('pad1 then a real option then pad1', b'\x00' + b'\x02\x02\x00\x0a' + b'\x00\x00\x00',
             [(Option.Pad1, 1), (Option.Binding_Refresh_Advice, 4),
              (Option.Pad1, 1), (Option.Pad1, 1), (Option.Pad1, 1)]),
            ('eight pad1 in a row', b'\x00' * 8, [(Option.Pad1, 1)] * 8),
            ('pad1 as the final octet', b'\x01\x05\x00\x00\x00\x00\x00' + b'\x00',
             [(Option.PadN, 7), (Option.Pad1, 1)]),
            ('padn is unaffected', b'\x01\x06\x00\x00\x00\x00\x00\x00',
             [(Option.PadN, 8)]),
        )

        for name, options, expected in cases:
            with self.subTest(case=name):
                raw = header + options
                self.assertEqual(len(raw), 16)

                info = MH(raw, extension=True).info
                self.assertEqual(info.length, 16)
                self.assertEqual(
                    [(code, opt.length) for code, opt in info.options.items(multi=True)],
                    expected,
                )
                self.assertEqual(bytes(MH(next=info.next, type=info.type,
                                          chksum=info.chksum, data=info)), raw)

    def test_mh_padding_option_schema_sizes_itself(self) -> None:
        """The padding option schema on its own, and the helper behind it.

        :func:`~pcapkit.protocols.schema.internet.mh.pad_opt_data_len` has to read
        a skipped conditional field -- which is recorded as
        :data:`~pcapkit.corekit.fields.field.NoValue`, not omitted -- as zero
        padding octets, rather than handing that singleton to
        :class:`~pcapkit.corekit.fields.strings.PaddingField` where it becomes an
        unusable :mod:`struct` template.
        """
        from pcapkit.const.mh.option import Option
        from pcapkit.corekit.fields.field import NoValue
        from pcapkit.protocols.schema.internet import mh as schema

        self.assertEqual(schema.pad_opt_data_len({}), 0)
        self.assertEqual(schema.pad_opt_data_len({'length': NoValue}), 0)
        self.assertEqual(schema.pad_opt_data_len({'length': None}), 0)
        self.assertEqual(schema.pad_opt_data_len({'length': 4}), 4)

        # a Pad1 option on its own: one octet read, the next left for whatever follows
        stream = io.BytesIO(b'\x00\x2a')
        pad1 = schema.PadOption.unpack(stream, 2, {})
        self.assertEqual(pad1.type, Option.Pad1)
        self.assertEqual(pad1.length, 0)
        self.assertEqual(len(pad1), 1)
        self.assertEqual(bytes(pad1), b'\x00')
        self.assertEqual(stream.tell(), 1)

        # a PadN option still spans its length octet plus that many data octets
        stream = io.BytesIO(b'\x01\x02\xaa\xbb\xcc')
        padn = schema.PadOption.unpack(stream, 5, {})
        self.assertEqual(padn.type, Option.PadN)
        self.assertEqual(padn.length, 2)
        self.assertEqual(len(padn), 4)
        self.assertEqual(bytes(padn), b'\x01\x02\xaa\xbb')
        self.assertEqual(stream.tell(), 4)

    def test_mh_padding_option_data_model_round_trips(self) -> None:
        """Re-making a parsed padding option must give back the same octets.

        The data model's ``length`` counts the whole option while the schema's is
        the ``Option Length`` field, so copying one into the other unconverted
        produced a ``PadN`` two octets longer than the one that was parsed.
        """
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.data.internet.mh import PadOption
        from pcapkit.protocols.internet.mh import MH

        proto = object.__new__(MH)
        for code, total in ((Option.Pad1, 1), (Option.PadN, 3), (Option.PadN, 6)):
            with self.subTest(option=code.name, length=total):
                made = proto._make_opt_pad(code, PadOption(type=code, length=total))
                self.assertEqual(made.type, code)
                self.assertEqual(len(made.pack()), total)

    def test_mh_constructed_header_round_trips(self) -> None:
        """Construction must declare the number of octets it actually emits.

        The Mobility Header is a multiple of 8 octets and ``Header Len`` counts
        those units less one [:rfc:`6275#section-6.1.1`]. Its fixed part is six
        octets, so it is ``len(message data) + 6`` that has to be aligned -- a
        different modulus from the 2-octet fixed part of an IPv6 options header.
        Rounding ``Header Len`` up without emitting the padding to match sent the
        re-parse off the end of the buffer.
        """
        from pcapkit.const.mh.option import Option
        from pcapkit.const.mh.packet import Packet
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.mh import MH

        brr = Packet.Binding_Refresh_Request
        cases = (
            # 2 octets of reserved + a 6-octet PadN = 8, so 6 + 8 = 14 needs 2 more
            ('padn then two pad1', [(Option.PadN, {'length': 4})], 16),
            # 2 + 8 = 10, and 6 + 10 = 16 is already aligned
            ('padn, already aligned', [(Option.PadN, {'length': 6})], 16),
            # 2 + 4 = 6, and 6 + 6 = 12 needs 4 more octets
            ('real option then padn', [(Option.Binding_Refresh_Advice, {'interval': 10})], 16),
            # no options at all: 6 + 2 = 8 is aligned, so MH needs no padding here
            # where an IPv6 options header would need 6 octets of it
            ('no options', [], 8),
        )

        for name, options, size in cases:
            with self.subTest(case=name):
                built = MH(next=TransType.IPv6_NoNxt, type=brr, chksum=b'\x00\x00',
                           data={'options': list(options)})
                raw = bytes(built)

                self.assertEqual(len(raw), size)
                self.assertEqual(len(raw) % 8, 0)
                # the declared length and the emitted length must be the same
                self.assertEqual((raw[1] + 1) * 8, len(raw))

                parsed = MH(raw, extension=True).info
                self.assertEqual(parsed.length, size)
                self.assertEqual(bytes(MH(next=parsed.next, type=parsed.type,
                                          chksum=parsed.chksum, data=parsed)), raw)

    def test_mh_opaque_message_body_cannot_be_padded(self) -> None:
        """An unpaddable message body is reported rather than silently misdeclared.

        A message whose body is raw bytes carries no mobility options, so there is
        nowhere to put the padding the header needs. Declaring a ``Header Len``
        that the body does not match is what used to happen, and the re-parse then
        read past the end of the buffer.
        """
        from pcapkit.const.mh.packet import Packet
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.utilities.warnings import ProtocolWarning

        proto = object.__new__(MH)

        # 4 octets of body: 6 + 4 = 10, which is 6 octets short of 16
        with self.assertWarns(ProtocolWarning):
            self.assertEqual(proto._pad_mh_message(b'\x00\x01\x02\x03'), b'\x00\x01\x02\x03')

        # a body that is already aligned goes through untouched and unremarked
        import warnings as _warnings
        with _warnings.catch_warnings():
            _warnings.simplefilter('error')
            self.assertEqual(proto._pad_mh_message(b'\x00\x02'), b'\x00\x02')

        # and the whole header still comes out 8-octet aligned when it can be padded
        raw = bytes(MH(next=TransType.IPv6_NoNxt, type=Packet.Binding_Refresh_Request,
                       chksum=b'\x00\x00', data={'options': []}))
        self.assertEqual(len(raw) % 8, 0)


if __name__ == '__main__':
    unittest.main()
