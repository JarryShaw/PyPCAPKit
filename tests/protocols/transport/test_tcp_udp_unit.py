from __future__ import annotations

import datetime
import ipaddress
import importlib.util
import types
import unittest
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class DummyData(dict):
    __getattr__ = dict.__getitem__


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TCPUDPUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_udp_index_make_and_make_data_preserve_core_fields(self) -> None:
        from pcapkit.const.reg.apptype import AppType, TransportProtocol
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.schema.transport.udp import UDP as Schema_UDP
        from pcapkit.protocols.transport.udp import UDP

        udp = object.__new__(UDP)
        schema = UDP.make(udp, srcport=53, dstport=5353, checksum=b'\x12\x34', payload=b'data')
        data = DummyData(srcport=53, dstport=5353, checksum=b'\xab\xcd', __next_type__=None)

        self.assertEqual(UDP.__index__(), TransType.UDP)
        self.assertEqual(schema.srcport, 53)
        self.assertEqual(schema.dstport, 5353)
        self.assertEqual(schema.len, 12)
        self.assertEqual(schema.checksum, b'\x12\x34')

        values = UDP._make_data(data)
        self.assertEqual(values['srcport'], 53)
        self.assertEqual(values['dstport'], 5353)
        self.assertEqual(values['checksum'], b'\xab\xcd')
        self.assertIn('payload', values)

        udp._info = DummyData(srcport=AppType.get(53, proto=TransportProtocol.udp),
                              dstport=AppType.get(5353, proto=TransportProtocol.udp))
        self.assertEqual(udp.name, 'User Datagram Protocol')
        self.assertEqual(udp.length, 8)
        self.assertEqual(udp.src.port, 53)
        self.assertEqual(udp.dst.port, 5353)
        self.assertEqual(udp.__length_hint__(), 8)

        udp.__header__ = Schema_UDP(
            srcport=AppType.get(53, proto=TransportProtocol.udp),
            dstport=AppType.get(5353, proto=TransportProtocol.udp),
            len=12,
            checksum=b'\x12\x34',
            payload=b'data',
        )
        udp._data = b'\x00' * 12
        udp.__cached__ = {}
        with mock.patch.object(UDP, '_decode_next_layer', return_value='decoded') as decode:
            self.assertEqual(udp.read(), 'decoded')
            self.assertEqual(udp.read(length=12), 'decoded')
        self.assertEqual(decode.call_count, 2)

    def test_tcp_index_and_make_data_preserve_flags_and_ports(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.transport.tcp import TCP

        flags = DummyData(cwr=False, ece=False, urg=False, ack=True, psh=True, rst=False, syn=False, fin=True)
        data = DummyData(
            srcport=443,
            dstport=59000,
            seq=123,
            ack=456,
            flags=flags,
            window_size=2048,
            checksum=b'\xfe\xed',
            urgent_pointer=0,
            options=None,
            __next_type__=None,
        )

        values = TCP._make_data(data)

        self.assertEqual(TCP.__index__(), TransType.TCP)
        self.assertEqual(values['srcport'], 443)
        self.assertEqual(values['dstport'], 59000)
        self.assertEqual(values['seq_no'], 123)
        self.assertEqual(values['ack_no'], 456)
        self.assertTrue(values['ack'])
        self.assertTrue(values['psh'])
        self.assertTrue(values['fin'])
        self.assertFalse(values['syn'])
        self.assertEqual(values['window'], 2048)
        self.assertEqual(values['checksum'], b'\xfe\xed')
        self.assertIn('payload', values)

    def test_tcp_properties_read_make_and_callable_registry_edges(self) -> None:
        from pcapkit.const.reg.apptype import AppType, TransportProtocol
        from pcapkit.const.tcp.flags import Flags
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
        from pcapkit.const.tcp.option import Option
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.data.transport import tcp as tcp_data
        from pcapkit.protocols.schema.transport import tcp as tcp_schema
        from pcapkit.protocols.transport.tcp import TCP

        proto = object.__new__(TCP)
        proto._info = DummyData(
            hdr_len=20,
            srcport=AppType.get(443, proto=TransportProtocol.tcp),
            dstport=AppType.get(59000, proto=TransportProtocol.tcp),
        )
        proto._flags = Flags.SYN | Flags.ACK
        self.assertEqual(proto.name, 'Transmission Control Protocol')
        self.assertEqual(proto.length, 20)
        self.assertEqual(proto.src.port, 443)
        self.assertEqual(proto.dst.port, 59000)
        self.assertEqual(proto.connection, Flags.SYN | Flags.ACK)
        self.assertEqual(proto.__length_hint__(), 20)

        proto.__header__ = tcp_schema.TCP(
            srcport=AppType.get(443, proto=TransportProtocol.tcp),
            dstport=AppType.get(59000, proto=TransportProtocol.tcp),
            seq=1,
            ack=2,
            offset={'offset': 6, 'ns': 0},
            flags={'cwr': 0, 'ece': 0, 'urg': 0, 'ack': 1,
                   'psh': 0, 'rst': 0, 'syn': 1, 'fin': 0},
            window=4096,
            checksum=b'\x12\x34',
            urgent=0,
            options=[tcp_schema.MaximumSegmentSize(kind=Option.Maximum_Segment_Size,
                                                   length=4, mss=1460)],
            payload=b'data',
        )
        proto._data = b'\x00' * 28
        proto.__cached__ = {}
        proto._decode_next_layer = mock.Mock(return_value='decoded')
        self.assertEqual(proto.read(length=28), 'decoded')
        decoded, ports, payload_len = proto._decode_next_layer.call_args.args
        self.assertEqual(decoded.hdr_len, 24)
        self.assertEqual(decoded.options[Option.Maximum_Segment_Size].mss, 1460)
        self.assertEqual(ports, (443, 59000))
        self.assertEqual(payload_len, 4)
        self.assertEqual(proto.connection, Flags.SYN | Flags.ACK)

        proto.__header__ = tcp_schema.TCP(
            srcport=AppType.get(53, proto=TransportProtocol.tcp),
            dstport=AppType.get(5353, proto=TransportProtocol.tcp),
            seq=3,
            ack=4,
            offset={'offset': 5, 'ns': 0},
            flags={'cwr': 0, 'ece': 0, 'urg': 0, 'ack': 0,
                   'psh': 0, 'rst': 0, 'syn': 0, 'fin': 1},
            window=1024,
            checksum=b'\x00\x00',
            urgent=0,
            options=[],
            payload=b'data',
        )
        proto._decode_next_layer.reset_mock()
        self.assertEqual(proto.read(), 'decoded')
        decoded_no_options = proto._decode_next_layer.call_args.args[0]
        self.assertFalse(hasattr(decoded_no_options, 'options'))
        self.assertEqual(proto.connection, Flags.FIN)

        made = proto.make(srcport=443, dstport=59000, syn=True, ack=True,
                          options=None, payload=b'data')
        self.assertEqual(made.offset['offset'], 5)
        self.assertTrue(made.flags['syn'])
        self.assertTrue(made.flags['ack'])
        self.assertEqual(proto.connection, Flags.SYN | Flags.ACK)
        made_with_options = proto.make(srcport=443, dstport=59000,
                                       options=[(Option.Maximum_Segment_Size, {'mss': 1200})],
                                       payload=b'')
        self.assertEqual(made_with_options.offset['offset'], 6)

        custom_option = Option.get(253)
        option_registry = TCP.__dict__['__option__']
        original_option = option_registry.get(custom_option)

        def parse_option(schema, *, options):
            return tcp_data.UnassignedOption(kind=schema.kind, length=schema.length,
                                             data=schema.data)

        def make_option(code, opt=None, *, data=b'', **kwargs):
            if opt is not None:
                data = opt.data
            return tcp_schema.UnassignedOption(kind=code, length=len(data) + 2, data=data)

        custom_mp = MPTCPOption.Reserved_for_Private_Use
        mp_registry = TCP.__dict__['__mp_option__']
        original_mp = mp_registry.get(custom_mp)

        def parse_mp(schema, *, options):
            return tcp_data.MPTCPUnknown(kind=Option.Multipath_TCP, length=schema.length,
                                         subtype=schema.subtype, data=b'parsed')

        def make_mp(subtype, opt=None, *, data=b'\x01', **kwargs):
            if opt is not None:
                data = opt.data
            return tcp_schema.MPTCPUnknown(
                kind=Option.Multipath_TCP,
                length=len(data) + 2,
                test={'subtype': subtype.value, 'data': data[0] & 0x0f},
                data=data[1:],
            )

        try:
            with mock.patch('pcapkit.protocols.transport.tcp.warn') as warn:
                TCP.register_option(custom_option, (parse_option, make_option))
                TCP.register_mp_option(custom_mp, (parse_mp, make_mp))
            warn.assert_not_called()

            option_schema = tcp_schema.UnassignedOption(kind=custom_option, length=4, data=b'ab')
            parsed_option = parse_option(
                option_schema,
                options=None,
            )
            self.assertEqual(parsed_option.data, b'ab')
            proto.__header__ = types.SimpleNamespace(options=[option_schema])
            self.assertEqual(proto._read_tcp_options(4)[custom_option].data, b'ab')

            custom_options, custom_len = proto._make_tcp_options([
                (custom_option, {'data': b'xy'}),
            ])
            self.assertEqual(custom_len, 4)
            self.assertEqual(custom_options[0].data, b'xy')
            option_dict = OrderedMultiDict([
                (custom_option, tcp_data.UnassignedOption(kind=custom_option,
                                                          length=4,
                                                          data=b'zz')),
            ])
            dict_options, dict_len = proto._make_tcp_options(option_dict)
            self.assertEqual(dict_len, 4)
            self.assertEqual(dict_options[0].data, b'zz')

            mp_schema = tcp_schema.MPTCPUnknown(
                kind=Option.Multipath_TCP,
                length=3,
                test={'subtype': custom_mp.value, 'data': 1},
                data=b'x',
            )
            object.__setattr__(mp_schema, 'subtype', custom_mp)
            object.__setattr__(mp_schema, 'length', 3)
            self.assertEqual(proto._read_mode_mp(mp_schema, options=None).data, b'parsed')
            self.assertEqual(proto._make_mode_mp(Option.Multipath_TCP,
                                                 subtype=custom_mp,
                                                 data=b'\x02z').data, b'z')
        finally:
            if original_option is None:
                option_registry.pop(custom_option, None)
            else:
                option_registry[custom_option] = original_option
            if original_mp is None:
                mp_registry.pop(custom_mp, None)
            else:
                mp_registry[custom_mp] = original_mp

    def test_tcp_register_option_warns_on_overwrite(self) -> None:
        from pcapkit.const.tcp.option import Option
        from pcapkit.protocols.transport.tcp import TCP

        original = TCP.__dict__['__option__'][Option.End_of_Option_List]
        try:
            with mock.patch('pcapkit.protocols.transport.tcp.warn') as warn:
                TCP.register_option(Option.End_of_Option_List, 'eool')
            warn.assert_called_once()
            self.assertEqual(TCP.__dict__['__option__'][Option.End_of_Option_List], 'eool')
        finally:
            TCP.__dict__['__option__'][Option.End_of_Option_List] = original

    def test_tcp_register_mptcp_option_warns_on_overwrite(self) -> None:
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
        from pcapkit.protocols.transport.tcp import TCP

        original = TCP.__dict__['__mp_option__'][MPTCPOption.MP_CAPABLE]
        try:
            with mock.patch('pcapkit.protocols.transport.tcp.warn') as warn:
                TCP.register_mp_option(MPTCPOption.MP_CAPABLE, 'capable')
            warn.assert_called_once()
            self.assertEqual(TCP.__dict__['__mp_option__'][MPTCPOption.MP_CAPABLE], 'capable')
        finally:
            TCP.__dict__['__mp_option__'][MPTCPOption.MP_CAPABLE] = original

    def test_tcp_option_constructors_cover_common_branches(self) -> None:
        from pcapkit.const.tcp.option import Option
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(TCP)

        self.assertEqual(proto._make_mode_donone(Option.RFC3692_style_Experiment_1,
                                                 data=b'xx').to_dict()['length'], 4)
        self.assertEqual(proto._make_mode_eool(Option.End_of_Option_List).to_dict()['length'], 1)
        self.assertEqual(proto._make_mode_nop(Option.No_Operation).to_dict()['length'], 1)
        self.assertEqual(proto._make_mode_mss(Option.Maximum_Segment_Size, mss=1460).to_dict()['mss'], 1460)
        self.assertEqual(proto._make_mode_ws(Option.Window_Scale, shift=7).to_dict()['shift'], 7)
        self.assertEqual(proto._make_mode_sackpmt(Option.SACK_Permitted).to_dict()['length'], 2)

        sack = proto._make_mode_sack(Option.SACK, sack=[(1, 2), (3, 4)])
        self.assertEqual(sack.to_dict()['length'], 18)
        self.assertEqual([(block.left, block.right) for block in sack.to_dict()['sack']], [(1, 2), (3, 4)])

        self.assertEqual(proto._make_mode_echo(Option.Echo, data=b'abcd').to_dict()['data'], b'abcd')
        self.assertEqual(proto._make_mode_echore(Option.Echo_Reply, data=b'wxyz').to_dict()['data'], b'wxyz')
        self.assertEqual(proto._make_mode_ts(Option.Timestamps, tsval=1, tsecr=2).to_dict()['reply'], 2)
        self.assertEqual(proto._make_mode_poc(Option.Partial_Order_Connection_Permitted).to_dict()['length'], 2)
        self.assertTrue(proto._make_mode_pocsp(Option.Partial_Order_Service_Profile,
                                               start=True).to_dict()['profile']['start'])
        self.assertEqual(proto._make_mode_cc(Option.CC, count=1).to_dict()['count'], 1)
        self.assertEqual(proto._make_mode_ccnew(Option.CC_NEW, count=2).to_dict()['count'], 2)
        self.assertEqual(proto._make_mode_ccecho(Option.CC_ECHO, count=3).to_dict()['count'], 3)
        self.assertEqual(proto._make_mode_chkreq(Option.TCP_Alternate_Checksum_Request,
                                                 algorithm=0).to_dict()['algorithm'], 0)
        self.assertEqual(proto._make_mode_chksum(Option.TCP_Alternate_Checksum_Data,
                                                 data=b'abc').to_dict()['length'], 5)
        self.assertEqual(proto._make_mode_sig(Option.MD5_Signature_Option,
                                              digest=b'0' * 16).to_dict()['digest'], b'0' * 16)
        self.assertEqual(proto._make_mode_qs(Option.Quick_Start_Response, rate=80,
                                             diff=datetime.timedelta(seconds=4),
                                             nonce=5).to_dict()['diff'], 4)
        self.assertEqual(proto._make_mode_timeout(Option.User_Timeout_Option,
                                                  timeout=60).to_dict()['info']['granularity'], False)
        self.assertEqual(proto._make_mode_timeout(Option.User_Timeout_Option,
                                                  timeout=1 << 16).to_dict()['info']['granularity'], True)
        self.assertEqual(proto._make_mode_ao(Option.TCP_Authentication_Option, key_id=1,
                                             next_key_id=2, mac=b'mac').to_dict()['length'], 7)
        self.assertEqual(proto._make_mode_fastopen(Option.TCP_Fast_Open_Cookie,
                                                   cookie=b'cookie').to_dict()['cookie'], b'cookie')

        raw_options, raw_length = proto._make_tcp_options([b'\xfeabc'])
        self.assertEqual(raw_length, 4)
        self.assertEqual(raw_options, [b'\xfeabc'])
        padded_raw_options, padded_raw_length = proto._make_tcp_options([b'\xfeabcde'])
        self.assertEqual(padded_raw_length, 8)
        self.assertEqual(type(padded_raw_options[-1]).__name__, 'EndOfOptionList')

        tuple_options, tuple_length = proto._make_tcp_options([
            (Option.Window_Scale, {'shift': 7}),
            (Option.No_Operation, {}),
        ])
        self.assertEqual(tuple_length, 4)
        self.assertEqual([type(item).__name__ for item in tuple_options],
                         ['WindowScale', 'EndOfOptionList'])

        with self.assertRaises(ProtocolError):
            proto._make_mode_timeout(Option.User_Timeout_Option, timeout=1 << 30)

    def test_tcp_option_constructors_cover_data_model_and_mapping_paths(self) -> None:
        from pcapkit.const.tcp.checksum import Checksum
        from pcapkit.const.tcp.flags import Flags
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
        from pcapkit.const.tcp.option import Option
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.data.transport import tcp as tcp_data
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(TCP)

        self.assertEqual(proto._make_mode_donone(
            Option.RFC3692_style_Experiment_1,
            tcp_data.UnassignedOption(kind=Option.RFC3692_style_Experiment_1,
                                      length=4, data=b'zz'),
        ).data, b'zz')
        self.assertEqual(proto._make_mode_mss(
            Option.Maximum_Segment_Size,
            tcp_data.MaximumSegmentSize(kind=Option.Maximum_Segment_Size,
                                        length=4, mss=1200),
        ).mss, 1200)
        self.assertEqual(proto._make_mode_ws(
            Option.Window_Scale,
            tcp_data.WindowScale(kind=Option.Window_Scale, length=3, shift=5),
        ).shift, 5)
        self.assertEqual(proto._make_mode_sack(
            Option.SACK,
            tcp_data.SACK(kind=Option.SACK, length=18,
                          sack=(tcp_data.SACKBlock(left=1, right=2),
                                tcp_data.SACKBlock(left=3, right=4))),
        ).sack[1].right, 4)
        self.assertEqual(proto._make_mode_sack(Option.SACK).sack, [])
        self.assertEqual(proto._make_mode_echo(
            Option.Echo,
            tcp_data.Echo(kind=Option.Echo, length=6, data=b'echo'),
        ).data, b'echo')
        self.assertEqual(proto._make_mode_echore(
            Option.Echo_Reply,
            tcp_data.EchoReply(kind=Option.Echo_Reply, length=6, data=b'erpl'),
        ).data, b'erpl')
        self.assertEqual(proto._make_mode_ts(
            Option.Timestamps,
            tcp_data.Timestamps(kind=Option.Timestamps, length=10,
                                timestamp=10, echo=11),
        ).reply, 11)
        self.assertEqual(proto._make_mode_pocsp(
            Option.Partial_Order_Service_Profile,
            tcp_data.PartialOrderServiceProfile(
                kind=Option.Partial_Order_Service_Profile,
                length=3,
                start=True,
                end=True,
            ),
        ).profile['end'], True)
        self.assertEqual(proto._make_mode_cc(
            Option.CC,
            tcp_data.CC(kind=Option.CC, length=6, cc=21),
        ).count, 21)
        self.assertEqual(proto._make_mode_ccnew(
            Option.CC_NEW,
            tcp_data.CCNew(kind=Option.CC_NEW, length=6, cc=22),
        ).count, 22)
        self.assertEqual(proto._make_mode_ccecho(
            Option.CC_ECHO,
            tcp_data.CCEcho(kind=Option.CC_ECHO, length=6, cc=23),
        ).count, 23)
        self.assertEqual(proto._make_mode_chkreq(
            Option.TCP_Alternate_Checksum_Request,
            tcp_data.AlternateChecksumRequest(
                kind=Option.TCP_Alternate_Checksum_Request,
                length=3,
                chksum=Checksum.TCP_checksum,
            ),
        ).algorithm, Checksum.TCP_checksum)
        self.assertEqual(proto._make_mode_chksum(
            Option.TCP_Alternate_Checksum_Data,
            tcp_data.AlternateChecksumData(kind=Option.TCP_Alternate_Checksum_Data,
                                           length=5, data=b'abc'),
        ).data, b'abc')
        self.assertEqual(proto._make_mode_sig(
            Option.MD5_Signature_Option,
            tcp_data.MD5Signature(kind=Option.MD5_Signature_Option,
                                  length=18, digest=b'1' * 16),
        ).digest, b'1' * 16)
        self.assertEqual(proto._make_mode_qs(
            Option.Quick_Start_Response,
            tcp_data.QuickStartResponse(kind=Option.Quick_Start_Response,
                                        length=8, req_rate=80,
                                        ttl_diff=7, nonce=9),
        ).diff, 7)
        self.assertEqual(proto._make_mode_timeout(
            Option.User_Timeout_Option,
            tcp_data.UserTimeout(kind=Option.User_Timeout_Option,
                                 length=4,
                                 timeout=datetime.timedelta(seconds=120)),
        ).info['timeout'], 120)
        self.assertEqual(proto._make_mode_ao(
            Option.TCP_Authentication_Option,
            tcp_data.Authentication(kind=Option.TCP_Authentication_Option,
                                    length=7, key_id=1, next_key_id=2,
                                    mac=b'mac'),
        ).mac, b'mac')
        self.assertEqual(proto._make_mode_fastopen(
            Option.TCP_Fast_Open_Cookie,
            tcp_data.FastOpenCookie(kind=Option.TCP_Fast_Open_Cookie,
                                    length=8, cookie=b'cookie'),
        ).cookie, b'cookie')

        schema_options, schema_total = proto._make_tcp_options([
            b'\x01',
            proto._make_mode_nop(Option.No_Operation),
            proto._make_mode_mss(Option.Maximum_Segment_Size, mss=1460),
        ])
        self.assertEqual(schema_total, 4)
        self.assertEqual(len(schema_options), 1)
        self.assertEqual(schema_options[0].mss, 1460)

        option_map = OrderedMultiDict([
            (Option.No_Operation,
             tcp_data.NoOperation(kind=Option.No_Operation, length=1)),
            (Option.Maximum_Segment_Size,
             tcp_data.MaximumSegmentSize(kind=Option.Maximum_Segment_Size,
                                         length=4, mss=1300)),
            (Option.Window_Scale,
             tcp_data.WindowScale(kind=Option.Window_Scale, length=3, shift=2)),
            (Option.SACK_Permitted,
             tcp_data.SACKPermitted(kind=Option.SACK_Permitted, length=2)),
        ])
        mapped_options, mapped_total = proto._make_tcp_options(option_map)
        self.assertEqual(mapped_total, 12)
        self.assertEqual(mapped_options[0].mss, 1300)
        self.assertEqual(type(mapped_options[-1]).__name__, 'EndOfOptionList')

        proto._flags = {Flags.SYN}
        join_syn = tcp_data.MPTCPJoinSYN(
            kind=Option.Multipath_TCP,
            length=12,
            subtype=MPTCPOption.MP_JOIN,
            connection=Flags.SYN,
            backup=True,
            addr_id=1,
            token=2,
            nonce=3,
        )
        self.assertEqual(proto._make_mode_mp(Option.Multipath_TCP, join_syn).addr_id, 1)

        proto._flags = {Flags.SYN, Flags.ACK}
        join_synack = tcp_data.MPTCPJoinSYNACK(
            kind=Option.Multipath_TCP,
            length=20,
            subtype=MPTCPOption.MP_JOIN,
            connection=Flags.SYN | Flags.ACK,
            backup=True,
            addr_id=2,
            hmac=b'12345678',
            nonce=4,
        )
        self.assertEqual(proto._make_mode_mp(Option.Multipath_TCP, join_synack).addr_id, 2)

        proto._flags = {Flags.ACK}
        join_ack = tcp_data.MPTCPJoinACK(
            kind=Option.Multipath_TCP,
            length=24,
            subtype=MPTCPOption.MP_JOIN,
            connection=Flags.ACK,
            hmac=b'1' * 20,
        )
        self.assertEqual(proto._make_mode_mp(Option.Multipath_TCP, join_ack).hmac, b'1' * 20)

        proto._flags = set()
        capable = tcp_data.MPTCPCapable(
            kind=Option.Multipath_TCP,
            length=32,
            subtype=MPTCPOption.MP_CAPABLE,
            version=0,
            flags=tcp_data.MPTCPCapableFlag(req=True, ext=False, hsa=True),
            skey=1,
            rkey=2,
        )
        self.assertEqual(proto._make_mode_mp(Option.Multipath_TCP, capable).rkey, 2)
        self.assertEqual(proto._make_mptcp_unknown(
            MPTCPOption.Reserved_for_Private_Use,
            tcp_data.MPTCPUnknown(kind=Option.Multipath_TCP,
                                  length=3,
                                  subtype=MPTCPOption.Reserved_for_Private_Use,
                                  data=b'\x0fz'),
        ).data, b'z')
        self.assertTrue(proto._make_mptcp_dss(
            MPTCPOption.DSS,
            tcp_data.MPTCPDSS(kind=Option.Multipath_TCP,
                              length=18,
                              subtype=MPTCPOption.DSS,
                              data_fin=True,
                              ack=(1 << 33),
                              dsn=(1 << 33),
                              ssn=2,
                              dl_len=3,
                              checksum=b'\x00\x01'),
        ).flags['a'])
        with self.assertRaises(ProtocolError):
            proto._make_mptcp_dss(MPTCPOption.DSS, ssn=2)
        self.assertEqual(str(proto._make_mptcp_addaddr(
            MPTCPOption.ADD_ADDR,
            tcp_data.MPTCPAddAddress(kind=Option.Multipath_TCP,
                                     length=10,
                                     subtype=MPTCPOption.ADD_ADDR,
                                     version=4,
                                     addr_id=1,
                                     addr=ipaddress.ip_address('192.0.2.1'),
                                     port=None),
        ).address), '192.0.2.1')
        self.assertEqual(proto._make_mptcp_remove(
            MPTCPOption.REMOVE_ADDR,
            tcp_data.MPTCPRemoveAddress(kind=Option.Multipath_TCP,
                                        length=4,
                                        subtype=MPTCPOption.REMOVE_ADDR,
                                        addr_id=(1, 2)),
        ).addr_id, (1, 2))
        self.assertEqual(proto._make_mptcp_prio(
            MPTCPOption.MP_PRIO,
            tcp_data.MPTCPPriority(kind=Option.Multipath_TCP,
                                   length=4,
                                   subtype=MPTCPOption.MP_PRIO,
                                   backup=True,
                                   addr_id=5),
        ).addr_id, 5)
        self.assertEqual(proto._make_mptcp_fail(
            MPTCPOption.MP_FAIL,
            tcp_data.MPTCPFallback(kind=Option.Multipath_TCP,
                                   length=12,
                                   subtype=MPTCPOption.MP_FAIL,
                                   dsn=99),
        ).dsn, 99)
        self.assertEqual(proto._make_mptcp_fastclose(
            MPTCPOption.MP_FASTCLOSE,
            tcp_data.MPTCPFastclose(kind=Option.Multipath_TCP,
                                    length=12,
                                    subtype=MPTCPOption.MP_FASTCLOSE,
                                    rkey=123),
        ).key, 123)

    def test_tcp_option_readers_cover_common_and_error_branches(self) -> None:
        from pcapkit.const.tcp.checksum import Checksum
        from pcapkit.const.tcp.option import Option
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.schema.transport.tcp import (
            AlternateChecksumData,
            AlternateChecksumRequest,
            Authentication,
            CC,
            CCEcho,
            CCNew,
            Echo,
            EchoReply,
            EndOfOptionList,
            FastOpenCookie,
            MaximumSegmentSize,
            MD5Signature,
            NoOperation,
            PartialOrderConnectionPermitted,
            PartialOrderServiceProfile,
            QuickStartResponse,
            SACK,
            SACKBlock,
            SACKPermitted,
            Timestamps,
            UnassignedOption,
            UserTimeout,
            WindowScale,
        )
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(TCP)
        proto._read_unpack = lambda length: bytes(length)
        options = OrderedMultiDict()

        def assert_bad(reader, schema) -> None:
            with self.assertRaises(ProtocolError):
                reader(schema, options=options)

        unknown = proto._read_mode_donone(
            UnassignedOption(kind=Option.RFC3692_style_Experiment_1, length=4, data=b'xx'),
            options=options,
        )
        self.assertEqual(unknown.data, b'xx')
        self.assertEqual(
            proto._read_mode_eool(EndOfOptionList(kind=Option.End_of_Option_List), options=options).length,
            1,
        )
        self.assertEqual(
            proto._read_mode_nop(NoOperation(kind=Option.No_Operation), options=options).length,
            1,
        )
        self.assertEqual(
            proto._read_mode_mss(MaximumSegmentSize(kind=Option.Maximum_Segment_Size, length=4, mss=1460),
                                 options=options).mss,
            1460,
        )
        self.assertEqual(
            proto._read_mode_ws(WindowScale(kind=Option.Window_Scale, length=3, shift=7),
                                options=options).shift,
            7,
        )
        self.assertEqual(
            proto._read_mode_sackpmt(SACKPermitted(kind=Option.SACK_Permitted, length=2),
                                     options=options).length,
            2,
        )

        sack = proto._read_mode_sack(
            SACK(kind=Option.SACK, length=18,
                 sack=[SACKBlock(left=1, right=2), SACKBlock(left=3, right=4)]),
            options=options,
        )
        self.assertEqual([(block.left, block.right) for block in sack.sack], [(1, 2), (3, 4)])

        self.assertEqual(proto._read_mode_echo(Echo(kind=Option.Echo, length=6, data=b'abcd'),
                                               options=options).data, b'abcd')
        self.assertEqual(proto._read_mode_echore(EchoReply(kind=Option.Echo_Reply, length=6,
                                                           data=b'wxyz'), options=options).data, b'wxyz')
        self.assertEqual(proto._read_mode_ts(Timestamps(kind=Option.Timestamps, length=10,
                                                        value=1, reply=2), options=options).echo, 2)
        self.assertEqual(
            proto._read_mode_poc(PartialOrderConnectionPermitted(
                kind=Option.Partial_Order_Connection_Permitted, length=2,
            ), options=options).length,
            2,
        )
        profile = proto._read_mode_pocsp(
            PartialOrderServiceProfile(kind=Option.Partial_Order_Service_Profile, length=3,
                                       profile={'start': 1, 'end': 0}),
            options=options,
        )
        self.assertTrue(profile.start)
        self.assertFalse(profile.end)
        self.assertEqual(proto._read_mode_cc(CC(kind=Option.CC, length=6, count=1),
                                             options=options).cc, 1)
        self.assertEqual(proto._read_mode_ccnew(CCNew(kind=Option.CC_NEW, length=6, count=2),
                                                options=options).cc, 2)
        self.assertEqual(proto._read_mode_ccecho(CCEcho(kind=Option.CC_ECHO, length=6, count=3),
                                                 options=options).cc, 3)
        self.assertEqual(proto._read_mode_chkreq(
            AlternateChecksumRequest(kind=Option.TCP_Alternate_Checksum_Request, length=3,
                                     algorithm=Checksum.TCP_checksum),
            options=options,
        ).chksum, Checksum.TCP_checksum)
        self.assertEqual(proto._read_mode_chksum(
            AlternateChecksumData(kind=Option.TCP_Alternate_Checksum_Data, length=5, data=b'abc'),
            options=options,
        ).data, b'abc')
        self.assertEqual(proto._read_mode_sig(
            MD5Signature(kind=Option.MD5_Signature_Option, length=18, digest=b'0' * 16),
            options=options,
        ).digest, b'0' * 16)
        self.assertEqual(proto._read_mode_qs(
            QuickStartResponse(kind=Option.Quick_Start_Response, length=8,
                               flags={'rate': 1}, diff=4, nonce={'nonce': 5}),
            options=options,
        ).req_rate, 80.0)
        self.assertEqual(proto._read_mode_timeout(
            UserTimeout(kind=Option.User_Timeout_Option, length=4,
                        info={'granularity': 0, 'timeout': 60}),
            options=options,
        ).timeout, datetime.timedelta(seconds=60))
        self.assertEqual(proto._read_mode_timeout(
            UserTimeout(kind=Option.User_Timeout_Option, length=4,
                        info={'granularity': 1, 'timeout': 2}),
            options=options,
        ).timeout, datetime.timedelta(minutes=2))
        self.assertEqual(proto._read_mode_ao(
            Authentication(kind=Option.TCP_Authentication_Option, length=7,
                           key_id=1, next_key_id=2, mac=b'mac'),
            options=options,
        ).mac, b'mac')
        self.assertIsNone(proto._read_mode_fastopen(
            FastOpenCookie(kind=Option.TCP_Fast_Open_Cookie, length=2, cookie=None),
            options=options,
        ).cookie)
        self.assertEqual(proto._read_mode_fastopen(
            FastOpenCookie(kind=Option.TCP_Fast_Open_Cookie, length=8, cookie=b'cookie'),
            options=options,
        ).cookie, b'cookie')

        proto.__header__ = types.SimpleNamespace(options=[
            proto._make_mode_mss(Option.Maximum_Segment_Size, mss=1460),
            proto._make_mode_nop(Option.No_Operation),
            proto._make_mode_eool(Option.End_of_Option_List),
            proto._make_mode_ws(Option.Window_Scale, shift=2),
        ])
        parsed = proto._read_tcp_options(6)
        self.assertEqual(list(parsed.keys()), [
            Option.Maximum_Segment_Size,
            Option.No_Operation,
            Option.End_of_Option_List,
        ])
        self.assertEqual(list(parsed.values())[0].mss, 1460)
        with self.assertRaises(ProtocolError):
            proto._read_tcp_options(5)

        assert_bad(proto._read_mode_mss, MaximumSegmentSize(kind=Option.Maximum_Segment_Size,
                                                           length=5, mss=1460))
        assert_bad(proto._read_mode_ws, WindowScale(kind=Option.Window_Scale, length=4, shift=7))
        assert_bad(proto._read_mode_sackpmt, SACKPermitted(kind=Option.SACK_Permitted, length=3))
        assert_bad(proto._read_mode_echo, Echo(kind=Option.Echo, length=5, data=b'abcd'))
        assert_bad(proto._read_mode_echore, EchoReply(kind=Option.Echo_Reply, length=5, data=b'wxyz'))
        assert_bad(proto._read_mode_ts, Timestamps(kind=Option.Timestamps, length=9, value=1, reply=2))
        assert_bad(proto._read_mode_poc, PartialOrderConnectionPermitted(
            kind=Option.Partial_Order_Connection_Permitted, length=3,
        ))
        assert_bad(proto._read_mode_pocsp, PartialOrderServiceProfile(
            kind=Option.Partial_Order_Service_Profile, length=4,
            profile={'start': 1, 'end': 0},
        ))
        assert_bad(proto._read_mode_cc, CC(kind=Option.CC, length=5, count=1))
        assert_bad(proto._read_mode_ccnew, CCNew(kind=Option.CC_NEW, length=5, count=2))
        assert_bad(proto._read_mode_ccecho, CCEcho(kind=Option.CC_ECHO, length=5, count=3))
        assert_bad(proto._read_mode_chkreq, AlternateChecksumRequest(
            kind=Option.TCP_Alternate_Checksum_Request, length=4,
            algorithm=Checksum.TCP_checksum,
        ))
        assert_bad(proto._read_mode_sig, MD5Signature(kind=Option.MD5_Signature_Option,
                                                      length=17, digest=b'0' * 16))
        assert_bad(proto._read_mode_qs, QuickStartResponse(
            kind=Option.Quick_Start_Response, length=7,
            flags={'rate': 1}, diff=4, nonce={'nonce': 5},
        ))
        assert_bad(proto._read_mode_timeout, UserTimeout(
            kind=Option.User_Timeout_Option, length=5,
            info={'granularity': 0, 'timeout': 60},
        ))
        assert_bad(proto._read_mode_ao, Authentication(
            kind=Option.TCP_Authentication_Option, length=3,
            key_id=1, next_key_id=2, mac=b'',
        ))
        assert_bad(proto._read_mode_fastopen, FastOpenCookie(
            kind=Option.TCP_Fast_Open_Cookie, length=4, cookie=b'ab',
        ))
        assert_bad(proto._read_mode_fastopen, FastOpenCookie(
            kind=Option.TCP_Fast_Open_Cookie, length=7, cookie=b'12345',
        ))

    def test_tcp_mptcp_constructors_cover_flag_branches(self) -> None:
        from pcapkit.const.tcp.flags import Flags
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
        from pcapkit.const.tcp.option import Option
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(TCP)

        self.assertEqual(
            proto._make_mode_mp(Option.Multipath_TCP, subtype=MPTCPOption.MP_CAPABLE,
                                skey=1, rkey=None).to_dict()['skey'],
            1,
        )
        self.assertEqual(
            type(proto._make_mode_mp(Option.Multipath_TCP, subtype=MPTCPOption.REMOVE_ADDR,
                                     addr_id=[1]).to_dict()).__name__,
            'dict',
        )
        self.assertEqual(
            proto._make_mptcp_unknown(MPTCPOption.Reserved_for_Private_Use,
                                      data=b'\xfa\x01').to_dict()['data'],
            b'\x01',
        )
        self.assertIsNone(proto._make_mptcp_capable(MPTCPOption.MP_CAPABLE,
                                                    rkey=None, skey=1).to_dict()['rkey'])
        self.assertEqual(proto._make_mptcp_capable(MPTCPOption.MP_CAPABLE,
                                                   rkey=2, skey=1).to_dict()['rkey'], 2)

        proto._flags = {Flags.SYN}
        join_syn = proto._make_mptcp_join(MPTCPOption.MP_JOIN, backup=True,
                                          addr_id=1, token=2, nonce=3)
        self.assertEqual(type(join_syn).__name__, 'MPTCPJoinSYN')
        self.assertTrue(join_syn.to_dict()['test']['backup'])

        proto._flags = {Flags.SYN, Flags.ACK}
        join_synack = proto._make_mptcp_join(MPTCPOption.MP_JOIN, addr_id=1,
                                             hmac=b'12345678', nonce=3)
        self.assertEqual(type(join_synack).__name__, 'MPTCPJoinSYNACK')
        self.assertEqual(join_synack.to_dict()['hmac'], b'12345678')

        proto._flags = {Flags.ACK}
        join_ack = proto._make_mptcp_join(MPTCPOption.MP_JOIN, hmac=b'1' * 20)
        self.assertEqual(type(join_ack).__name__, 'MPTCPJoinACK')
        self.assertEqual(join_ack.to_dict()['hmac'], b'1' * 20)

        proto._flags = set()
        self.assertTrue(proto._make_mptcp_dss(MPTCPOption.DSS, data_fin=True,
                                              ack=1).to_dict()['flags']['A'])
        self.assertTrue(proto._make_mptcp_dss(MPTCPOption.DSS, dsn=1, ssn=2,
                                              dl_len=3, checksum=b'\x00\x01').to_dict()['flags']['M'])
        self.assertEqual(str(proto._make_mptcp_addaddr(MPTCPOption.ADD_ADDR, addr_id=1,
                                                       addr='2001:db8::1',
                                                       port=443).to_dict()['address']), '2001:db8::1')
        self.assertEqual(proto._make_mptcp_remove(MPTCPOption.REMOVE_ADDR,
                                                  addr_id=[1, 2]).to_dict()['addr_id'], [1, 2])
        self.assertTrue(proto._make_mptcp_prio(MPTCPOption.MP_PRIO,
                                               backup=True, addr_id=1).to_dict()['test']['backup'])
        self.assertEqual(proto._make_mptcp_fail(MPTCPOption.MP_FAIL, dsn=99).to_dict()['dsn'], 99)
        self.assertEqual(proto._make_mptcp_fastclose(MPTCPOption.MP_FASTCLOSE,
                                                     key=123).to_dict()['key'], 123)

        with self.assertRaises(ProtocolError):
            proto._make_mptcp_join(MPTCPOption.MP_JOIN)
        with self.assertRaises(ProtocolError):
            proto._make_mptcp_dss(MPTCPOption.DSS, dsn=1)

    def test_tcp_mptcp_readers_cover_subtype_and_error_branches(self) -> None:
        from pcapkit.const.tcp.flags import Flags
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
        from pcapkit.const.tcp.option import Option
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.schema.transport.tcp import (
            MPTCPAddAddress,
            MPTCPCapable,
            MPTCPDSS,
            MPTCPFallback,
            MPTCPFastclose,
            MPTCPJoinACK,
            MPTCPJoinSYN,
            MPTCPJoinSYNACK,
            MPTCPPriority,
            MPTCPRemoveAddress,
            MPTCPUnknown,
        )
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(TCP)
        options = OrderedMultiDict()

        def mark(schema, length: int, subtype: MPTCPOption):
            object.__setattr__(schema, 'kind', Option.Multipath_TCP)
            object.__setattr__(schema, 'length', length)
            object.__setattr__(schema, 'subtype', subtype)
            return schema

        unknown = mark(
            MPTCPUnknown(test={'subtype': MPTCPOption.Reserved_for_Private_Use.value, 'data': 10},
                         data=b'\x01'),
            4,
            MPTCPOption.Reserved_for_Private_Use,
        )
        self.assertEqual(proto._read_mode_mp(unknown, options=options).data, b'\x0a\x01')

        capable_no_receiver = mark(
            MPTCPCapable(test={'subtype': MPTCPOption.MP_CAPABLE.value, 'version': 0},
                         flags={'req': 1, 'ext': 0, 'hsa': 1}, skey=1, rkey=2),
            20,
            MPTCPOption.MP_CAPABLE,
        )
        capable = proto._read_mode_mp(capable_no_receiver, options=options)
        self.assertTrue(capable.flags.req)
        self.assertTrue(capable.flags.hsa)
        self.assertIsNone(capable.rkey)

        capable_with_receiver = mark(
            MPTCPCapable(test={'subtype': MPTCPOption.MP_CAPABLE.value, 'version': 0},
                         flags={'req': 0, 'ext': 1, 'hsa': 0}, skey=1, rkey=2),
            32,
            MPTCPOption.MP_CAPABLE,
        )
        self.assertEqual(proto._read_mode_mp(capable_with_receiver, options=options).rkey, 2)
        with self.assertRaises(ProtocolError):
            proto._read_mode_mp(mark(
                MPTCPCapable(test={'subtype': MPTCPOption.MP_CAPABLE.value, 'version': 0},
                             flags={'req': 0, 'ext': 0, 'hsa': 0}, skey=1, rkey=None),
                12,
                MPTCPOption.MP_CAPABLE,
            ), options=options)

        proto._flags = {Flags.SYN}
        join_syn = mark(
            MPTCPJoinSYN(test={'subtype': MPTCPOption.MP_JOIN.value, 'backup': 1},
                         addr_id=1, token=2, nonce=3),
            12,
            MPTCPOption.MP_JOIN,
        )
        self.assertTrue(proto._read_mode_mp(join_syn, options=options).backup)
        with self.assertRaises(ProtocolError):
            proto._read_mode_mp(mark(
                MPTCPJoinSYN(test={'subtype': MPTCPOption.MP_JOIN.value, 'backup': 0},
                             addr_id=1, token=2, nonce=3),
                11,
                MPTCPOption.MP_JOIN,
            ), options=options)

        proto._flags = {Flags.SYN, Flags.ACK}
        join_synack = mark(
            MPTCPJoinSYNACK(test={'subtype': MPTCPOption.MP_JOIN.value, 'backup': 0},
                            addr_id=1, hmac=b'12345678', nonce=3),
            20,
            MPTCPOption.MP_JOIN,
        )
        self.assertEqual(proto._read_mode_mp(join_synack, options=options).hmac, b'12345678')
        with self.assertRaises(ProtocolError):
            proto._read_mode_mp(mark(
                MPTCPJoinSYNACK(test={'subtype': MPTCPOption.MP_JOIN.value, 'backup': 0},
                                addr_id=1, hmac=b'12345678', nonce=3),
                19,
                MPTCPOption.MP_JOIN,
            ), options=options)

        proto._flags = {Flags.ACK}
        join_ack = mark(
            MPTCPJoinACK(test={'subtype': MPTCPOption.MP_JOIN.value}, hmac=b'1' * 20),
            24,
            MPTCPOption.MP_JOIN,
        )
        self.assertEqual(proto._read_mode_mp(join_ack, options=options).hmac, b'1' * 20)
        with self.assertRaises(ProtocolError):
            proto._read_mode_mp(mark(
                MPTCPJoinACK(test={'subtype': MPTCPOption.MP_JOIN.value}, hmac=b'1' * 20),
                23,
                MPTCPOption.MP_JOIN,
            ), options=options)
        proto._flags = set()
        with self.assertRaises(ProtocolError):
            proto._read_mode_mp(join_syn, options=options)

        dss = mark(
            MPTCPDSS(test={'subtype': MPTCPOption.DSS.value},
                     flags={'F': 1, 'm': 0, 'M': 1, 'a': 0, 'A': 1},
                     ack=1, dsn=2, ssn=3, dl_len=4, checksum=b'\x00\x01'),
            18,
            MPTCPOption.DSS,
        )
        dss_data = proto._read_mode_mp(dss, options=options)
        self.assertTrue(dss_data.data_fin)
        self.assertEqual(dss_data.checksum, b'\x00\x01')

        addaddr = mark(
            MPTCPAddAddress(test={'subtype': MPTCPOption.ADD_ADDR.value, 'version': 4},
                            addr_id=1, address=ipaddress.ip_address('192.0.2.1'), port=443),
            10,
            MPTCPOption.ADD_ADDR,
        )
        self.assertEqual(str(proto._read_mode_mp(addaddr, options=options).addr), '192.0.2.1')
        with self.assertRaises(ProtocolError):
            proto._read_mode_mp(mark(
                MPTCPAddAddress(test={'subtype': MPTCPOption.ADD_ADDR.value, 'version': 5},
                                addr_id=1, address=ipaddress.ip_address('192.0.2.1'), port=None),
                8,
                MPTCPOption.ADD_ADDR,
            ), options=options)

        remove = mark(
            MPTCPRemoveAddress(test={'subtype': MPTCPOption.REMOVE_ADDR.value}, addr_id=[1, 2]),
            4,
            MPTCPOption.REMOVE_ADDR,
        )
        self.assertEqual(proto._read_mode_mp(remove, options=options).addr_id, (1, 2))
        with self.assertRaises(ProtocolError):
            proto._read_mode_mp(mark(
                MPTCPRemoveAddress(test={'subtype': MPTCPOption.REMOVE_ADDR.value}, addr_id=[]),
                2,
                MPTCPOption.REMOVE_ADDR,
            ), options=options)

        prio = mark(
            MPTCPPriority(test={'subtype': MPTCPOption.MP_PRIO.value, 'backup': 1}, addr_id=9),
            4,
            MPTCPOption.MP_PRIO,
        )
        self.assertTrue(proto._read_mode_mp(prio, options=options).backup)
        self.assertIsNone(proto._read_mode_mp(mark(
            MPTCPPriority(test={'subtype': MPTCPOption.MP_PRIO.value, 'backup': 0}, addr_id=None),
            3,
            MPTCPOption.MP_PRIO,
        ), options=options).addr_id)
        with self.assertRaises(ProtocolError):
            proto._read_mode_mp(mark(
                MPTCPPriority(test={'subtype': MPTCPOption.MP_PRIO.value, 'backup': 0}, addr_id=None),
                5,
                MPTCPOption.MP_PRIO,
            ), options=options)

        fallback = mark(
            MPTCPFallback(test={'subtype': MPTCPOption.MP_FAIL.value}, dsn=99),
            12,
            MPTCPOption.MP_FAIL,
        )
        self.assertEqual(proto._read_mode_mp(fallback, options=options).dsn, 99)
        with self.assertRaises(ProtocolError):
            proto._read_mode_mp(mark(
                MPTCPFallback(test={'subtype': MPTCPOption.MP_FAIL.value}, dsn=99),
                11,
                MPTCPOption.MP_FAIL,
            ), options=options)

        fastclose = mark(
            MPTCPFastclose(test={'subtype': MPTCPOption.MP_FASTCLOSE.value}, key=123),
            16,
            MPTCPOption.MP_FASTCLOSE,
        )
        self.assertEqual(proto._read_mode_mp(fastclose, options=options).rkey, 123)
        with self.assertRaises(ProtocolError):
            proto._read_mode_mp(mark(
                MPTCPFastclose(test={'subtype': MPTCPOption.MP_FASTCLOSE.value}, key=123),
                15,
                MPTCPOption.MP_FASTCLOSE,
            ), options=options)

    def test_transport_schema_helpers_cover_selectors_and_port_fields(self) -> None:
        from pcapkit.const.reg.apptype import AppType, TransportProtocol
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
        from pcapkit.const.tcp.option import Option
        from pcapkit.protocols.schema.transport import tcp as tcp_schema
        from pcapkit.protocols.schema.transport import udp as udp_schema
        from pcapkit.utilities.exceptions import FieldError

        tcp_field = tcp_schema.PortEnumField(length=2, namespace=AppType)
        tcp_field.name = 'srcport'
        self.assertEqual(
            tcp_field.pack(AppType.get(443, proto=TransportProtocol.tcp), {}),
            b'\x01\xbb',
        )
        self.assertEqual(tcp_field.pack(443, {}), b'\x01\xbb')
        self.assertEqual(tcp_field.unpack(b'\x01\xbb', {}).port, 443)

        udp_field = udp_schema.PortEnumField(length=2, namespace=AppType)
        udp_field.name = 'dstport'
        self.assertEqual(
            udp_field.pack(AppType.get(53, proto=TransportProtocol.udp), {}),
            b'\x005',
        )
        self.assertEqual(udp_field.pack(53, {}), b'\x005')
        self.assertEqual(udp_field.unpack(b'\x005', {}).port, 53)

        capable_selector = tcp_schema.mptcp_data_selector({
            'test': {'subtype': MPTCPOption.MP_CAPABLE.value, 'length': 12},
            'flags': {'syn': 0, 'ack': 0},
        })
        self.assertIs(capable_selector.schema, tcp_schema.MPTCPCapable)

        join_cases = [
            ({'syn': 1, 'ack': 0}, tcp_schema.MPTCPJoinSYN),
            ({'syn': 1, 'ack': 1}, tcp_schema.MPTCPJoinSYNACK),
            ({'syn': 0, 'ack': 1}, tcp_schema.MPTCPJoinACK),
        ]
        for flags, schema_cls in join_cases:
            field = tcp_schema.mptcp_data_selector({
                'test': {'subtype': MPTCPOption.MP_JOIN.value, 'length': 12},
                'flags': flags,
            })
            self.assertIs(field.schema, schema_cls)

        with self.assertRaises(FieldError):
            tcp_schema.mptcp_data_selector({
                'test': {'subtype': MPTCPOption.MP_JOIN.value, 'length': 12},
                'flags': {'syn': 0, 'ack': 0},
            })

        self.assertEqual(type(tcp_schema.mptcp_add_address_selector({
            'test': {'version': 4},
        })).__name__, 'IPv4AddressField')
        self.assertEqual(type(tcp_schema.mptcp_add_address_selector({
            'test': {'version': 6},
        })).__name__, 'IPv6AddressField')
        with self.assertRaises(FieldError):
            tcp_schema.mptcp_add_address_selector({'test': {'version': 5}})

        inner = tcp_schema.MPTCPUnknown(
            test={'subtype': MPTCPOption.Reserved_for_Private_Use.value, 'data': 1},
            data=b'x',
        )
        wrapper = object.__new__(tcp_schema._MPTCP)
        object.__setattr__(wrapper, 'data', inner)
        object.__setattr__(wrapper, 'test', {
            'length': 3,
            'subtype': MPTCPOption.Reserved_for_Private_Use.value,
        })

        processed = tcp_schema._MPTCP.post_process(
            wrapper,
            {'test': {'subtype': MPTCPOption.Reserved_for_Private_Use.value}},
        )
        self.assertIs(processed, inner)
        self.assertEqual(processed.option, Option.Multipath_TCP)
        self.assertEqual(processed.length, 3)
        self.assertEqual(processed.subtype, MPTCPOption.Reserved_for_Private_Use)


if __name__ == '__main__':
    unittest.main()
