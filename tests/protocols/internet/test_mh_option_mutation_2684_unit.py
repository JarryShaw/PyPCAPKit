# -*- coding: utf-8 -*-
"""A mobility option changed in one octet is refused or rebuilds byte for byte.

GitHub issue #2684. Option fields were read at their own widths whatever the
length said, so a length they overran or fell short of rebuilt as another; a
prefix length longer than its address parsed and then refused to rebuild; a text
identifier rebuilt the length of its text re-encoded; and the Quality-of-Service
traffic class lost its reserved bits.

Every registered option is built from a valid example inside a Binding Refresh
Request, and each octet of it changed in turn. The cases the issue reports are
pinned by name, against what their RFCs say the octets hold.

Every case builds its own octets in memory and reads no capture.

"""

import struct
import unittest
import warnings

from tests._support import reimport_once_per_class
from tests.utilities._harness import capture

#: Test tier (#1958): a sweep over every registered mobility option.
__tier__ = 'LATEST'

V6 = '2001:db8::1'
V4 = '198.51.100.7'
#: A DER SEQUENCE of 159 octets, whose length takes the long form.
LONG_KEY = b'\x30\x81\x9f' + bytes(range(159))

#: Options a one-octet change makes the reader raise an error that is not
#: pcapkit's, by the reader whose data model has no form for the octets. Inside
#: IPv6 the header is then Raw, so the round trip holds.
KNOWN_CRASHES = {}  # type: dict[str, str]


def _ipv6(body: bytes) -> bytes:
    return (bytes([0x60, 0, 0, 0]) + struct.pack('!HBB', len(body), 135, 64)
            + bytes(15) + b'\x01' + bytes(15) + b'\x02' + body)


def _examples() -> 'dict':
    """Valid arguments for the options whose defaults are not, or are too thin."""
    from pcapkit.const.mh.ani_suboption import ANISuboption as ANI
    from pcapkit.const.mh.cga_extension import CGAExtension
    from pcapkit.const.mh.cga_type import CGAType
    from pcapkit.const.mh.flow_id_suboption import FlowIDSuboption as FID
    from pcapkit.const.mh.lma_mag_suboption import LMAControlledMAGSuboption as LCMP
    from pcapkit.const.mh.mn_id_subtype import MNIDSubtype
    from pcapkit.const.mh.option import Option
    from pcapkit.const.mh.qos_attribute import QoSAttribute as QoS
    from pcapkit.protocols.internet.mh.data import CGAParameter

    fields = {'modifier': CGAType.Tag_086F_CA5E_10B2_00C9_9C8C_E001_6427_7C08,
              'prefix': 0x20010db800000000, 'collision_count': 0}  # type: dict
    parameter = CGAParameter(**fields, public_key=b'\x30\x02\xaa\xbb', extensions=[
        (CGAExtension.Multi_Prefix, {'prefixes': [0x20010db800000001]})])
    # a DER key past 127 octets, as a 1024-bit RSA SubjectPublicKeyInfo is
    long_key = CGAParameter(**fields, public_key=LONG_KEY, extensions=[])
    return {
        Option.PadN: [{'length': 4}],
        Option.Authorization_Data: [{'data': bytes(range(8))}],
        Option.Mobility_Header_Link_Layer_Address_option: [{'address': b'\x00\x11\x22\x33\x44\x55'}],
        Option.MN_ID_OPTION_TYPE: [{}, {'subtype': MNIDSubtype.NAI, 'identifier': 'usér@example.com'},
                                   {'subtype': MNIDSubtype.IMSI, 'identifier': b'\x12\x34\x56\x78\x9f'}],
        Option.AUTH_OPTION_TYPE: [{'spi': 0xdeadbeef, 'data': bytes(range(10))}],
        Option.MESG_ID_OPTION_TYPE: [{'seconds': 0x83aa7e80, 'fraction': 0x40000000}],
        Option.CGA_Parameters: [{'parameters': [parameter]}, {'parameters': [long_key]}],
        Option.Signature: [{'signature': b'\xaa' * 4}],
        Option.Permanent_Home_Keygen_Token: [{'token': bytes(range(8))}],
        Option.Experimental_Mobility_Option: [{'data': b'\x01\x02\x03\x04'}],
        Option.Binding_Authorization_Data_for_FMIPv6: [{'spi': 1, 'data': bytes(range(12))}],
        Option.Service_Selection_Mobility_Option: [{'identifier': 'ims'}],
        Option.Binding_Identifier: [{'bid': 5, 'address': V6}, {'bid': 5, 'address': V4}],
        Option.Local_Mobility_Anchor_Address_Option: [{'address': V6}, {'address': V4}],
        Option.Flow_Identification_Mobility_Option: [{'fid': 7, 'suboptions': [
            (FID.BID_Reference, {'bid': [1, 2]}),
            (FID.Traffic_Selector, {'ts_format': 2, 'selector': b'\x00\x01\x02\x03'}),
            (FID.Flow_Binding_Action, {'action': 11}),
            (FID.Target_Care_of_Address, {'address': V6}),
            (FID.Target_Care_of_Address, {'address': V4}),
            (FID.PadN, {'length': 2}), (FID.Pad, {}),
        ]}],
        Option.Redirect_Mobility_Option: [{'ipv6': V6}, {'ipv4': V4}],
        Option.Access_Network_Identifier: [{'suboptions': [
            (ANI.Network_Identifier, {'net_name': b'wifi', 'ap_name': b'\x00\x11\x22\x33\x44\x55'}),
            (ANI.Geo_Location, {'raw_latitude': -1234567, 'raw_longitude': 987654}),
            (ANI.Operator_Identifier, {'op_id_type': 2, 'identifier': b'example.com'}),
            (ANI.Civic_Location, {'format': 0, 'location': b'GB\x01\x02'}),
            (ANI.MAG_Group_Identifier, {'group_id': 9}),
            (ANI.ANI_Update_Timer, {'timer': 15}),
        ]}],
        Option.Delegated_Mobile_Network_Prefix: [{}, {'prefix_length': 24, 'prefix': '192.0.2.0'}],
        Option.Quality_of_Service: [{'sr_id': 3, 'dscp': 46, 'oc': 1, 'attributes': [
            (QoS.Per_MN_Agg_Max_DL_Bit_Rate, {'rate': 1_000_000}),
            (QoS.Per_Session_Agg_Max_UL_Bit_Rate, {'service': True, 'rate': 500_000}),
            (QoS.Allocation_Retention_Priority, {'priority_level': 5}),
            (QoS.QoS_Traffic_Selector, {'ts_format': 2, 'selector': b'\x01\x02'}),
            (QoS.QoS_Vendor_Specific_Attribute, {'vendor': 32473, 'subtype': 1, 'data': b'\xff'}),
        ]}],
        Option.LMA_User_Plane_Address: [{}, {'address': V6}, {'address': V4}],
        Option.LMA_Controlled_MAG_Parameters: [{'suboptions': [
            (LCMP.Binding_Re_registration_Control, {'start_time': 10, 'initial_retransmission': 2,
                                                    'max_retransmission': 30}),
            (LCMP.Heartbeat_Control, {'interval': 60, 'retransmission_delay': 3,
                                      'max_retransmissions': 5}),
        ]}],
    }


class TestMHOptionMutation(unittest.TestCase):
    """Pin byte-exact rebuilds of mobility options changed in one octet."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        catcher = warnings.catch_warnings()
        catcher.__enter__()
        self.addCleanup(catcher.__exit__, None, None, None)
        warnings.simplefilter('ignore')

    @staticmethod
    def _brr(code: 'object', kwargs: 'dict') -> bytes:
        from pcapkit.const.mh.packet import Packet
        from pcapkit.protocols.internet.mh.protocol import MH

        return MH(type=Packet.Binding_Refresh_Request, next=59, chksum=b'\x00\x00',
                  data={'options': [(code, kwargs)]}).data

    def _assert_identity_or_refused(self, raw: bytes, crashed: 'set[str]', name: str) -> 'object':
        """Parse ``raw`` alone and inside IPv6; return the parsed MH, or None if refused."""
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.internet.mh.protocol import MH
        from pcapkit.utilities.exceptions import BaseError

        try:
            mh = MH(raw, len(raw))
        except BaseError:
            mh = None
        except Exception:  # pylint: disable=broad-except
            crashed.add(name)
            mh = None
        else:
            self.assertEqual(MH.from_data(mh.info).data, raw)
            self.assertEqual(MH.from_data(mh.info.to_dict()).data, raw)

        packet = _ipv6(raw)
        ipv6 = IPv6(packet, len(packet))
        self.assertEqual(IPv6.from_data(ipv6.info).data, packet)
        return mh

    def test_reported_cases(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.corekit.fields.strings import DecodedString
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.internet.mh.protocol import MH
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.utilities import exceptions
        from pcapkit.utilities.exceptions import ProtocolError
        from pcapkit.utilities.logging import logger

        examples = _examples()
        # the issue's lone sub-options, so the octet changed is the first one's length
        examples[Option.LMA_Controlled_MAG_Parameters] = [{'suboptions': [
            examples[Option.LMA_Controlled_MAG_Parameters][0]['suboptions'][1]]}]
        examples[Option.Access_Network_Identifier] = [{'suboptions': [
            examples[Option.Access_Network_Identifier][0]['suboptions'][0]]}]
        # (option, octet of it, new value, refusal or the option the RFC reads)
        cases = (
            # (a) a length of 0 cannot hold the fields RFC 4283 section 3, RFC 8127
            # section 3.1.2 and RFC 6757 section 3.1.1 give
            (Option.MN_ID_OPTION_TYPE, 1, 0x00, 'invalid option length'),
            (Option.LMA_Controlled_MAG_Parameters, 3, 0x00, 'invalid sub-option length'),
            (Option.Access_Network_Identifier, 3, 0x00, 'invalid sub-option length'),
            # (b) a prefix length past the address is kept, as no RFC discards it
            (Option.IPv4_Address_Acknowledgement, 3, 0xff, lambda opt: opt.prefix_length == 63),
            (Option.IPv4_Home_Address_Request, 2, 0xff, lambda opt: opt.prefix_length == 63),
            (Option.IPv4_Home_Address_Reply, 3, 0xff, lambda opt: opt.prefix_length == 63),
            (Option.Delegated_Mobile_Network_Prefix, 3, 0xc0, lambda opt: opt.prefix_length == 192),
            # (c) octets that are not UTF-8 keep their own length, RFC 5149 section 3
            (Option.Service_Selection_Mobility_Option, 2, 0xe9,
             lambda opt: isinstance(opt.identifier, DecodedString) and opt.identifier.raw == b'\xe9ms'),
            # (d) the traffic class is the DSCP then two reserved bits, RFC 7222 section 4.1
            (Option.Quality_of_Service, 3, 0xb9, lambda opt: (opt.dscp, opt.tc_reserved) == (46, 1)),
            # (e) a public key past the option, and an extension shorter than its fields
            (Option.CGA_Parameters, 28, 0x82, 'runs past the option'),
            (Option.CGA_Parameters, 34, 0x00, 'invalid extension length'),
            # (f) a Signature retyped as CGA Parameters, and an option retyped as Pad1
            (Option.Signature, 0, Option.CGA_Parameters, 'cannot hold their fixed fields'),
            (Option.Mobile_Node_Link_local_Address_Interface_Identifier_Option, 0, Option.Pad1,
             'invalid option length'),
        )
        for code, offset, value, expected in cases:
            whole = self._brr(code, examples.get(code, [{}])[0])
            raw = whole[:8 + offset] + bytes([value]) + whole[8 + offset + 1:]
            with self.subTest(option=code.name, offset=offset, raw=raw.hex()):
                packet = _ipv6(raw)
                with capture(logger) as package, capture(exceptions.logger) as module:
                    ipv6 = IPv6(packet, len(packet))
                self.assertEqual(package.messages + module.messages, [])
                self.assertEqual(IPv6.from_data(ipv6.info).data, packet)

                if isinstance(expected, str):
                    with self.assertRaisesRegex(ProtocolError, expected):
                        MH(raw, len(raw))
                    self.assertIsInstance(ipv6.payload, Raw)
                    self.assertRegex(str(ipv6.payload.info.error), expected)
                    continue

                mh = MH(raw, len(raw))
                self.assertTrue(expected(mh.info.options[code]))
                self.assertEqual(MH.from_data(mh.info).data, raw)
                self.assertEqual(MH.from_data(mh.info.to_dict()).data, raw)

    def test_text_identifiers_count_their_octets(self) -> None:
        from pcapkit.const.mh.mn_id_subtype import MNIDSubtype
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh.protocol import MH

        # RFC 4283 section 3 and RFC 5149 section 3 count octets, and NAI and the
        # service identifier are UTF-8, so a non-ASCII character takes two
        for code, kwargs, octets in (
                (Option.MN_ID_OPTION_TYPE, {'subtype': MNIDSubtype.NAI, 'identifier': 'usér@x'}, 8),
                (Option.Service_Selection_Mobility_Option, {'identifier': 'voip.é'}, 7),
        ):
            with self.subTest(option=code.name):
                raw = self._brr(code, kwargs)
                self.assertEqual(raw[9], octets)
                mh = MH(raw, len(raw))
                self.assertEqual(MH.from_data(mh.info).data, raw)

    def test_prefix_length_is_checked_against_its_field(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.const.mh.packet import Packet
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.internet.mh.protocol import MH
        from pcapkit.utilities.exceptions import ProtocolError

        # RFC 5555 section 3.2.1, RFC 5844 sections 3.3.1 and 3.3.2 and RFC 7148
        # section 4.1 discard no prefix length, so a caller, a hand-built model and
        # a parse are all held to the field's width alone, and agree
        for code, widest in ((Option.IPv4_Address_Acknowledgement, 0x3F),
                             (Option.IPv4_Home_Address_Request, 0x3F),
                             (Option.IPv4_Home_Address_Reply, 0x3F),
                             (Option.Delegated_Mobile_Network_Prefix, 0xFF)):
            whole = self._brr(code, {})
            parsed = MH(whole, len(whole)).info.options[code]
            for value in sorted({33, min(129, widest), widest, widest + 1}):
                model = type(parsed)(**{**parsed.to_dict(), 'prefix_length': value})
                options = OrderedMultiDict([(code, model)])
                with self.subTest(option=code.name, prefix_length=value):
                    if value > widest:
                        with self.assertRaisesRegex(ProtocolError, 'invalid prefix length'):
                            self._brr(code, {'prefix_length': value})
                        with self.assertRaisesRegex(ProtocolError, 'invalid prefix length'):
                            MH(type=Packet.Binding_Refresh_Request, next=59, chksum=b'\x00\x00',
                               data={'options': options})
                        continue
                    raw = self._brr(code, {'prefix_length': value})
                    self.assertEqual(MH(type=Packet.Binding_Refresh_Request, next=59, chksum=b'\x00\x00',
                                        data={'options': options}).data, raw)
                    self.assertEqual(MH(raw, len(raw)).info.options[code].prefix_length, value)

    def test_cga_public_key_takes_its_der_length(self) -> None:
        from pcapkit.const.mh.cga_type import CGAType
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh.data import CGAParameter
        from pcapkit.protocols.internet.mh.protocol import MH

        # RFC 3972 section 3 has the key a DER SubjectPublicKeyInfo, whose length
        # past 127 octets is 0x80 plus the count of the octets holding it (X.690)
        for key in (LONG_KEY, b'\x30\x82\x00\xa2' + bytes(162), b'\x30\x02\xaa\xbb'):
            with self.subTest(key=key[:4].hex()):
                raw = self._brr(Option.CGA_Parameters, {'parameters': [CGAParameter(
                    modifier=CGAType.Tag_086F_CA5E_10B2_00C9_9C8C_E001_6427_7C08, prefix=1,
                    collision_count=0, public_key=key, extensions=[])]})
                mh = MH(raw, len(raw))
                parameter, = mh.info.options[Option.CGA_Parameters].parameters
                self.assertEqual(parameter.public_key, key)
                self.assertEqual(len(parameter.extensions), 0)
                self.assertEqual(MH.from_data(mh.info).data, raw)

    def test_every_option_changed_in_one_octet(self) -> None:
        from pcapkit.protocols.internet.mh.protocol import MH

        examples = _examples()
        crashed = set()  # type: set[str]
        for code in sorted(MH.__option__, key=int):
            for kwargs in examples.get(code, [{}]):
                whole = self._brr(code, kwargs)
                self.assertIsNotNone(self._assert_identity_or_refused(whole, crashed, code.name), code.name)
                end = 9 if whole[8] == 0 else 10 + whole[9]
                for pos in range(8, end):
                    octet = whole[pos]
                    values = {0x00, 0xff, octet ^ 0x01, octet ^ 0x80, (octet + 1) & 0xff, (octet - 1) & 0xff}
                    if pos == 9:
                        values.update(range(octet + 9))  # the Option Length
                    for value in sorted(values - {octet}):
                        raw = whole[:pos] + bytes([value]) + whole[pos + 1:]
                        with self.subTest(option=code.name, pos=pos - 8, raw=raw.hex()):
                            self._assert_identity_or_refused(raw, crashed, code.name)
        self.assertEqual(crashed, set(KNOWN_CRASHES))


if __name__ == '__main__':
    unittest.main()
