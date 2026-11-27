# -*- coding: utf-8 -*-
"""MH reserved octets rebuild as captured.

GitHub issue #1437, part A: every reserved field of the Mobility Header that a
:class:`~pcapkit.corekit.fields.strings.PaddingField` holds -- in a message
body, an option, a Flow Identification sub-option, an ANI sub-option or a QoS
attribute -- was dropped by its reader, so a rebuild wrote zeros: Home Test Init
reserved ``aabb`` came back as ``0000``. The field packs the octets it is given
(#1436), and the readers keep them on the data model (``msg_reserved`` on a
message, ``reserved`` elsewhere) and the makers write them back. A fresh build
writes zeros.

Each case is one Mobility Header carrying the site under test, with its
reserved octets set to ``aa``, ``aabb`` or ``aabbcc``; a fresh build writes the
same header with them zeroed. Messages travel bare; options travel in a Binding
Refresh Request; sub-options and attributes travel in their container option.
Every case builds its own octets in memory and reads no capture. :class:`MH` is
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import unittest

from tests._support import reimport_once_per_class

#: ``(schema class, carrier, code name, captured octets)``, with the reserved field
#: in brackets. A fresh build writes the same octets with that field zeroed.
CASES = (
    ('ANICivicLocationSuboption', 'ani', 'Civic_Location',
     '3b010000000000003406040400[aa]0102'),
    ('AccessTechnologyTypeOption', 'opt', 'Access_Technology_Type_Option',
     '3b010000000000001802[aa]0101020000'),
    ('AllocationRetentionPriorityAttribute', 'qos', 'Allocation_Retention_Priority',
     '3b020000000000003a0a0000000000000502[aa]1001020000'),
    ('AnchoredPrefixOption', 'opt', 'Anchored_Prefix',
     '3b030000000000004112[aa]400000000000000000000000000000000001020000'),
    ('BindingErrorMessage', 'msg', 'Binding_Error',
     '3b020700000000[aa]00000000000000000000000000000000'),
    ('BitRateAttribute', 'qos', 'Per_MN_Agg_Max_DL_Bit_Rate',
     '3b020000000000003a0e0000000000000106[aabb]00000000'),
    ('CareofTestInitMessage', 'msg', 'Care_of_Test_Init',
     '3b0102000000[aabb]0000000000000000'),
    ('ContextRequestOption', 'opt', 'Context_Request_Option',
     '3b010000000000002802[aabb]01020000'),
    ('DLIFLinkLayerAddressOption', 'opt', 'DLIF_Link_Layer_Address',
     '3b010000000000004602[aabb]01020000'),
    ('FastNeighborAdvertisementMessage', 'msg', 'Fast_Neighbor_Advertisement',
     '3b000a000000[aabb]'),
    ('FlowBindingActionSuboption', 'fid', 'Flow_Binding_Action',
     '3b020000000000002d0a0001000100000402[aa]0b01020000'),
    ('FlowIdentificationOption', 'opt', 'Flow_Identification_Mobility_Option',
     '3b010000000000002d0600010001[aa]00'),
    ('GREKeyOption', 'opt', 'GRE_Key_Option',
     '3b010000000000002102[aabb]01020000'),
    ('HomeAgentSwitchMessage', 'msg', 'Home_Agent_Switch_Message',
     '3b000c00000000[aa]'),
    ('HomeNetworkPrefixOption', 'opt', 'Home_Network_Prefix_Option',
     '3b030000000000001612[aa]400000000000000000000000000000000001020000'),
    ('HomeTestInitMessage', 'msg', 'Home_Test_Init',
     '3b0101000000[aabb]0000000000000000'),
    ('IPv4CareofAddressOption', 'opt', 'IPv4_Care_of_Address',
     '3b010000000000002006[aabb]00000000'),
    ('IPv4DefaultRouterAddressOption', 'opt', 'IPv4_Default_Router_Address',
     '3b010000000000002606[aabb]00000000'),
    ('LMAAddressOption', 'opt', 'Local_Mobility_Anchor_Address_Option',
     '3b03000000000000291201[aa]0000000000000000000000000000000001020000'),
    ('LMAUserPlaneAddressOption', 'opt', 'LMA_User_Plane_Address',
     '3b010000000000003b02[aabb]01020000'),
    ('LocalPrefixOption', 'opt', 'Local_Prefix',
     '3b030000000000004212[aa]400000000000000000000000000000000001020000'),
    ('LocalizedRoutingInitiationMessage', 'msg', 'Localized_Routing_Initiation',
     '3b01110000000000[aabb]000001020000'),
    ('MAGIPv6AddressOption', 'opt', 'MAG_IPv6_Address',
     '3b030000000000003312[aa]800000000000000000000000000000000001020000'),
    ('MAGIdentifierOption', 'opt', 'MAG_Identifier',
     '3b01000000000000400201[aa]01020000'),
    ('MNGroupIdentifierOption', 'opt', 'Mobile_Node_Group_Identifier',
     '3b01000000000000320601[aa]00000001'),
    ('MNLLAIIDOption', 'opt', 'Mobile_Node_Link_local_Address_Interface_Identifier_Option',
     '3b020000000000002a0a[aabb]000000000000000001020000'),
    ('MNLLIdentifierOption', 'opt', 'Mobile_Node_Link_layer_Identifier_Option',
     '3b010000000000001902[aabb]01020000'),
    ('MobileNetworkPrefixOption', 'opt', 'Mobile_Network_Prefix_Option',
     '3b030000000000000612[aa]000000000000000000000000000000000001020000'),
    ('MulticastMobilityOption', 'opt', 'Multicast_Mobility_Option',
     '3b010000000000003c0002[aa]01020000'),
    ('PreviousMAAROption', 'opt', 'Previous_MAAR',
     '3b050000000000004322[aa]4000000000000000000000000000000000'
     '0000000000000000000000000000000001020000'),
    ('QoSTrafficSelectorAttribute', 'qos', 'QoS_Traffic_Selector',
     '3b020000000000003a0a0000000000000a02[aa]0201020000'),
    ('QoSVendorSpecificAttribute', 'qos', 'QoS_Vendor_Specific_Attribute',
     '3b030000000000003a0f0000000000000b07[aabb]000000000001050000000000'),
    ('QualityOfServiceOption', 'opt', 'Quality_of_Service',
     '3b010000000000003a06000000[aabbcc]'),
    ('RedirectCapabilityOption', 'opt', 'Redirect_Capability_Mobility_Option',
     '3b010000000000002e02[aabb]01020000'),
    ('SubscriptionQueryMessage', 'msg', 'Subscription_Query',
     '3b001600000000[aa]'),
    ('TargetCareofAddressSuboption', 'fid', 'Target_Care_of_Address',
     '3b040000000000002d1a0001000100000512[aabb]0000000000000000000000000000000001020000'),
    ('TrafficSelectorSuboption', 'fid', 'Traffic_Selector',
     '3b020000000000002d0a000100010000030202[aa]01020000'),
    ('UpdateNotificationAcknowledgementMessage', 'msg', 'Update_Notification_Acknowledgement',
     '3b0114000000000000[aabbcc]01020000'),)

#: Where the code name of each carrier is looked up.
ENUMS = {
    'msg': ('pcapkit.const.mh.packet', 'Packet'),
    'opt': ('pcapkit.const.mh.option', 'Option'),
    'fid': ('pcapkit.const.mh.flow_id_suboption', 'FlowIDSuboption'),
    'ani': ('pcapkit.const.mh.ani_suboption', 'ANISuboption'),
    'qos': ('pcapkit.const.mh.qos_attribute', 'QoSAttribute'),
}


def octets(captured: 'str') -> 'tuple[bytes, bytes]':
    """A case's captured octets, and a fresh build's with the bracketed field zeroed."""
    head, rest = captured.split('[')
    reserved, tail = rest.split(']')
    return bytes.fromhex(head + reserved + tail), bytes.fromhex(head + '00' * (len(reserved) // 2) + tail)


class TestMHReservedPadding(unittest.TestCase):
    """Pin the wire form of every MH ``PaddingField`` reserved site."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def fresh(carrier: 'str', name: 'str') -> 'bytes':
        """Build the case's header from keyword arguments alone."""
        import importlib

        from pcapkit.const.mh.option import Option
        from pcapkit.const.mh.packet import Packet
        from pcapkit.protocols.internet.mh.protocol import MH

        module, enum = ENUMS[carrier]
        code = getattr(getattr(importlib.import_module(module), enum), name)
        base = {'next': 59, 'checksum': b'\x00\x00', 'payload': b''}
        if carrier == 'msg':
            return bytes(MH.from_fields(type=code, data={}, **base))
        if carrier == 'opt':
            option = (code, {})
        elif carrier == 'fid':
            option = (Option.Flow_Identification_Mobility_Option, {'suboptions': [(code, {})]})
        elif carrier == 'qos':
            option = (Option.Quality_of_Service, {'attributes': [(code, {})]})
        else:
            option = (Option.Access_Network_Identifier,
                      {'suboptions': [(code, {'location': b'\x01\x02'})]})
        return bytes(MH.from_fields(type=Packet.Binding_Refresh_Request, data={'options': [option]}, **base))

    def test_reserved_octets_rebuild_as_captured(self) -> None:
        from pcapkit.protocols.internet.mh.protocol import MH

        for site, _, _, captured in CASES:
            raw, zero = octets(captured)
            with self.subTest(site=site):
                self.assertNotEqual(raw, zero)
                parsed = MH(io.BytesIO(raw), len(raw), extension=True).info
                rebuilt = bytes(MH.from_fields(next=parsed.next, type=parsed.type, checksum=parsed.chksum,
                                               data=parsed, payload=b''))
                self.assertEqual(rebuilt.hex(), raw.hex())

    def test_fresh_build_writes_zeros(self) -> None:
        from pcapkit.protocols.internet.mh.protocol import MH

        for site, carrier, name, captured in CASES:
            _, zero = octets(captured)
            with self.subTest(site=site):
                self.assertEqual(self.fresh(carrier, name).hex(), zero.hex())
                parsed = MH(io.BytesIO(zero), len(zero), extension=True).info
                rebuilt = bytes(MH.from_fields(next=parsed.next, type=parsed.type, checksum=parsed.chksum,
                                               data=parsed, payload=b''))
                self.assertEqual(rebuilt.hex(), zero.hex())

    def test_every_padding_site_has_a_case(self) -> None:
        from pcapkit.corekit.fields.strings import PaddingField
        from pcapkit.protocols.internet.mh import schema

        # ``PadOption`` and ``PadFlowIdentificationSuboption`` carry padding
        # rather than a reserved field, and are pinned by
        # ``test_mh_padn_contents_unit``.
        sites = {
            name for name, cls in vars(schema).items()
            if isinstance(cls, type) and cls.__module__ == schema.__name__
            and any(isinstance(field, PaddingField) for field in getattr(cls, '__fields__', {}).values())
        } - {'PadOption', 'PadFlowIdentificationSuboption'}
        self.assertEqual(sites, {case[0] for case in CASES})

    def test_data_model_keeps_the_octets(self) -> None:
        from pcapkit.protocols.internet.mh.protocol import MH

        captured = {case[0]: octets(case[3])[0] for case in CASES}
        hoti = captured['HomeTestInitMessage']
        info = MH(io.BytesIO(hoti), len(hoti), extension=True).info
        self.assertEqual(info.msg_reserved, b'\xaa\xbb')
        self.assertEqual(info.reserved, 0)  # the fixed header's own octet

        gre = captured['GREKeyOption']
        option = next(iter(MH(io.BytesIO(gre), len(gre), extension=True).info.options.values()))
        self.assertEqual(option.reserved, b'\xaa\xbb')

    def test_maker_takes_reserved_keyword(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh.protocol import MH

        proto = object.__new__(MH)
        self.assertEqual(bytes(proto._make_msg_hoti(msg_reserved=b'\xaa\xbb').pack())[:2], b'\xaa\xbb')
        self.assertEqual(bytes(proto._make_opt_gre(Option.GRE_Key_Option, reserved=b'\xaa\xbb').pack()).hex(),
                         '2102aabb')


if __name__ == '__main__':
    unittest.main()
