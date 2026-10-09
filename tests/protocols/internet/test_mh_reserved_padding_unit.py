# -*- coding: utf-8 -*-
"""MH reserved octets rebuild as captured.

GitHub issue #1437, part A: every reserved field of the Mobility Header that a
:class:`~pcapkit.corekit.fields.strings.PaddingField` holds -- in a message
body, an option, a Flow Identification sub-option, an ANI sub-option or a QoS
attribute -- was dropped by its reader, so a rebuild wrote zeros: Home Test Init
reserved ``aabb`` came back as ``0000``. #1436 made the field pack the octets it
is given; the readers now keep them on the data model (``msg_reserved`` on a
message, ``reserved`` elsewhere) and the makers write them back. A fresh build
still writes zeros.

Each case is one Mobility Header carrying the site under test, with its
reserved octets set to ``aa``, ``aabb`` or ``aabbcc``, next to the same header
as a fresh build writes it. Messages travel bare; options travel in a Binding
Refresh Request; sub-options and attributes travel in their container option.
Every case builds its own octets in memory and reads no capture. :class:`MH` is
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import unittest

from tests._support import reimport_once_per_class

#: ``(schema class, carrier, code name, captured octets, fresh-build octets)``.
#: The two octet strings differ only in the reserved field.
CASES = (
    ('ANICivicLocationSuboption', 'ani', 'Civic_Location',
     '3b010000000000003406040400aa0102',
     '3b010000000000003406040400000102'),
    ('AccessTechnologyTypeOption', 'opt', 'Access_Technology_Type_Option',
     '3b010000000000001802aa0101020000',
     '3b010000000000001802000101020000'),
    ('AllocationRetentionPriorityAttribute', 'qos', 'Allocation_Retention_Priority',
     '3b020000000000003a0a0000000000000502aa1001020000',
     '3b020000000000003a0a0000000000000502001001020000'),
    ('AnchoredPrefixOption', 'opt', 'Anchored_Prefix',
     '3b030000000000004112aa400000000000000000000000000000000001020000',
     '3b03000000000000411200400000000000000000000000000000000001020000'),
    ('BindingErrorMessage', 'msg', 'Binding_Error',
     '3b020700000000aa00000000000000000000000000000000',
     '3b0207000000000000000000000000000000000000000000'),
    ('BitRateAttribute', 'qos', 'Per_MN_Agg_Max_DL_Bit_Rate',
     '3b020000000000003a0e0000000000000106aabb00000000',
     '3b020000000000003a0e0000000000000106000000000000'),
    ('CareofTestInitMessage', 'msg', 'Care_of_Test_Init',
     '3b0102000000aabb0000000000000000',
     '3b010200000000000000000000000000'),
    ('ContextRequestOption', 'opt', 'Context_Request_Option',
     '3b010000000000002802aabb01020000',
     '3b010000000000002802000001020000'),
    ('DLIFLinkLayerAddressOption', 'opt', 'DLIF_Link_Layer_Address',
     '3b010000000000004602aabb01020000',
     '3b010000000000004602000001020000'),
    ('FastNeighborAdvertisementMessage', 'msg', 'Fast_Neighbor_Advertisement',
     '3b000a000000aabb',
     '3b000a0000000000'),
    ('FlowBindingActionSuboption', 'fid', 'Flow_Binding_Action',
     '3b020000000000002d0a0001000100000402aa0b01020000',
     '3b020000000000002d0a0001000100000402000b01020000'),
    ('FlowIdentificationOption', 'opt', 'Flow_Identification_Mobility_Option',
     '3b010000000000002d0600010001aa00',
     '3b010000000000002d06000100010000'),
    ('GREKeyOption', 'opt', 'GRE_Key_Option',
     '3b010000000000002102aabb01020000',
     '3b010000000000002102000001020000'),
    ('HomeAgentSwitchMessage', 'msg', 'Home_Agent_Switch_Message',
     '3b000c00000000aa',
     '3b000c0000000000'),
    ('HomeNetworkPrefixOption', 'opt', 'Home_Network_Prefix_Option',
     '3b030000000000001612aa400000000000000000000000000000000001020000',
     '3b03000000000000161200400000000000000000000000000000000001020000'),
    ('HomeTestInitMessage', 'msg', 'Home_Test_Init',
     '3b0101000000aabb0000000000000000',
     '3b010100000000000000000000000000'),
    ('IPv4CareofAddressOption', 'opt', 'IPv4_Care_of_Address',
     '3b010000000000002006aabb00000000',
     '3b010000000000002006000000000000'),
    ('IPv4DefaultRouterAddressOption', 'opt', 'IPv4_Default_Router_Address',
     '3b010000000000002606aabb00000000',
     '3b010000000000002606000000000000'),
    ('LMAAddressOption', 'opt', 'Local_Mobility_Anchor_Address_Option',
     '3b03000000000000291201aa0000000000000000000000000000000001020000',
     '3b03000000000000291201000000000000000000000000000000000001020000'),
    ('LMAUserPlaneAddressOption', 'opt', 'LMA_User_Plane_Address',
     '3b010000000000003b02aabb01020000',
     '3b010000000000003b02000001020000'),
    ('LocalPrefixOption', 'opt', 'Local_Prefix',
     '3b030000000000004212aa400000000000000000000000000000000001020000',
     '3b03000000000000421200400000000000000000000000000000000001020000'),
    ('LocalizedRoutingInitiationMessage', 'msg', 'Localized_Routing_Initiation',
     '3b01110000000000aabb000001020000',
     '3b011100000000000000000001020000'),
    ('MAGIPv6AddressOption', 'opt', 'MAG_IPv6_Address',
     '3b030000000000003312aa800000000000000000000000000000000001020000',
     '3b03000000000000331200800000000000000000000000000000000001020000'),
    ('MAGIdentifierOption', 'opt', 'MAG_Identifier',
     '3b01000000000000400201aa01020000',
     '3b010000000000004002010001020000'),
    ('MNGroupIdentifierOption', 'opt', 'Mobile_Node_Group_Identifier',
     '3b01000000000000320601aa00000001',
     '3b010000000000003206010000000001'),
    ('MNLLAIIDOption', 'opt', 'Mobile_Node_Link_local_Address_Interface_Identifier_Option',
     '3b020000000000002a0aaabb000000000000000001020000',
     '3b020000000000002a0a0000000000000000000001020000'),
    ('MNLLIdentifierOption', 'opt', 'Mobile_Node_Link_layer_Identifier_Option',
     '3b010000000000001902aabb01020000',
     '3b010000000000001902000001020000'),
    ('MobileNetworkPrefixOption', 'opt', 'Mobile_Network_Prefix_Option',
     '3b030000000000000612aa000000000000000000000000000000000001020000',
     '3b03000000000000061200000000000000000000000000000000000001020000'),
    ('MulticastMobilityOption', 'opt', 'Multicast_Mobility_Option',
     '3b010000000000003c0002aa01020000',
     '3b010000000000003c00020001020000'),
    ('PreviousMAAROption', 'opt', 'Previous_MAAR',
     '3b050000000000004322aa4000000000000000000000000000000000'
     '0000000000000000000000000000000001020000',
     '3b05000000000000432200400000000000000000000000000000000000'
     '00000000000000000000000000000001020000'),
    ('QoSTrafficSelectorAttribute', 'qos', 'QoS_Traffic_Selector',
     '3b020000000000003a0a0000000000000a02aa0201020000',
     '3b020000000000003a0a0000000000000a02000201020000'),
    ('QoSVendorSpecificAttribute', 'qos', 'QoS_Vendor_Specific_Attribute',
     '3b030000000000003a0f0000000000000b07aabb000000000001050000000000',
     '3b030000000000003a0f0000000000000b070000000000000001050000000000'),
    ('QualityOfServiceOption', 'opt', 'Quality_of_Service',
     '3b010000000000003a06000000aabbcc',
     '3b010000000000003a06000000000000'),
    ('RedirectCapabilityOption', 'opt', 'Redirect_Capability_Mobility_Option',
     '3b010000000000002e02aabb01020000',
     '3b010000000000002e02000001020000'),
    ('SubscriptionQueryMessage', 'msg', 'Subscription_Query',
     '3b001600000000aa',
     '3b00160000000000'),
    ('TargetCareofAddressSuboption', 'fid', 'Target_Care_of_Address',
     '3b040000000000002d1a0001000100000512aabb0000000000000000000000000000000001020000',
     '3b040000000000002d1a000100010000051200000000000000000000000000000000000001020000'),
    ('TrafficSelectorSuboption', 'fid', 'Traffic_Selector',
     '3b020000000000002d0a000100010000030202aa01020000',
     '3b020000000000002d0a0001000100000302020001020000'),
    ('UpdateNotificationAcknowledgementMessage', 'msg', 'Update_Notification_Acknowledgement',
     '3b0114000000000000aabbcc01020000',
     '3b011400000000000000000001020000'),)

#: Where the code name of each carrier is looked up.
ENUMS = {
    'msg': ('pcapkit.const.mh.packet', 'Packet'),
    'opt': ('pcapkit.const.mh.option', 'Option'),
    'fid': ('pcapkit.const.mh.flow_id_suboption', 'FlowIDSuboption'),
    'ani': ('pcapkit.const.mh.ani_suboption', 'ANISuboption'),
    'qos': ('pcapkit.const.mh.qos_attribute', 'QoSAttribute'),
}


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
        from pcapkit.protocols.internet.mh import MH

        module, enum = ENUMS[carrier]
        code = getattr(getattr(importlib.import_module(module), enum), name)
        base = {'next': 59, 'chksum': b'\x00\x00', 'payload': b''}
        if carrier == 'msg':
            return bytes(MH(type=code, data={}, **base))
        if carrier == 'opt':
            option = (code, {})
        elif carrier == 'fid':
            option = (Option.Flow_Identification_Mobility_Option, {'suboptions': [(code, {})]})
        elif carrier == 'qos':
            option = (Option.Quality_of_Service, {'attributes': [(code, {})]})
        else:
            option = (Option.Access_Network_Identifier,
                      {'suboptions': [(code, {'location': b'\x01\x02'})]})
        return bytes(MH(type=Packet.Binding_Refresh_Request, data={'options': [option]}, **base))

    def test_reserved_octets_rebuild_as_captured(self) -> None:
        from pcapkit.protocols.internet.mh import MH

        for site, _, _, raw_hex, zero_hex in CASES:
            raw = bytes.fromhex(raw_hex)
            with self.subTest(site=site):
                self.assertNotEqual(raw_hex, zero_hex)
                parsed = MH(io.BytesIO(raw), len(raw), extension=True).info
                rebuilt = bytes(MH(next=parsed.next, type=parsed.type, chksum=parsed.chksum,
                                   data=parsed, payload=b''))
                self.assertEqual(rebuilt.hex(), raw_hex)

    def test_fresh_build_writes_zeros(self) -> None:
        from pcapkit.protocols.internet.mh import MH

        for site, carrier, name, _, zero_hex in CASES:
            with self.subTest(site=site):
                self.assertEqual(self.fresh(carrier, name).hex(), zero_hex)
                zero = bytes.fromhex(zero_hex)
                parsed = MH(io.BytesIO(zero), len(zero), extension=True).info
                rebuilt = bytes(MH(next=parsed.next, type=parsed.type, chksum=parsed.chksum,
                                   data=parsed, payload=b''))
                self.assertEqual(rebuilt.hex(), zero_hex)

    def test_every_padding_site_has_a_case(self) -> None:
        from pcapkit.corekit.fields.strings import PaddingField
        from pcapkit.protocols.schema.internet import mh as schema

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
        from pcapkit.protocols.internet.mh import MH

        hoti = bytes.fromhex(dict((case[0], case[3]) for case in CASES)['HomeTestInitMessage'])
        info = MH(io.BytesIO(hoti), len(hoti), extension=True).info
        self.assertEqual(info.msg_reserved, b'\xaa\xbb')
        self.assertEqual(info.reserved, 0)  # the fixed header's own octet

        gre = bytes.fromhex(dict((case[0], case[3]) for case in CASES)['GREKeyOption'])
        option = next(iter(MH(io.BytesIO(gre), len(gre), extension=True).info.options.values()))
        self.assertEqual(option.reserved, b'\xaa\xbb')

    def test_maker_takes_reserved_keyword(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh import MH

        proto = object.__new__(MH)
        self.assertEqual(bytes(proto._make_msg_hoti(msg_reserved=b'\xaa\xbb').pack())[:2], b'\xaa\xbb')
        self.assertEqual(bytes(proto._make_opt_gre(Option.GRE_Key_Option, reserved=b'\xaa\xbb').pack()).hex(),
                         '2102aabb')


if __name__ == '__main__':
    unittest.main()
