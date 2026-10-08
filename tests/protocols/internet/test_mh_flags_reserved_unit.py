# -*- coding: utf-8 -*-
"""MH flag words keep their reserved bits on rebuild.

GitHub issue #1418: 24 MH ``flags`` bit fields named only some of their bits,
and :class:`~pcapkit.corekit.fields.strings.BitField` packs an unnamed bit as
zero, so a message, option or sub-structure whose reserved bits were set came
back with them cleared. Each site now names a ``reserved`` sub-field, read into
the data model (``flags_reserved`` on a message, since :attr:`MH.reserved` is
the fixed-header octet, and ``reserved`` elsewhere) and written back by
``make()``, where it defaults to ``0``.

Every frame sets every reserved bit of its site and nothing else unusual. Each
case builds its own octets in memory and reads no capture. :class:`MH` is
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import unittest

from tests._support import reimport_once_per_class

#: ``site -> (Mobility Header octets, width of the reserved sub-field)``. The
#: options ride in a Binding Refresh Request; next header is 59 throughout.
FRAMES = {
    'BindingRevocationMessage': ('3b0110000000010000001fff01020000', 13),
    'FastBindingAcknowledgmentMessage': ('3b0109000000007f0000000401020000', 7),
    'FastBindingUpdateMessage': ('3b01080000000000cfff000401020000', 12),
    'FlowBindingMessage': ('3b011500000000010000017f01020000', 7),
    'HandoverAcknowledgeMessage': ('3b010f00000000001f00010400000000', 5),
    'HandoverInitiateMessage': ('3b010e00000000000f00010400000000', 4),
    'HeartbeatMessage': ('3b010d000000fffc0000000001020000', 14),
    'LocalizedRoutingAcknowledgmentMessage': ('3b011200000000007f00000001020000', 7),
    'SubscriptionResponseMessage': ('3b0017000000007f', 7),
    'UpdateNotificationMessage': ('3b0113000000000000013fff01020000', 14),
    'DNSUpdateOption': ('3b010000000000001102007f01020000', 7),
    'DelegatedMNPOption': ('3b010000000000003706ff18c0000200', 7),
    'DynamicIPMulticastSelectorOption': ('3b0100000000000036048f7f00000000', 7),
    'IPv4AddressAcknowledgementOption': ('3b010000000000001e06008300000000', 2),
    'IPv4DHCPSupportModeOption': ('3b010000000000002702fffe01020000', 15),
    'IPv4HomeAddressReplyOption': ('3b010000000000002506008300000000', 2),
    'IPv4HomeAddressRequestOption': ('3b01000000000000240683ff00000000', 10),
    'IPv4TrafficOffloadSelectorOption': ('3b0100000000000035047fffffff0000', 31),
    'MAGMultipathBindingOption': ('3b010000000000003f060100013fffff', 22),
    'NATDetectionOption': ('3b010000000000001f067fff00000000', 15),
    'RedirectOption': ('3b010000000000002f067fffc0000201', 14),
    'TransientBindingOption': ('3b010000000000002b02fe0001020000', 7),
    # CGA Parameters option carrying one CGA parameter with a Multi-Prefix extension
    'MultiPrefixExtension': ('3b060000000000000c2b086fca5e10b200c99c8ce00164277c08'
                             '0000000000000001013000' '0012000c7fffffff0000000000000001'
                             '010100', 31),
    # Quality-of-Service option carrying one per-session bit-rate attribute
    'PerSessionBitRateAttribute': ('3b020000000000003a0e00000000000003063fff000003e8', 14),
}

MESSAGES = {
    'BindingRevocationMessage': 'Binding_Revocation_Message',
    'FastBindingAcknowledgmentMessage': 'Fast_Binding_Acknowledgment',
    'FastBindingUpdateMessage': 'Fast_Binding_Update',
    'FlowBindingMessage': 'Flow_Binding_Message',
    'HandoverAcknowledgeMessage': 'Handover_Acknowledge_Message',
    'HandoverInitiateMessage': 'Handover_Initiate_Message',
    'HeartbeatMessage': 'Heartbeat_Message',
    'LocalizedRoutingAcknowledgmentMessage': 'Localized_Routing_Acknowledgment',
    'SubscriptionResponseMessage': 'Subscription_Response',
    'UpdateNotificationMessage': 'Update_Notification',
}

#: ``site -> (option name, extra make() arguments)``.
OPTIONS = {
    'DNSUpdateOption': ('DNS_UPDATE_TYPE', {}),
    'DelegatedMNPOption': ('Delegated_Mobile_Network_Prefix', {'prefix': '192.0.2.0', 'prefix_length': 24}),
    'DynamicIPMulticastSelectorOption': ('Dynamic_IP_Multicast_Selector', {}),
    'IPv4AddressAcknowledgementOption': ('IPv4_Address_Acknowledgement', {}),
    'IPv4DHCPSupportModeOption': ('IPv4_DHCP_Support_Mode', {}),
    'IPv4HomeAddressReplyOption': ('IPv4_Home_Address_Reply', {}),
    'IPv4HomeAddressRequestOption': ('IPv4_Home_Address_Request', {}),
    'IPv4TrafficOffloadSelectorOption': ('IPv4_Traffic_Offload_Selector', {}),
    'MAGMultipathBindingOption': ('MAG_Multipath_Binding', {}),
    'NATDetectionOption': ('NAT_Detection', {}),
    'RedirectOption': ('Redirect_Mobility_Option', {'ipv4': '192.0.2.1'}),
    'TransientBindingOption': ('Transient_Binding', {}),
}


class TestMHFlagsReserved(unittest.TestCase):
    """Pin the reserved bits of every MH ``flags`` bit field."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _parse(octets: 'bytes') -> 'object':
        import io

        from pcapkit.protocols.internet.mh import MH

        return MH(io.BytesIO(octets), len(octets), extension=True)

    @staticmethod
    def _site(info: 'object', site: 'str') -> 'tuple[object, str]':
        """Return the data model holding the site's reserved bits and its name."""
        from pcapkit.const.mh.cga_extension import CGAExtension
        from pcapkit.const.mh.option import Option
        from pcapkit.const.mh.qos_attribute import QoSAttribute

        if site in MESSAGES:
            return info, 'flags_reserved'
        if site in OPTIONS:
            return info.options[Option[OPTIONS[site][0]]], 'reserved'  # type: ignore[attr-defined]
        if site == 'MultiPrefixExtension':
            param = info.options[Option.CGA_Parameters].parameters[0]  # type: ignore[attr-defined]
            return param.extensions[CGAExtension.Multi_Prefix], 'reserved'
        qos = info.options[Option.Quality_of_Service]  # type: ignore[attr-defined]
        return qos.attributes[QoSAttribute.Per_Session_Agg_Max_DL_Bit_Rate], 'reserved'

    @staticmethod
    def _make(site: 'str', **reserved: 'int') -> 'bytes':
        """Build the site through ``make()``, passing ``reserved`` through."""
        from pcapkit.const.mh.cga_extension import CGAExtension
        from pcapkit.const.mh.cga_type import CGAType
        from pcapkit.const.mh.option import Option
        from pcapkit.const.mh.packet import Packet
        from pcapkit.const.mh.qos_attribute import QoSAttribute
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.data.internet.mh import CGAParameter
        from pcapkit.protocols.internet.mh import MH

        if site in MESSAGES:
            data = {'flags_reserved': reserved['value']} if reserved else {}
            return bytes(MH(next=TransType.IPv6_NoNxt, type=Packet[MESSAGES[site]], data=data))

        args = {'reserved': reserved['value']} if reserved else {}
        if site in OPTIONS:
            name, extra = OPTIONS[site]
            option = (Option[name], dict(extra, **args))
        elif site == 'MultiPrefixExtension':
            param = CGAParameter(modifier=CGAType.Tag_086F_CA5E_10B2_00C9_9C8C_E001_6427_7C08,
                                 prefix=1, collision_count=1, public_key=b'\x30\x00',
                                 extensions=[(CGAExtension.Multi_Prefix, dict(args, prefixes=[1]))])
            option = (Option.CGA_Parameters, {'parameters': [param]})
        else:
            option = (Option.Quality_of_Service, {'attributes': [
                (QoSAttribute.Per_Session_Agg_Max_DL_Bit_Rate, dict(args, rate=1000))]})
        return bytes(MH(next=TransType.IPv6_NoNxt, type=Packet.Binding_Refresh_Request,
                        data={'options': [option]}))

    def test_every_site_is_covered(self) -> None:
        self.assertEqual(len(FRAMES), 24)
        self.assertEqual(set(FRAMES), set(MESSAGES) | set(OPTIONS)
                         | {'MultiPrefixExtension', 'PerSessionBitRateAttribute'})

    def test_reserved_bits_are_read(self) -> None:
        for site, (frame, width) in FRAMES.items():
            with self.subTest(site=site):
                model, attr = self._site(self._parse(bytes.fromhex(frame)).info, site)  # type: ignore[attr-defined]
                self.assertEqual(type(model).__name__, site)
                self.assertEqual(getattr(model, attr), (1 << width) - 1)

    def test_from_data_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.internet.mh import MH

        for site, (frame, _) in FRAMES.items():
            with self.subTest(site=site):
                octets = bytes.fromhex(frame)
                rebuilt = MH.from_data(self._parse(octets).info)  # type: ignore[attr-defined]
                self.assertEqual(bytes(rebuilt).hex(), octets.hex())

    def test_make_writes_the_reserved_bits(self) -> None:
        for site, (frame, width) in FRAMES.items():
            with self.subTest(site=site):
                built = self._make(site, value=(1 << width) - 1)
                self.assertEqual(built.hex(), frame)
                model, attr = self._site(self._parse(built).info, site)  # type: ignore[attr-defined]
                self.assertEqual(getattr(model, attr), (1 << width) - 1)

    def test_make_defaults_the_reserved_bits_to_zero(self) -> None:
        for site in FRAMES:
            with self.subTest(site=site):
                model, attr = self._site(self._parse(self._make(site)).info, site)  # type: ignore[attr-defined]
                self.assertEqual(getattr(model, attr), 0)

    def test_make_rejects_a_value_wider_than_the_reserved_bits(self) -> None:
        from pcapkit.utilities.exceptions import FieldValueError

        for site, (_, width) in FRAMES.items():
            with self.subTest(site=site):
                with self.assertRaisesRegex(FieldValueError, r"subfield 'reserved' value \d+ needs"):
                    self._make(site, value=1 << width)


if __name__ == '__main__':
    unittest.main()
