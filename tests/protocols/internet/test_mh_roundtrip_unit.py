# -*- coding: utf-8 -*-
"""MH zero-length ``PadN``, reserved fields and flag bits rebuild byte for byte.

GitHub issue #1324: a ``PadN`` whose ``Option Length`` is ``0`` -- two octets
of padding, which :rfc:`6275#section-6.2.3` allows -- was rejected on read and
rewritten as a ``Pad1`` on make.

GitHub issue #1329: the reserved octet of the fixed header, the Binding Refresh
Request reserved field, the Handoff Indicator reserved octet and the reserved
bits of the IPv4 Home Address option and the Network-Identifier ANI sub-option
were written back as zero, and so were the Binding Update and Binding
Acknowledgement flag bits other than ``A``/``H``/``L``/``K`` and ``K``, which
later RFCs assign (IANA *Binding Update Flags* and *Binding Acknowledgment
Flags*).

Non-zero ``PadN`` contents are #1223 and are not covered here.

Every case builds its own octets in memory and reads no capture. :class:`MH` is
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import unittest

from tests._support import reimport_once_per_class

#: Mobility Header octets, parsed as an IPv6 extension header (next header 59).
FRAMES = {
    # BRR carrying a PadN of Option Length 0, then a PadN of Option Length 4
    'padn-zero': '3b01000000000000' '0100' '010400000000',
    'header-reserved': '3b0000aa00000000',
    'brr-reserved': '3b0000000000aabb',
    # BU: seq 0, every flag bit set, lifetime 1, PadN of Option Length 2
    'bu-flags': '3b0105000000' '0000' 'ffff' '0001' '01020000',
    # BA: status 0, every flag bit set, seq 0, lifetime 1, PadN of Option Length 2
    'ba-flags': '3b0106000000' '00ff' '0000' '0001' '01020000',
    # BRR carrying a Handoff Indicator with reserved 0xaa, then a PadN
    'hi-reserved': '3b01000000000000' '1702aa01' '01020000',
    # BRR carrying an IPv4 Home Address: prefix 32, P set, reserved 0x155
    'ipv4-hoa-reserved': '3b01000000000000' '1d068355c0000201',
    # BRR carrying an ANI option whose Network-Identifier flags octet is 0xff
    'ani-reserved': '3b02000000000000' '3407' '0105ff0161' '0162' '01050000000000',
}


class TestMHRoundTrip(unittest.TestCase):
    """Pin the wire form of MH padding, reserved fields and flag bits."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _parse(octets: 'bytes') -> 'object':
        import io

        from pcapkit.protocols.internet.mh import MH

        return MH(io.BytesIO(octets), len(octets), extension=True)

    def test_from_data_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.internet.mh import MH

        for name, frame in FRAMES.items():
            with self.subTest(frame=name):
                octets = bytes.fromhex(frame)
                rebuilt = MH.from_data(self._parse(octets).info)  # type: ignore[attr-defined]
                self.assertEqual(bytes(rebuilt).hex(), octets.hex())

    def test_zero_length_padn_is_read_as_a_two_octet_padn(self) -> None:
        from pcapkit.const.mh.option import Option

        options = self._parse(bytes.fromhex(FRAMES['padn-zero'])).info.options  # type: ignore[attr-defined]
        pads = options.getlist(Option.PadN)
        self.assertEqual([pad.length for pad in pads], [2, 6])

    def test_make_keeps_a_zero_length_padn(self) -> None:
        import warnings

        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh import MH

        proto = object.__new__(MH)
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            pad = proto._make_opt_pad(Option.PadN, length=0)
        self.assertEqual(pad.type, Option.PadN)
        self.assertEqual(bytes(pad), b'\x01\x00')

    def test_reserved_fields_are_read(self) -> None:
        from pcapkit.const.mh.ani_suboption import ANISuboption
        from pcapkit.const.mh.option import Option

        self.assertEqual(self._parse(bytes.fromhex(FRAMES['header-reserved'])).info.reserved,  # type: ignore[attr-defined]
                         0xaa)
        self.assertEqual(self._parse(bytes.fromhex(FRAMES['brr-reserved'])).info.msg_reserved,  # type: ignore[attr-defined]
                         0xaabb)

        hi = self._parse(bytes.fromhex(FRAMES['hi-reserved'])).info.options[Option.Handoff_Indicator_Option]  # type: ignore[attr-defined]
        self.assertEqual(hi.reserved, 0xaa)

        hoa = self._parse(bytes.fromhex(FRAMES['ipv4-hoa-reserved'])).info.options[Option.IPv4_Home_Address]  # type: ignore[attr-defined]
        self.assertEqual((hoa.prefix_length, hoa.request_prefix, hoa.reserved), (32, True, 0x155))

        ani = self._parse(bytes.fromhex(FRAMES['ani-reserved'])).info.options[Option.Access_Network_Identifier]  # type: ignore[attr-defined]
        net = ani.suboptions[ANISuboption.Network_Identifier]
        self.assertEqual((net.utf8, net.reserved), (True, 0x7f))

    def test_binding_update_and_acknowledgement_flags_are_modelled(self) -> None:
        bu = self._parse(bytes.fromhex(FRAMES['bu-flags'])).info  # type: ignore[attr-defined]
        for name in ('ack', 'home', 'lla_compat', 'key_mngt', 'map_reg', 'mobile_router',
                     'proxy_reg', 'udp_encap', 'tlv_format', 'bulk_binding', 'multicast', 'dmm'):
            with self.subTest(message='BU', flag=name):
                self.assertIs(getattr(bu, name), True)
        self.assertEqual(bu.flags_reserved, 0xf)

        ba = self._parse(bytes.fromhex(FRAMES['ba-flags'])).info  # type: ignore[attr-defined]
        for name in ('key_mngt', 'mobile_router', 'proxy_reg', 'tlv_format', 'bulk_binding',
                     'multicast', 'dmm'):
            with self.subTest(message='BA', flag=name):
                self.assertIs(getattr(ba, name), True)
        self.assertEqual(ba.flags_reserved, 1)

    def test_fresh_make_places_each_flag_on_its_iana_bit(self) -> None:
        from pcapkit.const.mh.binding_ack_flag import BindingACKFlag
        from pcapkit.const.mh.binding_update_flag import BindingUpdateFlag
        from pcapkit.protocols.internet.mh import MH

        proto = object.__new__(MH)
        bu_flags = {'map_reg': BindingUpdateFlag.M, 'mobile_router': BindingUpdateFlag.R,
                    'proxy_reg': BindingUpdateFlag.P, 'udp_encap': BindingUpdateFlag.F,
                    'tlv_format': BindingUpdateFlag.T, 'bulk_binding': BindingUpdateFlag.B,
                    'multicast': BindingUpdateFlag.S, 'dmm': BindingUpdateFlag.D}
        for name, bit in bu_flags.items():
            with self.subTest(message='BU', flag=name):
                packed = bytes(proto._make_msg_bu(None, options=[], **{name: True}))
                self.assertEqual(int.from_bytes(packed[2:4], 'big'), int(bit))

        ba_flags = {'mobile_router': BindingACKFlag.R, 'proxy_reg': BindingACKFlag.P,
                    'tlv_format': BindingACKFlag.T, 'bulk_binding': BindingACKFlag.B,
                    'multicast': BindingACKFlag.S, 'dmm': BindingACKFlag.D}
        for name, bit in ba_flags.items():
            with self.subTest(message='BA', flag=name):
                packed = bytes(proto._make_msg_ba(None, options=[], **{name: True}))
                self.assertEqual(packed[1], int(bit))


if __name__ == '__main__':
    unittest.main()
