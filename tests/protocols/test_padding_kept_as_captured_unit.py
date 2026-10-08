# -*- coding: utf-8 -*-
"""Padding and reserved octets held by a ``PaddingField`` rebuild as captured.

GitHub issue #1223. :class:`~pcapkit.corekit.fields.strings.PaddingField` packed
zeros whatever it had read, so non-zero padding or reserved octets parsed
silently and came back zeroed. The field now packs the octets it was given,
and zeros when it has none, which is still what a freshly built packet writes.
Each protocol below carries the octets through its reader, data model and
``make()``; the HIP and SCTP trailing alignment padding is kept on the data
model only when it is not all zeros.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import unittest

from tests._support import reimport_once_per_class

#: An IPv6 address, for the routing headers.
ADDR = '20010db8000000000000000000000001'

#: ``(module, class, extension)`` -> wire octets that must rebuild unchanged.
FRAMES = {
    'HOPOPT PadN data': ('internet.hopopt', 'HOPOPT', True, '3b000104aabbccdd'),
    'IPv6-Opts PadN data': ('internet.ipv6_opts', 'IPv6_Opts', True, '3b000104aabbccdd'),
    'HOPOPT QS report Not Used octet': ('internet.hopopt', 'HOPOPT', True,
                                        '3b01' '260680aa00000000' '010400000000'),
    'IPv6-Opts QS report Not Used octet': ('internet.ipv6_opts', 'IPv6_Opts', True,
                                           '3b01' '260680aa00000000' '010400000000'),
    'IPv6-Frag reserved octet': ('internet.ipv6_frag', 'IPv6_Frag', True, '3baa000000000001'),
    'IPv6-Route Source Route reserved': ('internet.ipv6_route', 'IPv6_Route', True,
                                         '3b020001aabbccdd' + ADDR),
    'IPv6-Route Type 2 reserved': ('internet.ipv6_route', 'IPv6_Route', True,
                                   '3b020201aabbccdd' + ADDR),
    # CmprI 15, CmprE 15, Pad 7: one 1-octet address then 7 pad octets
    'IPv6-Route RPL padding': ('internet.ipv6_route', 'IPv6_Route', True,
                               '3b010301ff700000' '01eeeeeeeeeeeeee'),
    'HTTP/2 DATA padding': ('application.httpv2', 'HTTP', False, '00000600080000000102616263eeff'),
    'HTTP/2 HEADERS padding': ('application.httpv2', 'HTTP', False, '0000040108000000010282eeff'),
    'HTTP/2 PUSH_PROMISE padding': ('application.httpv2', 'HTTP', False,
                                    '000008050800000001020000000282eeff'),
    'OSPF cryptographic authentication reserved': (
        'application.ospf', 'OSPF', False,
        '0201002c' 'c0a8000100000000' '0000' '0002' 'aabb011000000007'
        'ffffff00000a020100000028c0a8000100000000' + '00' * 16),
    'TCP octets after EOOL': ('transport.tcp', 'TCP', False,
                              '0050005000000001000000007002ffff00000000' '020405b400aabbcc'),
    'SCTP DATA chunk padding': ('transport.sctp', 'SCTP', False,
                                '138813891122334400000000' '00030011' '00000001' '0000' '0000'
                                '00000000' '61ffffff'),
    'SCTP parameter padding': ('transport.sctp', 'SCTP', False,
                               '138813891122334400000000' '0100001b' '00000001' '0000ffff'
                               '00010001' '00000001' '80010007616263ee'),
    'SCTP error cause padding': ('transport.sctp', 'SCTP', False,
                                 '138813891122334400000000' '06000009' '00ff0005aaeeeeee'),
}

#: HIP parameters whose reserved octets are ``ff`` (the 12 sites listed on
#: #1223), and one whose trailing padding is not zero.
HIP_PARAMS = {
    'R1_COUNTER': '0081000cffffffff00000000aabbccdd',
    'NAT_TRAVERSAL_MODE': '02600002ffff0000',
    'ENCRYPTED': '02810004ffffffff',
    'NOTIFICATION': '03400004ffff4000',
    'REG_FROM': '03b60014000011ff' + '00' * 16,
    'ESP_TRANSFORM': '0fff0002ffff0000',
    'PAYLOAD_MIC': '11e1000811ffffff0000000000000000',
    'ROUTE_DST': '11f900140000ffff' + ADDR,
    'RELAY_FROM': 'f9fe0014000011ff' + '00' * 16,
    'RELAY_TO': 'fa020014000011ff' + '00' * 16,
    'OVERLAY_TTL': 'fa0b00040000ffff',
    'ROUTE_VIA': 'fa1100140000ffff' + ADDR,
    'NOTIFICATION trailing padding': '03400005000040006100000000eeeeee',
}


def hip_packet(param: 'str') -> 'bytes':
    """A HIP packet (next header 59, HIPv2 I1) carrying one parameter."""
    body = bytes.fromhex(param)
    length = (40 + len(body)) // 8 - 1
    return bytes([0x3b, length, 0x01, 0x21]) + bytes(36) + body


class TestPaddingKeptAsCaptured(unittest.TestCase):
    """Pin the wire form of padding and reserved octets across rebuilds."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_padding_field_packs_what_it_was_given(self) -> None:
        from pcapkit.corekit.fields.strings import PaddingField
        from pcapkit.protocols.schema.schema import Schema, schema_final

        @schema_final
        class Padded(Schema):
            pad: 'bytes' = PaddingField(length=3)

        self.assertEqual(bytes(Padded.unpack(b'\xaa\xbb\xcc')), b'\xaa\xbb\xcc')
        self.assertEqual(bytes(Padded()), bytes(3))
        self.assertEqual(bytes(Padded(pad=b'\x01\x02\x03')), b'\x01\x02\x03')
        # a value of another width is zero-filled or truncated, as ``struct``'s
        # ``s`` format does; an absent or empty one packs as zeros
        self.assertEqual(bytes(Padded(pad=b'\x01')), b'\x01\x00\x00')
        self.assertEqual(bytes(Padded(pad=b'\x01\x02\x03\x04')), b'\x01\x02\x03')
        self.assertEqual(bytes(Padded(pad=b'')), bytes(3))
        self.assertEqual(PaddingField(length=2).pack(None, {}), bytes(2))

    def test_wrong_width_padding_is_zero_filled_or_truncated(self) -> None:
        """A ``ConditionalField``-wrapped padding keeps ``main``'s ``struct`` semantics."""
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTP
        from pcapkit.protocols.link.l2tpv2 import L2TPv2

        # the L2TPv2 ``padding`` contract: zero-filled or truncated to ``offset``
        # octets (bytes measured on ``main``)
        for padding, wire in ((b'\xaa', '0202000000000003aa00007878'),
                              (b'\xaa\xbb\xcc\xdd\xee', '0202000000000003aabbcc7878'),
                              (None, '02020000000000030000007878')):
            with self.subTest(l2tpv2=padding):
                self.assertEqual(L2TPv2(offset=3, padding=padding, payload=b'xx').data.hex(), wire)

        for padding, wire in ((b'\xaa', '0000050008000000010378aa0000'),
                              (b'\xaa\xbb\xcc\xdd', '0000050008000000010378aabbcc'),
                              (b'', '0000050008000000010378000000')):
            with self.subTest(http2=padding):
                frame = {'pad_len': 3, 'data': b'x', 'padding': padding}
                self.assertEqual(HTTP(type=Frame.DATA, sid=1, frame=frame).data.hex(), wire)

    def test_makers_tolerate_a_data_model_without_the_new_fields(self) -> None:
        """A stand-in lacking the new attributes rebuilds with zero padding."""
        from types import SimpleNamespace

        from pcapkit.const.ipv6.option import Option
        from pcapkit.protocols.internet.hopopt import HOPOPT

        proto = object.__new__(HOPOPT)
        opt = SimpleNamespace(type=Option.PadN, length=6)
        self.assertEqual(bytes(proto._make_opt_pad(Option.PadN, opt)).hex(), '010400000000')

    def test_from_data_rebuilds_byte_for_byte(self) -> None:
        import importlib

        for name, (module, cls_name, extension, wire) in FRAMES.items():
            with self.subTest(name):
                cls = getattr(importlib.import_module(f'pcapkit.protocols.{module}'), cls_name)
                raw = bytes.fromhex(wire)
                kwargs = {'extension': True} if extension else {}
                parsed = cls(io.BytesIO(raw), len(raw), **kwargs)
                self.assertEqual(bytes(cls.from_data(parsed.info).data).hex(), raw.hex())

    def test_hip_from_data_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.internet.hip import HIP

        for name, param in HIP_PARAMS.items():
            with self.subTest(name):
                raw = hip_packet(param)
                parsed = HIP(io.BytesIO(raw), len(raw), extension=True)
                self.assertEqual(bytes(HIP.from_data(parsed.info).data).hex(), raw.hex())

    def test_zero_padding_is_not_recorded(self) -> None:
        """HIP and SCTP alignment padding stays off the data model while zero."""
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.protocols.transport.sctp import SCTP

        raw = hip_packet('03400005000040006100000000000000')
        param = next(iter(HIP(io.BytesIO(raw), len(raw), extension=True).info.parameters.values()))
        self.assertNotIn('padding', param)
        raw = hip_packet(HIP_PARAMS['NOTIFICATION trailing padding'])
        param = next(iter(HIP(io.BytesIO(raw), len(raw), extension=True).info.parameters.values()))
        self.assertEqual(param.padding, b'\x00' * 4 + b'\xee' * 3)

        raw = bytes.fromhex(FRAMES['SCTP DATA chunk padding'][3])
        chunk = next(iter(SCTP(raw).info.chunks.values()))
        self.assertEqual(chunk.padding, b'\xff' * 3)
        chunk = next(iter(SCTP(raw[:-3] + bytes(3)).info.chunks.values()))
        self.assertNotIn('padding', chunk)

    def test_make_writes_zeros_by_default(self) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag

        proto = object.__new__(HOPOPT)
        self.assertEqual(bytes(proto._make_opt_pad(Option.PadN, length=4)).hex(), '010400000000')
        self.assertEqual(bytes(proto._make_opt_pad(Option.PadN, length=4, pad=b'\xaa' * 4)).hex(),
                         '0104aaaaaaaa')
        self.assertEqual(IPv6_Frag(next=59, id=1, extension=True).data.hex(), '3b00000000000001')
        self.assertEqual(IPv6_Frag(next=59, id=1, reserved_octet=b'\xaa', extension=True).data.hex(),
                         '3baa000000000001')

    def test_make_takes_the_hip_reserved_octets(self) -> None:
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.protocols.internet.hip import HIP

        base = {'next': 59, 'packet': 1, 'version': 2, 'checksum': b'\x00\x00',
                'controls_anonymous': False, 'shit': 0, 'rhit': 0, 'payload': b''}
        params = [(Parameter.NOTIFICATION, {})]
        self.assertEqual(HIP(parameters=params, extension=True, **base).data[44:46], b'\x00\x00')
        params = [(Parameter.NOTIFICATION, {'reserved': b'\xff\xff'})]
        self.assertEqual(HIP(parameters=params, extension=True, **base).data[44:46], b'\xff\xff')


if __name__ == '__main__':
    unittest.main()
