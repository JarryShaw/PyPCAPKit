# -*- coding: utf-8 -*-
"""GitHub issue #2576: radiotap's optional fields, decoded.

:class:`~pcapkit.protocols.link.radiotap.Radiotap` decodes the field-data
region into ``decoded`` per the radiotap.org field pages: each field's
alignment, size and subfields, the namespace fields, extended presence words
and the TLV list. Unknown and vendor fields stay raw, ``fields`` keeps the
region as captured, and both round trips are byte-exact.

The vectors come from three places:

* hand-built from radiotap.org's field pages, with each expected value
  worked out by hand;
* the ``check/`` vectors of radiotap.org's own parser library,
  https://github.com/radiotap/radiotap-library at
  ``c21ba1e6fc6cc7723bd02faf000dd6d3d345abfa``, each pinned to what that
  library's ``.out`` file prints for it;
* records of tcpdump's test captures ``ieee802.11_exthdr.pcap``,
  ``ieee802.11_rx-stbc.pcap`` and ``ieee802.11_htc.pcap``,
  https://github.com/the-tcpdump-group/tcpdump at
  ``f34cf40526e1f6326138fedba2a606d1c2f089f3``, each pinned to what tcpdump's
  ``.out`` file prints for it.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`.

"""

import struct
import unittest

from tests._support import reimport_once_per_class

#: An 802.11 Ack frame to ``01:01:01:01:01:01``, with a 4-octet FCS.
ACK = bytes.fromhex('d4000000') + b'\x01' * 6 + b'\x11\x22\x33\x44'

#: radiotap-library's ``check/*.bin`` vectors, by file name.
RTLIB = {
    '0': '00001000010000001122334455667788',
    '00': '00002000010000a001000000000000001122334455667788aabbccddeeff0011',
    '0fcs': '00001400014000001122334455667788aabbccdd',
    '0v0': '00003000010000c0010000a0010000001122334455667788000000000400ffeeddcc000000000000'
           'aabbccddeeff0011',
    '0v0-2': '00003000010000c0020000a0010000001122334455667788000000000400ffeeddcc000000000000'
             'aabbccddeeff0011',
    '0v0-3': '00003000010000c0020000a0010000001122334455667788000000010400ffeeddcc000000000000'
             'aabbccddeeff0011',
    '0v0-4': '00003800010000c000000080000010a001000000000000001122334455667788000000000400'
             'ffeeddcc000000000000aabbccddeeff0011',
    '1': '000009000200000033',
    'malformed-vendor': '000022002e4800c000000080000000a00400000010029e09a000e3050000ffffffff',
    'unparsed-vendor': '000027002e4800c000000080000000a00400000010029e09a000e3050000ffffffff'
                       '0200dead04',
}

#: The radiotap headers of tcpdump's test-capture records, by file and record.
TCPDUMP = {
    'exthdr#1': '000059006f480080f70177100000000068d698000000000010026c09a000eaaa0100000000000200'
                '6c09a000031b68d698000000000001000140334080aa009fff019cffaa00000000000000000000'
                '00000000000000000000',
    'exthdr#3': '0000530045840280777f761000000000ddd998000000000002aa1b000000000000026c09a00003'
                '1bfc060000000000000000000000000043364380aa009fff019cffe1000000000000000000000000'
                '00000000',
    'rx-stbc#1': '000025002b480800641c00000000000010009e098004cd0100002725070000000000000000',
    'rx-stbc#2': '000025002b4808003d0f23070000000010009e098004d20100002741070000000000000000',
    'htc#1': '00003c006b08804086b2ae390000000004003c144001d3950000fcc3fe00e5690f008021027f00037f'
             '001000cb050204feff000000000000e06e8e27',
}

#: The ``reason`` of an ``Unknown`` entry, for a type with no layout and for a
#: field past the region.
NO_LAYOUT = 'no layout is defined for the field type'
PAST = 'the field runs past the field-data region'

#: Wire octets of each field below, from 0x81 up, so that a signed octet is negative.
PATTERN = bytes(range(0x81, 0xA1))

#: The pad octets each field takes after a Flags field ends at octet 9 of the
#: header, and what the field decodes to from :data:`PATTERN`, worked out from
#: its radiotap.org page.
EXPECTED = {
    'Rate': (0, {'rate': 0x81}),
    'Channel': (1, {'frequency': 0x8281, 'flags': 0x8483}),
    'FHSS': (1, {'hop_set': 0x81, 'hop_pattern': 0x82}),
    'Antenna_signal': (0, {'signal': -127}),
    'Antenna_noise': (0, {'noise': -127}),
    'Lock_quality': (1, {'quality': 0x8281}),
    'TX_attenuation': (1, {'attenuation': 0x8281}),
    'dB_TX_attenuation': (1, {'attenuation': 0x8281}),
    'dBm_TX_power': (0, {'power': -127}),
    'Antenna': (0, {'antenna': 0x81}),
    'dB_antenna_signal': (0, {'signal': 0x81}),
    'dB_antenna_noise': (0, {'noise': 0x81}),
    'RX_flags': (1, {'flags': 0x8281}),
    'TX_flags': (1, {'flags': 0x8281}),
    'RTS_retries': (0, {'retries': 0x81}),
    'data_retries': (0, {'retries': 0x81}),
    'MCS': (0, {'known': 0x81, 'flags': 0x82, 'mcs': 0x83}),
    'A_MPDU_status': (3, {'reference': 0x84838281, 'flags': 0x8685, 'delimiter_crc': 0x87,
                          'reserved': 0x88}),
    'VHT': (1, {'known': 0x8281, 'flags': 0x83, 'bandwidth': 0x84, 'mcs_nss': (0x85, 0x86, 0x87, 0x88),
                'coding': 0x89, 'group_id': 0x8A, 'partial_aid': 0x8C8B}),
    'timestamp': (7, {'timestamp': 0x8887868584838281, 'accuracy': 0x8A89, 'unit_position': 0x8B,
                      'flags': 0x8C}),
    'HE': (1, {'data1': 0x8281, 'data2': 0x8483, 'data3': 0x8685, 'data4': 0x8887, 'data5': 0x8A89,
               'data6': 0x8C8B}),
    'HE_MU': (1, {'flags1': 0x8281, 'flags2': 0x8483, 'ru_channel1': (0x85, 0x86, 0x87, 0x88),
                  'ru_channel2': (0x89, 0x8A, 0x8B, 0x8C)}),
    'HE_MU_other_user': (1, {'per_user_1': 0x8281, 'per_user_2': 0x8483, 'per_user_position': 0x85,
                             'per_user_known': 0x86}),
    'FieldType_0_length_PSDU': (0, {'psdu_type': 0x81}),
    'L_SIG': (1, {'data1': 0x8281, 'data2': 0x8483}),
}

#: Octets of each field in :data:`EXPECTED`, from its radiotap.org page.
SIZE = {
    'Rate': 1, 'Channel': 4, 'FHSS': 2, 'Antenna_signal': 1, 'Antenna_noise': 1, 'Lock_quality': 2,
    'TX_attenuation': 2, 'dB_TX_attenuation': 2, 'dBm_TX_power': 1, 'Antenna': 1,
    'dB_antenna_signal': 1, 'dB_antenna_noise': 1, 'RX_flags': 2, 'TX_flags': 2, 'RTS_retries': 1,
    'data_retries': 1, 'MCS': 3,
    'A_MPDU_status': 8, 'VHT': 12, 'timestamp': 12, 'HE': 12, 'HE_MU': 12, 'HE_MU_other_user': 6,
    'FieldType_0_length_PSDU': 1, 'L_SIG': 4,
}

#: ``(alignment, size)`` of each field in the tables of three parsers, where
#: they give one: the Linux kernel's ``net/wireless/radiotap.c``, Wireshark's
#: ``epan/dissectors/packet-ieee80211-radiotap-iter.c`` and radiotap-library's
#: ``radiotap.c``. Bit 18, which radiotap.org lists as unofficial and none of
#: them sizes, is left out; Wireshark gives bit 25 no size.
REFERENCE = {
    'linux': {0: (8, 8), 1: (1, 1), 2: (1, 1), 3: (2, 4), 4: (2, 2), 5: (1, 1), 6: (1, 1), 7: (2, 2),
              8: (2, 2), 9: (2, 2), 10: (1, 1), 11: (1, 1), 12: (1, 1), 13: (1, 1), 14: (2, 2),
              15: (2, 2), 16: (1, 1), 17: (1, 1), 19: (1, 3), 20: (4, 8), 21: (2, 12)},
    'wireshark': {0: (8, 8), 1: (1, 1), 2: (1, 1), 3: (2, 4), 4: (2, 2), 5: (1, 1), 6: (1, 1),
                  7: (2, 2), 8: (2, 2), 9: (2, 2), 10: (1, 1), 11: (1, 1), 12: (1, 1), 13: (1, 1),
                  14: (2, 2), 15: (2, 2), 16: (1, 1), 17: (1, 1), 19: (1, 3), 20: (4, 8), 21: (2, 12),
                  22: (8, 12),
                  23: (2, 12), 24: (2, 12), 26: (1, 1), 27: (2, 4)},
    'radiotap-library': {0: (8, 8), 1: (1, 1), 2: (1, 1), 3: (2, 4), 4: (2, 2), 5: (1, 1), 6: (1, 1),
                         7: (2, 2), 8: (2, 2), 9: (2, 2), 10: (1, 1), 11: (1, 1), 12: (1, 1),
                         13: (1, 1), 14: (2, 2), 15: (2, 2), 16: (1, 1), 17: (1, 1), 19: (1, 3),
                         20: (4, 8), 21: (2, 12), 22: (8, 12)},
}


def _radiotap(present: 'list[int]', fields: bytes = b'', it_len: 'int | None' = None) -> bytes:
    """Pack a radiotap header: fixed start, present-flags chain, fields."""
    if it_len is None:
        it_len = 4 + 4 * len(present) + len(fields)
    return struct.pack('<BBH', 0, 0, it_len) + b''.join(struct.pack('<I', word) for word in present) + fields


class TestRadiotapFields(unittest.TestCase):
    """Pin the decoding of the field-data region, and its encoding."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _parse(self, raw: bytes):  # type: ignore[no-untyped-def]
        from pcapkit.protocols.link.radiotap import Radiotap

        parsed = Radiotap(raw, len(raw))
        self.assertEqual(parsed.data, raw)
        return parsed

    def _entries(self, parsed) -> 'list[tuple[str, dict]]':  # type: ignore[no-untyped-def]
        """The decoded fields as ``(type name, subfields)``, the type left out."""
        return [(key.name, {name: value for name, value in entry.items() if name != 'type'})
                for key, entry in parsed.info.decoded.items(multi=True)]

    def _assert_round_trips(self, parsed, raw: bytes, *, reencodes: bool = True) -> None:  # type: ignore[no-untyped-def]
        """Rebuild ``raw`` from the info, its dict, and, unless ``reencodes`` is
        false, from ``present`` and ``decoded`` through ``make()``."""
        from pcapkit.protocols.link.radiotap import Radiotap

        for data in (parsed.info, parsed.info.to_dict()):
            with self.subTest(data=type(data).__name__):
                self.assertEqual(Radiotap.from_data(data).data.hex(), raw.hex())
        if reencodes:
            made = Radiotap(present=parsed.info.present, fields=parsed.info.decoded,
                            payload=raw[parsed.info.it_len:])
            self.assertEqual(made.data.hex(), raw.hex())

    def test_each_field_decodes_at_its_alignment(self) -> None:
        """Every field radiotap.org lays out, after a 1-octet Flags field, and its padding."""
        from pcapkit.const.radiotap.field_type import FieldType

        for name, (pad, values) in EXPECTED.items():
            with self.subTest(field=name):
                field_type = FieldType[name]
                data = PATTERN[:SIZE[name]]
                raw = _radiotap([1 << 1 | 1 << field_type], b'\x5a' + bytes(pad) + data) + ACK
                parsed = self._parse(raw)
                self.assertEqual(self._entries(parsed), [('Flags', {'flags': 0x5A}), (name, values)])
                self.assertEqual(parsed.payload.data, ACK)
                self._assert_round_trips(parsed, raw)

    def test_tsft_aligns_from_the_header_start(self) -> None:
        """The 8-octet TSFT after one word needs no pad; after two words it takes 4."""
        for present, pad in (([1], 0), ([1 << 31 | 1, 0], 4), ([1 << 31 | 1, 1 << 31, 0], 0)):
            with self.subTest(words=len(present)):
                raw = _radiotap(present, bytes(pad) + PATTERN[:8])
                parsed = self._parse(raw)
                self.assertEqual(self._entries(parsed), [('TSFT', {'mactime': 0x8887868584838281})])
                self._assert_round_trips(parsed, raw)

    def test_radiotap_library_vectors(self) -> None:
        """What radiotap-library's ``check/*.out`` prints for each, under its default options."""
        tsft_0 = ('TSFT', {'mactime': 9833440827789222417})
        tsft_1 = ('TSFT', {'mactime': 1225260500033256362})
        reset = ('Radiotap_Namespace', {})
        vendor_head = [('Flags', {'flags': 0x10}), ('Rate', {'rate': 2}),
                       ('Channel', {'frequency': 2462, 'flags': 0x00A0}),
                       ('Antenna_signal', {'signal': -29}), ('Antenna', {'antenna': 5}),
                       ('RX_flags', {'flags': 0})]

        def vendor(sub: int) -> 'tuple[str, dict]':
            return ('Vendor_Namespace', {'oui': b'\x00\x00\x00', 'sub_namespace': sub, 'skip_length': 4,
                                         'data': bytes.fromhex('ffeeddcc')})

        cases = {
            '0': [tsft_0],
            '00': [tsft_0, reset, tsft_1],
            # its --fcshdr option reads bit 14 as OpenBSD's FCS; the default is RX flags
            '0fcs': [tsft_0, ('RX_flags', {'flags': 0xBBAA})],
            '0v0': [tsft_0, vendor(0), reset, tsft_1],
            '0v0-2': [tsft_0, vendor(0), reset, tsft_1],
            '0v0-3': [tsft_0, vendor(1), reset, tsft_1],
            '0v0-4': [tsft_0, vendor(0), reset, tsft_1],
            '1': [('Flags', {'flags': 0x33})],
            'malformed-vendor': vendor_head + [('Vendor_Namespace', {'data': b'\xff' * 4, 'reason': PAST})],
            'unparsed-vendor': vendor_head + [
                ('Vendor_Namespace', {'oui': b'\xff' * 3, 'sub_namespace': 0xFF, 'skip_length': 2,
                                      'data': b'\xde\xad'}),
                reset, ('Rate', {'rate': 4}),
            ],
        }
        for name, expected in cases.items():
            with self.subTest(vector=name):
                raw = bytes.fromhex(RTLIB[name])
                parsed = self._parse(raw)
                self.assertEqual(self._entries(parsed), expected)
                # 0fcs ends in two octets no bit selects, kept in ``fields`` alone
                self._assert_round_trips(parsed, raw, reencodes=name != '0fcs')

        malformed = self._parse(bytes.fromhex(RTLIB['malformed-vendor'])).info.decoded
        self.assertEqual(type(malformed.getlist(30)[0]).__name__, 'Unknown')

    def test_tcpdump_captures(self) -> None:
        """What tcpdump's ``.out`` file prints for each record, where it decodes the field."""
        signal = 'Antenna_signal'
        cases = {
            # 10016360us tsft 1.0 Mb/s 2412 MHz 11b -22dBm signal -86dBm noise antenna 1 [bit 32]
            'exthdr#1': [('TSFT', {'mactime': 10016360}), ('Flags', {'flags': 0x10}), ('Rate', {'rate': 2}),
                         ('Channel', {'frequency': 2412, 'flags': 0x00A0}), (signal, {'signal': -22}),
                         ('Antenna_noise', {'noise': -86}), ('Antenna', {'antenna': 1}),
                         ('RX_flags', {'flags': 0}), ('S1G', None)],
            # 10017245us tsft 1.0 Mb/s -86dBm noise 27dBm tx power [bit 15]
            'exthdr#3': [('TSFT', {'mactime': 10017245}), ('Rate', {'rate': 2}),
                         ('Antenna_noise', {'noise': -86}), ('dBm_TX_power', {'power': 27}),
                         ('TX_flags', {'flags': 0}), ('data_retries', {'retries': 0}), ('S1G', None)],
            # 7268us tsft 2462 MHz 11n -51dBm signal antenna 1 ... MCS 7 40 MHz short GI RX-STBC1
            'rx-stbc#1': [('TSFT', {'mactime': 7268}), ('Flags', {'flags': 0x10}),
                          ('Channel', {'frequency': 2462, 'flags': 0x0480}), (signal, {'signal': -51}),
                          ('Antenna', {'antenna': 1}), ('RX_flags', {'flags': 0}),
                          ('MCS', {'known': 0x27, 'flags': 0x25, 'mcs': 7})],
            # 119738173us tsft 2462 MHz 11n -46dBm signal antenna 1 ... MCS 7 40 MHz long GI RX-STBC2
            'rx-stbc#2': [('TSFT', {'mactime': 119738173}), ('Flags', {'flags': 0x10}),
                          ('Channel', {'frequency': 2462, 'flags': 0x0480}), (signal, {'signal': -46}),
                          ('Antenna', {'antenna': 1}), ('RX_flags', {'flags': 0}),
                          ('MCS', {'known': 0x27, 'flags': 0x41, 'mcs': 7})],
            # 967750278us tsft wep 5180 MHz 11a -45dBm signal -107dBm noise antenna 0 [bit 23]
            'htc#1': [('TSFT', {'mactime': 967750278}), ('Flags', {'flags': 0x04}),
                      ('Channel', {'frequency': 5180, 'flags': 0x0140}), (signal, {'signal': -45}),
                      ('Antenna_noise', {'noise': -107}), ('Antenna', {'antenna': 0}),
                      ('HE', {'data1': 0xC3FC, 'data2': 0x00FE, 'data3': 0x69E5, 'data4': 0x000F,
                              'data5': 0x2180, 'data6': 0x7F02}),
                      ('Vendor_Namespace', {'oui': b'\x00\x03\x7f', 'sub_namespace': 0, 'skip_length': 16,
                                            'data': bytes.fromhex('cb050204feff000000000000e06e8e27')})],
        }
        for name, expected in cases.items():
            with self.subTest(record=name):
                raw = bytes.fromhex(TCPDUMP[name]) + ACK
                parsed = self._parse(raw)
                entries = self._entries(parsed)
                self.assertEqual([key for key, _ in entries], [key for key, _ in expected])
                for (key, values), (_, want) in zip(entries, expected):
                    if want is None:  # a bit no field is defined for: the rest, raw
                        self.assertEqual(sorted(values), ['data', 'reason'])
                        self.assertEqual(values['reason'], NO_LAYOUT)
                    else:
                        self.assertEqual(values, want, key)
                self.assertEqual(parsed.payload.data, ACK)
                # rx-stbc's headers end in 8 zero octets no bit selects
                self._assert_round_trips(parsed, raw, reencodes=not name.startswith('rx-stbc'))

    def test_namespaces_restart_and_repeat(self) -> None:
        """A per-chain signal in each of three radiotap namespaces, as Linux writes them."""
        from pcapkit.const.radiotap.field_type import FieldType

        reset = 1 << 29 | 1 << 31
        present = [1 << 5 | reset, 1 << 5 | 1 << 11 | reset, 1 << 5 | 1 << 11]
        raw = _radiotap(present, bytes([0xD8, 0xD6, 0x00, 0xDA, 0x01])) + ACK
        parsed = self._parse(raw)
        self.assertEqual([key for key, _ in self._entries(parsed)],
                         ['Antenna_signal', 'Radiotap_Namespace', 'Antenna_signal', 'Antenna',
                          'Radiotap_Namespace', 'Antenna_signal', 'Antenna'])
        decoded = parsed.info.decoded
        self.assertEqual([entry.signal for entry in decoded.getlist(FieldType.Antenna_signal)], [-40, -42, -38])
        self.assertEqual([entry.antenna for entry in decoded.getlist(FieldType.Antenna)], [0, 1])
        self._assert_round_trips(parsed, raw)

    def test_a_namespace_without_a_reset_continues_at_bit_32(self) -> None:
        """Bit 0 of a second word is field type 32 there, which no presence bit defines."""
        raw = _radiotap([1 << 1 | 1 << 31, 1], b'\x10\xaa\xbb')
        parsed = self._parse(raw)
        self.assertEqual(self._entries(parsed),
                         [('Flags', {'flags': 0x10}), ('S1G', {'data': b'\xaa\xbb', 'reason': NO_LAYOUT})])
        self.assertEqual(type(parsed.info.decoded.getlist(32)[0]).__name__, 'Unknown')
        self._assert_round_trips(parsed, raw)

    def test_a_bit_no_field_is_defined_for_ends_the_walk(self) -> None:
        """Bit 18, FreeBSD's XChannel, has no layout; the MCS field after it stays raw."""
        raw = _radiotap([1 << 1 | 1 << 18 | 1 << 19], b'\x10\x07\x27\x25\x07')
        parsed = self._parse(raw)
        self.assertEqual(self._entries(parsed),
                         [('Flags', {'flags': 0x10}),
                          ('Unassigned', {'data': b'\x07\x27\x25\x07', 'reason': NO_LAYOUT})])
        self.assertEqual(int(list(parsed.info.decoded)[1]), 18)
        self._assert_round_trips(parsed, raw)

    def test_the_unofficial_retries_fields(self) -> None:
        """Bits 16 and 17, as Linux writes them on a TX status frame, before an MCS field."""
        raw = _radiotap([1 << 15 | 1 << 16 | 1 << 17 | 1 << 19], b'\x02\x00\x03\x01\x27\x25\x07')
        parsed = self._parse(raw)
        self.assertEqual(self._entries(parsed), [
            ('TX_flags', {'flags': 0x0002}), ('RTS_retries', {'retries': 3}), ('data_retries', {'retries': 1}),
            ('MCS', {'known': 0x27, 'flags': 0x25, 'mcs': 7}),
        ])
        self._assert_round_trips(parsed, raw)

    def test_a_field_past_the_region_is_unknown(self) -> None:
        """A TSFT with half its octets inside ``it_len``, and a capture cut inside a field."""
        raw = _radiotap([1 << 1 | 1], PATTERN[:4]) + ACK
        parsed = self._parse(raw)
        self.assertEqual(self._entries(parsed), [('TSFT', {'data': PATTERN[:4], 'reason': PAST})])
        self._assert_round_trips(parsed, raw)

        whole = _radiotap([1 << 3], PATTERN[:4])
        for keep in range(8, len(whole)):
            with self.subTest(keep=keep):
                parsed = self._parse(whole[:keep])
                self.assertEqual(self._entries(parsed), [('Channel', {'data': whole[8:keep], 'reason': PAST})])

    def test_tlv_fields(self) -> None:
        """Each kind of TLV item, after a Flags field and 3 pad octets."""
        def item(tlv_type: int, data: bytes) -> bytes:
            return struct.pack('<HH', tlv_type, len(data)) + data + bytes(-len(data) % 4)

        s1g = struct.pack('<HHH', 0x0001, 0x0002, 0x0003)
        usig = struct.pack('<III', 0x11, 0x22, 0x33)
        eht = struct.pack('<12I', 0xE0, *range(1, 10), 0xA1, 0xA2)
        vendor = bytes.fromhex('001374') + struct.pack('<BHH', 1, 5, 0) + b'\xaa\xbb'
        tlvs = (item(32, s1g) + item(33, usig) + item(34, eht) + item(30, vendor)
                + item(0, PATTERN[:8]) + item(32, s1g[:4]) + item(28, b''))
        raw = _radiotap([1 << 1 | 1 << 28], b'\x10' + bytes(3) + tlvs) + ACK
        parsed = self._parse(raw)
        entries = self._entries(parsed)
        self.assertEqual([key for key, _ in entries], ['Flags', 'TLV_fields_in_radiotap'])
        got = [(item.type.name, item.length, item.data) for item in entries[1][1]['tlvs']]
        self.assertEqual(got[:3], [
            ('S1G', 6, {'type': 32, 'known': 1, 'data1': 2, 'data2': 3}),
            ('U_SIG', 12, {'type': 33, 'common': 0x11, 'value': 0x22, 'mask': 0x33}),
            ('EHT', 48, {'type': 34, 'known': 0xE0, 'data': tuple(range(1, 10)), 'user_info': (0xA1, 0xA2)}),
        ])
        self.assertEqual(got[3], ('Vendor_Namespace', 10, {'oui': bytes.fromhex('001374'), 'subtype': 1,
                                                            'presence_type': 5, 'reserved': 0,
                                                            'data': b'\xaa\xbb'}))
        self.assertEqual(got[4], ('TSFT', 8, {'type': 0, 'mactime': 0x8887868584838281}))
        # S1G cut short by its producer decodes with the zeros it left out (#2655),
        # and a padding item stays raw
        self.assertEqual(got[5:], [('S1G', 4, {'type': 32, 'known': 1, 'data1': 2, 'data2': 0,
                                               '__short_read__': ('data2', 0)}),
                                   ('TLV_fields_in_radiotap', 0, b'')])
        self._assert_round_trips(parsed, raw)

    def test_a_tlv_past_the_region_is_unknown(self) -> None:
        """An item whose length runs past ``it_len`` leaves the whole list raw, its pad included."""
        tlvs = struct.pack('<HH', 32, 6) + b'\x01\x00'
        raw = _radiotap([1 << 1 | 1 << 28], b'\x10' + bytes(3) + tlvs)
        parsed = self._parse(raw)
        self.assertEqual(self._entries(parsed),
                         [('Flags', {'flags': 0x10}),
                          ('TLV_fields_in_radiotap', {'data': bytes(3) + tlvs, 'reason': PAST})])
        self._assert_round_trips(parsed, raw)

    def _assert_flag(self, value, registry, number, named) -> None:  # type: ignore[no-untyped-def]
        """``value`` is a member of ``registry`` worth ``number``, with the bits of ``named`` set."""
        with self.subTest(registry=registry.__name__):
            self.assertIsInstance(value, registry)
            self.assertEqual(int(value), number)
            self.assertEqual(value & named, named)

    def test_bitmaps_decode_into_their_flag_registries(self) -> None:
        """A bitmap radiotap.org defines bit by bit is a registry member, its undefined bits kept."""
        from pcapkit.const.radiotap.ampdu_flags import AMPDUFlags
        from pcapkit.const.radiotap.channel_flags import ChannelFlags
        from pcapkit.const.radiotap.eht_known import EHTKnown
        from pcapkit.const.radiotap.flags import Flags
        from pcapkit.const.radiotap.he_mu_other_user_known import HEMUOtherUserKnown
        from pcapkit.const.radiotap.lsig_data1 import LSIGData1
        from pcapkit.const.radiotap.mcs_known import MCSKnown
        from pcapkit.const.radiotap.rx_flags import RXFlags
        from pcapkit.const.radiotap.s1g_known import S1GKnown
        from pcapkit.const.radiotap.timestamp_flags import TimestampFlags
        from pcapkit.const.radiotap.vht_coding import VHTCoding
        from pcapkit.const.radiotap.vht_flags import VHTFlags
        from pcapkit.const.radiotap.vht_known import VHTKnown

        # Flags, Channel, RX flags, MCS and VHT; the Channel flags carry the
        # undefined bits 0x0008 and 0x8000, the VHT known the unused 0x0200,
        # and the VHT coding the unused 0x10
        fields = (b'\x90' + b'\x00' + struct.pack('<HH', 2412, 0x80A8) + struct.pack('<H', 0x0003)
                  + bytes([0x27, 0x25, 0x07]) + b'\x00'
                  + struct.pack('<HBB4BBBH', 0x0244, 0x05, 4, 0x91, 0, 0, 0, 0x15, 0, 0))
        raw = _radiotap([1 << 1 | 1 << 3 | 1 << 14 | 1 << 19 | 1 << 21], fields) + ACK
        parsed = self._parse(raw)
        decoded = parsed.info.decoded
        self._assert_flag(decoded[1].flags, Flags, 0x90, Flags.F_FCS | Flags.F_SHORTGI)
        self._assert_flag(decoded[3].flags, ChannelFlags, 0x80A8, ChannelFlags.CHAN_CCK | ChannelFlags.CHAN_2GHZ)
        self._assert_flag(decoded[14].flags, RXFlags, 0x0003, RXFlags.F_RX_BADPLCP)
        self._assert_flag(decoded[19].known, MCSKnown, 0x27, MCSKnown.MCS_HAVE_BW | MCSKnown.MCS_HAVE_MCS
                          | MCSKnown.MCS_HAVE_GI | MCSKnown.MCS_HAVE_STBC)
        self._assert_flag(decoded[21].known, VHTKnown, 0x0244, VHTKnown.VHT_KNOWN_GI | VHTKnown.VHT_KNOWN_BANDWIDTH)
        self._assert_flag(decoded[21].flags, VHTFlags, 0x05, VHTFlags.VHT_FLAG_STBC | VHTFlags.VHT_FLAG_SGI)
        self._assert_flag(decoded[21].coding, VHTCoding, 0x15,
                          VHTCoding.CODING_LDPC_USER0 | VHTCoding.CODING_LDPC_USER2)
        self.assertEqual(int(decoded[3].flags) & ~0x00A0, 0x8008)
        # the MCS flags hold value subfields, so they stay a plain integer
        self.assertIs(type(decoded[19].flags), int)
        self._assert_round_trips(parsed, raw)

        # A-MPDU status, timestamp, HE-MU-other-user and L-SIG; the reserved
        # 0x0100 of the A-MPDU flags, 0x04 of the timestamp flags and 0x0004
        # of the L-SIG data1 are kept
        fields = (struct.pack('<IHBB', 7, 0x0105, 0, 0) + struct.pack('<QHBB', 1, 0, 0x11, 0x06)
                  + struct.pack('<HHBB', 0, 0, 0, 0x23) + struct.pack('<HH', 0x0007, 0))
        raw = _radiotap([1 << 20 | 1 << 22 | 1 << 25 | 1 << 27], fields) + ACK
        parsed = self._parse(raw)
        decoded = parsed.info.decoded
        self._assert_flag(decoded[20].flags, AMPDUFlags, 0x0105,
                          AMPDUFlags.AMPDU_REPORT_ZEROLEN | AMPDUFlags.AMPDU_LAST_KNOWN)
        self._assert_flag(decoded[22].flags, TimestampFlags, 0x06, TimestampFlags.TIMESTAMP_FLAG_ACCURACY)
        self._assert_flag(decoded[25].per_user_known, HEMUOtherUserKnown, 0x23,
                          HEMUOtherUserKnown.user_field_position_known | HEMUOtherUserKnown.STA_ID_known
                          | HEMUOtherUserKnown.MCS_known)
        self._assert_flag(decoded[27].data1, LSIGData1, 0x0007,
                          LSIGData1.LSIG_DATA1_RATE_KNOWN | LSIGData1.LSIG_DATA1_LENGTH_KNOWN)
        self._assert_round_trips(parsed, raw)

        # S1G and EHT, which are TLV-only
        tlv = (struct.pack('<HH', 32, 6) + struct.pack('<HHH', 0x0103, 0, 0) + bytes(2)
               + struct.pack('<HH', 34, 40) + struct.pack('<10I', 0x00000003, *range(9)))
        raw = _radiotap([1 << 28], tlv)
        parsed = self._parse(raw)
        s1g, eht = (item.data for item in parsed.info.decoded[28].tlvs)
        self._assert_flag(s1g.known, S1GKnown, 0x0103,
                          S1GKnown.S1G_KNOWN_PPDU_FORMAT | S1GKnown.S1G_KNOWN_RESPONSE_IND)
        self._assert_flag(eht.known, EHTKnown, 0x00000003, EHTKnown.EHT_KNOWN_SPATIAL_REUSE)
        self._assert_round_trips(parsed, raw)

    def test_make_takes_flag_members_or_ints(self) -> None:
        """The enum-or-int rule: a member, a composite or an ``int`` writes the same octets."""
        from pcapkit.const.radiotap.flags import Flags
        from pcapkit.protocols.link.radiotap import Radiotap
        from pcapkit.utilities.exceptions import ProtocolError

        expected = _radiotap([1 << 1], b'\x50')
        for value in (Flags.F_FCS | Flags.F_BADFCS, Flags.get(0x50), 0x50):
            with self.subTest(value=value):
                self.assertEqual(Radiotap(present=(1 << 1,), fields=[(1, {'flags': value})]).data, expected)
        for value in ('FCS', 0x100, True):
            with self.subTest(value=value), self.assertRaises(ProtocolError):
                Radiotap(present=(1 << 1,), fields=[(1, {'flags': value})])

    def test_make_from_type_and_mapping_pairs(self) -> None:
        """``make()`` takes a type as a member or an ``int``, and writes the padding."""
        from pcapkit.const.radiotap.field_type import FieldType
        from pcapkit.protocols.link.radiotap import Radiotap

        # a vendor namespace in the second word, then the radiotap one again
        present = (1 << 1 | 1 << 3 | 1 << 5 | 1 << 30 | 1 << 31, 1 << 29 | 1 << 31, 1)
        fields = [
            (FieldType.Flags, {'flags': 0x10}),
            (3, {'frequency': 2412, 'flags': 0x00A0}),
            (5, {'signal': -40}),
            (FieldType.Vendor_Namespace, {'oui': b'\x00\x13\x74', 'sub_namespace': 2, 'data': b'\x01\x02'}),
            (29, {}),
            (0, {'mactime': 1}),
        ]
        made = Radiotap(present=present, fields=fields, payload=ACK)
        # Flags at octet 16, a pad, Channel, the signal, a pad, the vendor field
        # and its data, then TSFT on the 8-octet boundary at octet 32
        expected = _radiotap(list(present),
                             b'\x10' + b'\x00' + struct.pack('<HH', 2412, 0x00A0) + b'\xd8'
                             + b'\x00' + b'\x00\x13\x74\x02' + struct.pack('<H', 2) + b'\x01\x02'
                             + struct.pack('<Q', 1)) + ACK
        self.assertEqual(made.data.hex(), expected.hex())
        parsed = self._parse(made.data)
        self.assertEqual([key for key, _ in self._entries(parsed)],
                         ['Flags', 'Channel', 'Antenna_signal', 'Vendor_Namespace', 'Radiotap_Namespace',
                          'TSFT'])
        self._assert_round_trips(parsed, made.data)

    def test_make_with_raw_fields_is_unchanged(self) -> None:
        """Raw octets are written as given, whatever ``present`` says."""
        from pcapkit.protocols.link.radiotap import Radiotap

        made = Radiotap(present=(1 << 31, 7), fields=b'\x01\x02\x03')
        self.assertEqual(made.data, _radiotap([1 << 31, 7], b'\x01\x02\x03'))

    def test_make_rejects_fields_that_do_not_fit(self) -> None:
        from pcapkit.const.radiotap.field_type import FieldType
        from pcapkit.protocols.link.radiotap import Radiotap
        from pcapkit.utilities.exceptions import ProtocolError

        flags = (FieldType.Flags, {'flags': 0})
        cases = {
            'a string': ((2,), 'flags'),
            'not iterable': ((2,), 2),
            'none for a bit': ((2 | 4,), [flags]),
            'one past the bits': ((2,), [flags, flags]),
            'the wrong type': ((2,), [(FieldType.Rate, {'rate': 0})]),
            'a missing subfield': ((2,), [(FieldType.Flags, {})]),
            'an unsigned overflow': ((2,), [(FieldType.Flags, {'flags': 0x100})]),
            'a bool': ((4,), [(FieldType.Rate, {'rate': True})]),
            'a signed overflow': ((1 << 5,), [(FieldType.Antenna_signal, {'signal': 128})]),
            'a short tuple': ((1 << 21,), [(FieldType.VHT, {'known': 0, 'flags': 0, 'bandwidth': 0,
                                                            'mcs_nss': (0,), 'coding': 0, 'group_id': 0,
                                                            'partial_aid': 0})]),
            'a short oui': ((1 << 30,), [(30, {'oui': b'\x00', 'sub_namespace': 0, 'data': b''})]),
            'a wrong skip_length': ((1 << 30,), [(30, {'oui': bytes(3), 'sub_namespace': 0,
                                                        'skip_length': 4, 'data': b''})]),
            'a chain cut short': ((2, 0), [flags]),
            'raw data not bytes': ((1 << 18,), [(18, {'data': 'x'})]),
            'a wrong tlv length': ((1 << 28,), [(28, {'tlvs': [{'type': 32, 'length': 1, 'data': b''}]})]),
            'decoded tlv data of no layout': ((1 << 28,), [(28, {'tlvs': [{'type': 18, 'data': {'x': 1}}]})]),
        }
        for name, (present, fields) in cases.items():
            with self.subTest(case=name), self.assertRaises(ProtocolError):
                Radiotap(present=present, fields=fields)

    def test_unknown_entries_are_written_raw(self) -> None:
        """An ``Unknown`` entry, or one for a bit no field is defined for, ends the region."""
        from pcapkit.const.radiotap.field_type import FieldType
        from pcapkit.protocols.data.link.radiotap import Unknown
        from pcapkit.protocols.link.radiotap import Radiotap

        unknown = Unknown(type=FieldType.TSFT, data=b'\x01\x02', reason='any')
        self.assertEqual(Radiotap(present=(1,), fields=[unknown]).data, _radiotap([1], b'\x01\x02'))
        self.assertEqual(Radiotap(present=(1 << 18,), fields=[(18, {'data': b'\x03'})]).data,
                         _radiotap([1 << 18], b'\x03'))

    def test_the_layouts_match_three_parsers(self) -> None:
        """Alignment and size of each field's schema, as the Linux kernel, Wireshark and radiotap-library give them."""
        from pcapkit.protocols.schema.link.radiotap import RadiotapField

        for parser, table in REFERENCE.items():
            for bit, (align, size) in table.items():
                with self.subTest(parser=parser, bit=bit):
                    schema = RadiotapField.registry[bit]
                    self.assertEqual((schema.__align__, sum(field.length for field in schema.__fields__.values())),
                                     (align, size))

    def test_each_field_type_pairs_a_schema_with_its_methods(self) -> None:
        """``__field__`` and the schema registry name the same types, and each name has its two methods."""
        from pcapkit.protocols.link.radiotap import Radiotap
        from pcapkit.protocols.schema.link.radiotap import RadiotapField

        self.assertEqual(sorted(map(int, Radiotap.__field__)), sorted(map(int, RadiotapField.registry)))
        for code, name in Radiotap.__field__.items():
            with self.subTest(field=code.name):
                self.assertTrue(callable(getattr(Radiotap, f'_read_field_{name}', None)))
                self.assertTrue(callable(getattr(Radiotap, f'_make_field_{name}', None)))

    def test_a_ragged_eht_tlv_decodes_quietly(self) -> None:
        """An EHT item whose last user word is cut short decodes it padded with zeros (#2655), and nothing is logged."""
        import logging

        records = []  # type: list[logging.LogRecord]
        handler = logging.Handler()
        handler.emit = records.append  # type: ignore[method-assign]
        logger = logging.getLogger('pcapkit')
        logger.addHandler(handler)
        try:
            data = struct.pack('<10I', 0, *range(9)) + b'\xa1\xa2'
            raw = _radiotap([1 << 28], struct.pack('<HH', 34, len(data)) + data + bytes(2))
            parsed = self._parse(raw)
        finally:
            logger.removeHandler(handler)
        self.assertEqual([(item.type.name, item.data) for item in parsed.info.decoded[28].tlvs],
                         [('EHT', {'type': 34, 'known': 0, 'data': tuple(range(9)), 'user_info': (0xA2A1,),
                                   '__short_read__': ('user_info', 2)})])
        self.assertEqual(records, [])
        self._assert_round_trips(parsed, raw)

    def test_register_field_warns_on_overwrite(self) -> None:
        """``register_field`` warns when it displaces an entry, and only then."""
        from unittest import mock

        from pcapkit.const.radiotap.field_type import FieldType
        from pcapkit.protocols.link.radiotap import Radiotap
        from pcapkit.utilities.warnings import RegistryWarning

        registry = Radiotap.__dict__['__field__']
        try:
            with mock.patch('pcapkit.protocols.link.radiotap.warn') as warn:
                Radiotap.register_field(FieldType.Channel, 'fhss')
            warn.assert_called_once()
            self.assertIs(warn.call_args.args[1], RegistryWarning)
            self.assertEqual(registry[FieldType.Channel], 'fhss')
        finally:
            registry[FieldType.Channel] = 'channel'

        # An unregistered type carries no entry, so registering one is not an
        # overwrite, and handing back the entry stored, or one equal to it, is a
        # silent no-op (#1362).
        custom = FieldType.get(18)
        self.assertNotIn(custom, registry)
        pair = (lambda *_: None, lambda *_: None)
        try:
            with mock.patch('pcapkit.protocols.link.radiotap.warn') as warn:
                Radiotap.register_field(custom, pair)
                Radiotap.register_field(custom, pair)
                Radiotap.register_field(custom, (pair[0], pair[1]))
            warn.assert_not_called()
            self.assertIs(registry[custom], pair)

            with mock.patch('pcapkit.protocols.link.radiotap.warn') as warn:
                Radiotap.register_field(custom, 'tsft')
            warn.assert_called_once()
            self.assertEqual(registry[custom], 'tsft')
        finally:
            registry.pop(custom, None)

    def test_a_field_type_registered_through_the_api_decodes(self) -> None:
        """Bit 18, FreeBSD's XChannel, registered with a schema, a parser and a constructor of its own."""
        from unittest import mock

        from pcapkit.const.radiotap.field_type import FieldType
        from pcapkit.corekit.fields.numbers import UInt8Field, UInt16Field, UInt32Field
        from pcapkit.corekit.infoclass import info_final
        from pcapkit.foundation.registry import register_radiotap_field
        from pcapkit.protocols.data.link.radiotap import RadiotapField as DataField
        from pcapkit.protocols.link.radiotap import Radiotap
        from pcapkit.protocols.schema.link.radiotap import RadiotapField
        from pcapkit.protocols.schema.schema import schema_final

        @schema_final
        class XChannelSchema(RadiotapField):
            __align__ = 4

            flags = UInt32Field(byteorder='little')
            frequency = UInt16Field(byteorder='little')
            channel = UInt8Field()
            maxpower = UInt8Field()

        @info_final
        class XChannel(DataField):
            flags: int
            frequency: int
            channel: int
            maxpower: int

        def parser(field_type, schema):  # type: ignore[no-untyped-def]
            return XChannel(type=field_type, flags=schema.flags, frequency=schema.frequency,
                            channel=schema.channel, maxpower=schema.maxpower)

        def constructor(field_type, entry):  # type: ignore[no-untyped-def]
            return XChannelSchema(flags=entry['flags'], frequency=entry['frequency'],
                                  channel=entry['channel'], maxpower=entry['maxpower'])

        raw = _radiotap([1 << 1 | 1 << 18 | 1 << 19],
                        b'\x10' + bytes(3) + struct.pack('<IHBB', 0x0140, 2412, 1, 20) + b'\x27\x25\x07') + ACK
        before = self._entries(self._parse(raw))
        self.assertEqual([key for key, _ in before], ['Flags', 'Unassigned'])

        with mock.patch.dict(Radiotap.__field__), mock.patch.dict(RadiotapField.registry):
            register_radiotap_field(FieldType.get(18), (parser, constructor), schema=XChannelSchema)
            parsed = self._parse(raw)
            self.assertEqual(self._entries(parsed), [
                ('Flags', {'flags': 0x10}),
                ('Unassigned', {'flags': 0x0140, 'frequency': 2412, 'channel': 1, 'maxpower': 20}),
                ('MCS', {'known': 0x27, 'flags': 0x25, 'mcs': 7}),
            ])
            self.assertIsInstance(parsed.info.decoded[18], XChannel)
            self._assert_round_trips(parsed, raw)
        self.assertEqual(self._entries(self._parse(raw)), before)

    def test_linux_sll_hands_on_the_decoded_header(self) -> None:
        """The capture path of #2502: ``LINUX_SLL`` with ``ARPHRD_IEEE80211_RADIOTAP``."""
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1

        radiotap = bytes.fromhex(TCPDUMP['rx-stbc#1'])
        raw = (struct.pack('>HHH', 0, ARPHRD.IEEE80211_RADIOTAP, 0) + bytes(8) + struct.pack('>H', 0)
               + radiotap + ACK)
        parsed = LinuxSLL1(raw, len(raw))
        self.assertEqual(parsed.protochain.chain, 'LINUX_SLL1:Radiotap:802.11:Raw')
        self.assertEqual(parsed.payload.info.decoded[19].mcs, 7)
        self.assertEqual(parsed.data, raw)
        self.assertEqual(type(parsed).from_data(parsed.info).data, raw)


if __name__ == '__main__':
    unittest.main()
