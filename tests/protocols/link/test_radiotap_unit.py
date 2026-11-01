# -*- coding: utf-8 -*-
"""GitHub issue #2502: the IEEE 802.11 radiotap header.

:class:`~pcapkit.protocols.link.radiotap.Radiotap` dissects the
``arphrd_type`` ``ARPHRD_IEEE80211_RADIOTAP`` payload that
:class:`~pcapkit.protocols.link.linux_sll.LinuxSLL` previously kept whole as
:class:`~pcapkit.protocols.misc.raw.Raw` (see
:attr:`LinuxSLL.__proto__ <pcapkit.protocols.link.linux_sll.LinuxSLL.__proto__>`). Covers the
fixed 8-octet start, the present-flags chain (plain and extended), the
field-data region being skipped rather than decoded, the 802.11 MAC frame
being kept as :class:`~pcapkit.protocols.misc.raw.Raw` (per the module
docstring's *Scope* section), malformed/truncated headers, and byte-exact
round trips. The Radiotap-dispatch side of ``LinuxSLL1``/``LinuxSLL2`` is
covered in their own test modules.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`.

"""

import unittest

from tests._support import reimport_once_per_class


def _radiotap(it_len: int, present: 'list[int]', fields: bytes = b'',
              it_version: int = 0, it_pad: int = 0) -> bytes:
    """Pack a bare radiotap header: fixed start, present-flags chain, fields."""
    chain = b''.join(word.to_bytes(4, 'little') for word in present)
    return (bytes([it_version, it_pad]) + it_len.to_bytes(2, 'little')
            + chain + fields)


class TestRadiotap(unittest.TestCase):
    """Pin the Radiotap layer, alone."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _assert_rebuilds(self, layer, **kwargs) -> None:  # type: ignore[no-untyped-def]
        """``layer`` rebuilds byte-exactly from its info, and from ``info.to_dict()``."""
        for data in (layer.info, layer.info.to_dict()):
            with self.subTest(layer=type(layer).__name__, data=type(data).__name__):
                self.assertEqual(type(layer).from_data(data, **kwargs).data.hex(), layer.data.hex())

    def test_minimal_header_with_empty_bitmask(self) -> None:
        """The shortest valid radiotap header: 8 octets, no fields, no
        extended present-flags word.
        """
        from pcapkit.protocols.link.radiotap import Radiotap
        from pcapkit.protocols.misc.null import NoPayload

        raw = _radiotap(8, [0])
        parsed = Radiotap(raw, len(raw))
        self.assertEqual(parsed.info.it_version, 0)
        self.assertEqual(parsed.info.it_pad, 0)
        self.assertEqual(parsed.info.it_len, 8)
        self.assertEqual(parsed.info.present, (0,))
        self.assertEqual(parsed.info.fields, b'')
        self.assertEqual((parsed.name, parsed.alias, parsed.length), ('Radiotap', 'Radiotap', 8))
        self.assertIsInstance(parsed.payload, NoPayload)
        self.assertEqual(parsed.protochain.chain, 'Radiotap')
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_header_with_present_fields_is_skipped_not_decoded(self) -> None:
        """A non-empty bitmask with a field-data region: the region is
        skipped over whole, per the module docstring's *Scope* section, and
        the 802.11 MAC frame behind it is kept as
        :class:`~pcapkit.protocols.misc.raw.Raw`.
        """
        from pcapkit.protocols.link.radiotap import Radiotap
        from pcapkit.protocols.misc.raw import Raw

        # bit 0 (TSFT, 8 octets) + bit 1 (Flags, 1 octet) + bit 2 (Rate, 1
        # octet) -- the exact field widths are not decoded, so any 10-octet
        # filler stands in for them.
        fields = bytes.fromhex('0102030405060708090a')
        mac = b'\xde\xad\xbe\xef' * 3
        raw = _radiotap(8 + len(fields), [0b111], fields) + mac
        parsed = Radiotap(raw, len(raw))
        self.assertEqual(parsed.info.it_len, 8 + len(fields))
        self.assertEqual(parsed.info.present, (0b111,))
        self.assertEqual(parsed.info.fields, fields)
        self.assertIsInstance(parsed.payload, Raw)
        self.assertEqual(parsed.payload.data, mac)
        self.assertEqual(parsed.protochain.chain, 'Radiotap:Raw')
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_extended_presence_chaining(self) -> None:
        """Bit 31 of a present-flags word chains in another word; the chain
        is walked fully, every word recorded in :attr:`~pcapkit.protocols.data.link.radiotap.Radiotap.present`.
        """
        from pcapkit.protocols.link.radiotap import Radiotap
        from pcapkit.protocols.misc.raw import Raw

        word0 = (1 << 31) | 0b1      # bit 31 set: a second word follows
        word1 = (1 << 31) | 0b10     # bit 31 set: a third word follows
        word2 = 0b100                # bit 31 clear: chain ends here
        fields = bytes.fromhex('aabbccdd')
        mac = b'\x01\x02\x03'
        raw = _radiotap(8 + 8 + len(fields), [word0, word1, word2], fields) + mac
        parsed = Radiotap(raw, len(raw))
        self.assertEqual(parsed.info.present, (word0, word1, word2))
        self.assertEqual(parsed.info.fields, fields)
        self.assertEqual(parsed.info.it_len, 20)
        self.assertIsInstance(parsed.payload, Raw)
        self.assertEqual(parsed.payload.data, mac)
        self.assertEqual(parsed.protochain.chain, 'Radiotap:Raw')
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_malformed_it_len_smaller_than_the_chain_it_claims(self) -> None:
        """``it_len`` claims a header too small to hold the present-flags
        word its own first word's bit 31 promises. The chain is still
        walked from the actual octets captured; the field-data region is
        empty rather than negative, and the frame behind the (malformed)
        header is not swallowed by it.
        """
        from pcapkit.protocols.link.radiotap import Radiotap
        from pcapkit.protocols.misc.raw import Raw

        word0 = (1 << 31) | 0b1
        word1 = 0b10
        # it_len=8 claims only the fixed start, but word0's bit 31 means a
        # second present-flags word genuinely follows on the wire.
        raw = _radiotap(8, [word0, word1]) + b'\xaa\xbb'
        parsed = Radiotap(raw, len(raw))
        self.assertEqual(parsed.info.it_len, 8)
        self.assertEqual(parsed.info.present, (word0, word1))
        self.assertEqual(parsed.info.fields, b'')
        self.assertIsInstance(parsed.payload, Raw)
        self.assertEqual(parsed.payload.data, b'\xaa\xbb')
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_malformed_it_len_larger_than_what_was_captured(self) -> None:
        """``it_len`` claims more octets than the capture actually holds
        (fully captured, just internally inconsistent -- distinct from a
        genuinely short capture, covered below). Nothing is decoded past
        what is there, and the payload is empty rather than negative-length.
        """
        from pcapkit.protocols.link.radiotap import Radiotap
        from pcapkit.protocols.misc.null import NoPayload

        raw = _radiotap(200, [0]) + b'\x01\x02\x03'
        parsed = Radiotap(raw, len(raw))
        self.assertEqual(parsed.info.it_len, 200)
        self.assertEqual(parsed.info.present, (0,))
        self.assertEqual(parsed.info.fields, b'\x01\x02\x03')
        self.assertIsInstance(parsed.payload, NoPayload)
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_truncated_header_rebuilds_as_captured(self) -> None:
        """A capture ending inside the header -- the fixed start, the
        present-flags chain, or the field-data region -- must not blow up
        the parse, and rebuilds to exactly the octets captured. See
        ``tests/protocols/test_short_read_roundtrip_unit.py`` for the sweep
        that cuts this (and every other) family at every offset.
        """
        import warnings

        from pcapkit.protocols.link.radiotap import Radiotap

        word0 = (1 << 31) | 0b1
        word1 = 0b10
        fields = bytes.fromhex('aabbccdd')
        raw = _radiotap(16, [word0, word1], fields) + b'\x01\x02\x03'
        for keep in range(1, len(raw)):
            with self.subTest(keep=keep):
                cut = raw[:keep]
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    parsed = Radiotap(cut, len(cut))
                self.assertEqual(parsed.data, cut)
                self.assertEqual(Radiotap.from_data(parsed.info).data, cut)

    def test_make_then_parse_minimal(self) -> None:
        from pcapkit.protocols.link.radiotap import Radiotap

        made = Radiotap().data
        self.assertEqual(made, _radiotap(8, [0]))

        parsed = Radiotap(made, len(made))
        self.assertEqual(parsed.info.present, (0,))
        self._assert_rebuilds(parsed)

    def test_make_then_parse_with_fields_and_payload(self) -> None:
        from pcapkit.protocols.link.radiotap import Radiotap

        fields = bytes.fromhex('0102030405060708090a')
        mac = b'\xde\xad\xbe\xef' * 3
        made = Radiotap(present=(0b111,), fields=fields, payload=mac).data
        self.assertEqual(made, _radiotap(8 + len(fields), [0b111], fields) + mac)

        parsed = Radiotap(made, len(made))
        self.assertEqual(parsed.info.fields, fields)
        self.assertEqual(type(parsed.payload).__name__, 'Raw')
        self.assertEqual(parsed.payload.data, mac)
        self._assert_rebuilds(parsed)

    def test_make_then_parse_extended_presence(self) -> None:
        from pcapkit.protocols.link.radiotap import Radiotap

        word0 = (1 << 31) | 0b1
        word1 = 0b10
        made = Radiotap(present=(word0, word1)).data
        self.assertEqual(made, _radiotap(12, [word0, word1]))

        parsed = Radiotap(made, len(made))
        self.assertEqual(parsed.info.present, (word0, word1))
        self._assert_rebuilds(parsed)

    def test_make_computes_it_len_from_present_and_fields(self) -> None:
        from pcapkit.protocols.link.radiotap import Radiotap

        made = Radiotap(present=(0, 0), fields=bytes(5), payload=bytes(3))
        self.assertEqual(made.info.it_len, 8 + 4 + 5)

    def test_make_explicit_it_len_is_written_as_given(self) -> None:
        """An explicit ``it_len`` is written as given, not recomputed -- the
        same reason :meth:`UDP.make <pcapkit.protocols.transport.udp.UDP.make>`
        keeps an explicit ``total_length`` (:issue:`1155`), and
        :meth:`Netlink.make <pcapkit.protocols.link.netlink.Netlink.make>`
        keeps an explicit ``nlmsg_len``.
        """
        from pcapkit.protocols.link.radiotap import Radiotap

        made = Radiotap(it_len=999)
        self.assertEqual(made.info.it_len, 999)

    def test_make_rejects_what_does_not_fit(self) -> None:
        from pcapkit.protocols.link.radiotap import Radiotap
        from pcapkit.utilities.exceptions import ProtocolError

        for kwargs in (
            {'it_version': -1}, {'it_version': 0x100}, {'it_version': True},
            {'it_pad': -1}, {'it_pad': 0x100},
            {'present': ()},
            {'present': (-1,)}, {'present': (0x1_0000_0000,)},
            {'fields': 'not bytes'},
            {'it_len': -1}, {'it_len': 0x1_0000}, {'it_len': True},
        ):
            with self.subTest(**kwargs), self.assertRaises(ProtocolError):
                Radiotap(**kwargs)

    def test_id_and_index(self) -> None:
        """``__index__`` is the ``arphrd_type`` LinuxSLL dispatches here (#2510)."""
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.link.linux_sll import LinuxSLL
        from pcapkit.protocols.link.radiotap import Radiotap

        self.assertEqual(Radiotap.id(), ('Radiotap',))
        self.assertIs(Radiotap.__index__(), ARPHRD.IEEE80211_RADIOTAP)
        self.assertEqual(Radiotap.__index__(), 803)
        self.assertIs(LinuxSLL._lookup_next_layer(LinuxSLL.__proto__, Radiotap.__index__()),
                      Radiotap)


if __name__ == '__main__':
    unittest.main()
