# -*- coding: utf-8 -*-
"""GitHub issue #2500: Linux Netlink socket framing (``nlmsghdr``).

:class:`~pcapkit.protocols.link.netlink.Netlink` dissects the ``arphrd_type``
``ARPHRD_NETLINK`` payload that
:class:`~pcapkit.protocols.link.linux_sll.LinuxSLL` previously kept whole as
:class:`~pcapkit.protocols.misc.raw.Raw` (see
:attr:`LinuxSLL.__proto__ <pcapkit.protocols.link.linux_sll.LinuxSLL.__proto__>`). Covers the
16-octet ``nlmsghdr`` fields, the byte-order heuristic
:func:`~pcapkit.protocols.link.netlink.nlmsg_byteorder` resolves (see
:rfc:`3549#section-2.3.2`), and byte-exact round trips. The NETLINK-dispatch
side of ``LinuxSLL1``/``LinuxSLL2`` is covered in their own test modules.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`.

"""

import struct
import unittest

from tests._support import reimport_once_per_class


def _nlmsghdr(byteorder: str, nlmsg_type: int = 0, nlmsg_flags: int = 0,
             nlmsg_seq: int = 0, nlmsg_pid: int = 0, payload: bytes = b'',
             nlmsg_len: 'int | None' = None) -> bytes:
    """Pack a bare ``nlmsghdr`` plus ``payload`` in the given byte order."""
    if nlmsg_len is None:
        nlmsg_len = 16 + len(payload)
    fmt = ('<' if byteorder == 'little' else '>') + 'IHHII'
    return struct.pack(fmt, nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid) + payload


class TestNetlink(unittest.TestCase):
    """Pin the Netlink layer, alone."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _assert_rebuilds(self, layer, **kwargs) -> None:  # type: ignore[no-untyped-def]
        """``layer`` rebuilds byte-exactly from its info, and from ``info.to_dict()``."""
        for data in (layer.info, layer.info.to_dict()):
            with self.subTest(layer=type(layer).__name__, data=type(data).__name__):
                self.assertEqual(type(layer).from_data(data, **kwargs).data.hex(), layer.data.hex())

    def test_little_endian_header_decodes_every_field(self) -> None:
        from pcapkit.protocols.link.netlink import Netlink

        raw = _nlmsghdr('little', nlmsg_type=3, nlmsg_flags=0x0101, nlmsg_seq=42,
                        nlmsg_pid=1234, payload=b'\xaa\xbb\xcc\xdd')
        parsed = Netlink(raw, len(raw))
        self.assertEqual(parsed.info.nlmsg_len, 20)
        self.assertEqual(parsed.info.nlmsg_type, 3)
        self.assertEqual(parsed.info.nlmsg_flags, 0x0101)
        self.assertEqual(parsed.info.nlmsg_seq, 42)
        self.assertEqual(parsed.info.nlmsg_pid, 1234)
        self.assertEqual(parsed.info.byteorder, 'little')
        self.assertEqual(parsed.protocol, 3)
        self.assertEqual((parsed.name, parsed.alias, parsed.length), ('Netlink', 'Netlink', 16))
        self.assertEqual(type(parsed.payload).__name__, 'Raw')
        self.assertEqual(parsed.payload.data, b'\xaa\xbb\xcc\xdd')
        self.assertEqual(parsed.protochain.chain, 'Netlink:Raw')
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_big_endian_header_is_detected_by_heuristic(self) -> None:
        """A length field that only makes sense read big-endian is read
        that way, per :func:`~pcapkit.protocols.link.netlink.nlmsg_byteorder`.
        """
        from pcapkit.protocols.link.netlink import Netlink

        raw = _nlmsghdr('big', nlmsg_type=16, nlmsg_flags=5, nlmsg_seq=7,
                        nlmsg_pid=0, payload=b'\x01\x02\x03\x04\x05\x06')
        parsed = Netlink(raw, len(raw))
        self.assertEqual(parsed.info.byteorder, 'big')
        self.assertEqual(parsed.info.nlmsg_len, 22)
        self.assertEqual(parsed.info.nlmsg_type, 16)
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_heuristic_matches_wireshark_on_both_byteorders_of_the_same_payload(self) -> None:
        """The same field values, packed each way, are read back the same
        way they were packed -- the heuristic is not biased toward one
        reading regardless of the octets.
        """
        from pcapkit.protocols.link.netlink import Netlink

        for byteorder in ('little', 'big'):
            with self.subTest(byteorder=byteorder):
                raw = _nlmsghdr(byteorder, nlmsg_type=1, nlmsg_flags=0, nlmsg_seq=99,
                                nlmsg_pid=500, payload=bytes(32))
                parsed = Netlink(raw, len(raw))
                self.assertEqual(parsed.info.byteorder, byteorder)
                self.assertEqual(parsed.info.nlmsg_seq, 99)
                self.assertEqual(parsed.info.nlmsg_pid, 500)
                self._assert_rebuilds(parsed)

    def test_payload_is_always_raw_regardless_of_type(self) -> None:
        """Per-family payload decoding is out of scope: every ``nlmsg_type``,
        including the generic control values, resolves to
        :class:`~pcapkit.protocols.misc.raw.Raw`.
        """
        from pcapkit.protocols.link.netlink import Netlink
        from pcapkit.protocols.misc.raw import Raw

        # NLMSG_NOOP, NLMSG_ERROR, NLMSG_DONE, NLMSG_OVERRUN, and a
        # family-specific value (RTM_NEWLINK = 16, NETLINK_ROUTE's own).
        for nlmsg_type in (1, 2, 3, 4, 16):
            with self.subTest(nlmsg_type=nlmsg_type):
                raw = _nlmsghdr('little', nlmsg_type=nlmsg_type, payload=b'\x00\x00\x00\x00')
                parsed = Netlink(raw, len(raw))
                self.assertEqual(parsed.info.nlmsg_type, nlmsg_type)
                self.assertIsInstance(parsed.payload, Raw)
                self.assertEqual(parsed.protochain.chain, 'Netlink:Raw')
                self._assert_rebuilds(parsed)

    def test_zero_length_payload_is_no_payload(self) -> None:
        from pcapkit.protocols.link.netlink import Netlink
        from pcapkit.protocols.misc.null import NoPayload

        raw = _nlmsghdr('little', nlmsg_type=3)
        parsed = Netlink(raw, len(raw))
        self.assertEqual(parsed.info.nlmsg_len, 16)
        self.assertIsInstance(parsed.payload, NoPayload)
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_make_then_parse(self) -> None:
        from pcapkit.protocols.link.netlink import Netlink

        made = Netlink(nlmsg_type=3, nlmsg_flags=0x0101, nlmsg_seq=1, nlmsg_pid=0,
                      byteorder='little', payload=b'\xaa\xbb\xcc\xdd').data
        self.assertEqual(made, _nlmsghdr('little', nlmsg_type=3, nlmsg_flags=0x0101,
                                         nlmsg_seq=1, nlmsg_pid=0, payload=b'\xaa\xbb\xcc\xdd'))

        parsed = Netlink(made, len(made))
        self.assertEqual(parsed.info.nlmsg_type, 3)
        self.assertEqual(type(parsed.payload).__name__, 'Raw')
        self._assert_rebuilds(parsed)

    def test_make_computes_nlmsg_len_from_payload(self) -> None:
        from pcapkit.protocols.link.netlink import Netlink

        made = Netlink(payload=bytes(10))
        self.assertEqual(made.info.nlmsg_len, 26)

    def test_make_defaults(self) -> None:
        import sys

        from pcapkit.protocols.link.netlink import Netlink

        made = Netlink()
        self.assertEqual(made.data, struct.pack(
            ('<' if sys.byteorder == 'little' else '>') + 'IHHII', 16, 0, 0, 0, 0))

    def test_make_explicit_byteorder_round_trips(self) -> None:
        from pcapkit.protocols.link.netlink import Netlink

        for byteorder in ('little', 'big'):
            with self.subTest(byteorder=byteorder):
                made = Netlink(nlmsg_type=5, byteorder=byteorder, payload=b'\x01\x02')
                self.assertEqual(made.data, _nlmsghdr(byteorder, nlmsg_type=5, payload=b'\x01\x02'))
                parsed = Netlink(made.data, len(made.data))
                self.assertEqual(parsed.info.byteorder, byteorder)
                self.assertEqual(parsed.info.nlmsg_type, 5)

    def test_make_rejects_invalid_byteorder(self) -> None:
        from pcapkit.protocols.link.netlink import Netlink
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError):
            Netlink(byteorder='middle')  # type: ignore[arg-type]

    def test_make_rejects_what_does_not_fit(self) -> None:
        from pcapkit.protocols.link.netlink import Netlink
        from pcapkit.utilities.exceptions import ProtocolError

        for kwargs in (
            {'nlmsg_type': -1}, {'nlmsg_type': 0x1_0000}, {'nlmsg_type': True},
            {'nlmsg_flags': -1}, {'nlmsg_flags': 0x1_0000},
            {'nlmsg_seq': -1}, {'nlmsg_seq': 0x1_0000_0000},
            {'nlmsg_pid': -1}, {'nlmsg_pid': 0x1_0000_0000},
            {'nlmsg_len': -1}, {'nlmsg_len': 0x1_0000_0000}, {'nlmsg_len': True},
        ):
            with self.subTest(**kwargs), self.assertRaises(ProtocolError):
                Netlink(**kwargs)

    def test_make_explicit_nlmsg_len_is_written_as_given(self) -> None:
        """An explicit ``nlmsg_len`` is written as given, not recomputed --
        the same reason :meth:`UDP.make <pcapkit.protocols.transport.udp.UDP.make>`
        keeps an explicit ``total_length`` (:issue:`1155`).
        """
        from pcapkit.protocols.link.netlink import Netlink

        made = Netlink(nlmsg_len=999, payload=b'\x01\x02')
        self.assertEqual(made.info.nlmsg_len, 999)

    def test_id_and_index(self) -> None:
        """``__index__`` is the ``arphrd_type`` LinuxSLL dispatches here (#2510)."""
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.link.linux_sll import LinuxSLL
        from pcapkit.protocols.link.netlink import Netlink

        self.assertEqual(Netlink.id(), ('Netlink',))
        self.assertIs(Netlink.__index__(), ARPHRD.NETLINK)
        self.assertEqual(Netlink.__index__(), 824)
        self.assertIs(LinuxSLL._lookup_next_layer(LinuxSLL.__proto__, Netlink.__index__()),
                      Netlink)

    def test_truncated_header_rebuilds_as_captured(self) -> None:
        """A capture ending inside the header must not blow up the parse, and
        rebuilds to exactly the octets captured. See
        ``tests/protocols/test_short_read_roundtrip_unit.py`` for the sweep
        that cuts this (and every other) family at every offset.
        """
        import warnings

        from pcapkit.protocols.link.netlink import Netlink

        raw = _nlmsghdr('little', nlmsg_type=3, payload=b'\xaa\xbb\xcc\xdd')
        for keep in (1, 2, 3, 4, 8, 15):
            with self.subTest(keep=keep):
                cut = raw[:keep]
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    parsed = Netlink(cut, len(cut))
                self.assertEqual(parsed.data, cut)
                self.assertEqual(Netlink.from_data(parsed.info).data, cut)


if __name__ == '__main__':
    unittest.main()
