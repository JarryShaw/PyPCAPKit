# -*- coding: utf-8 -*-
"""GitHub issue #2460: Frame Relay Access Device (FRAD) frames.

:class:`~pcapkit.protocols.link.frad.FRAD` dissects the ``arphrd_type``
``ARPHRD_FRAD`` payload that
:class:`~pcapkit.protocols.link.linux_sll.LinuxSLL` previously kept whole as
:class:`~pcapkit.protocols.misc.raw.Raw` (see
:attr:`LinuxSLL.__proto__ <pcapkit.protocols.link.linux_sll.LinuxSLL.__proto__>`). Covers the
Q.922 address field, the direct-NLPID and SNAP-encapsulated forms per
:rfc:`2427`, and byte-exact round trips. The FRAD-dispatch side of
``LinuxSLL1``/``LinuxSLL2`` is covered in their own test modules.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`.

"""

import unittest

from tests._support import reimport_once_per_class

#: An IPv4 header (DF clear, protocol UDP) and an 8-octet UDP header.
IPV4 = (bytes.fromhex('4500001c00010000401100000a0000010a000002')
        + bytes.fromhex('3039003500080000'))
#: An IPv6 header (next header UDP) and an 8-octet UDP header.
IPV6 = (bytes.fromhex('6000000000081140') + bytes(15) + b'\x01' + bytes(15) + b'\x02'
        + bytes.fromhex('3039003500080000'))
#: A minimal ARP request (RFC 826), 28 octets.
ARP_REQUEST = (bytes.fromhex('00010800060400010011223344550a000001')
               + bytes.fromhex('0000000000000a000002'))

#: The Q.922 address RFC 2427 section 3 uses as its own worked example: DLCI 50.
DLCI_50 = bytes.fromhex('0c21')


def _direct(nlpid: int, payload: bytes, addr: bytes = DLCI_50, control: int = 0x03) -> bytes:
    """A direct-NLPID FRAD frame: address, control, one NLPID octet, payload."""
    return addr + bytes([control, nlpid]) + payload


def _snap(oui: bytes, pid: int, payload: bytes, addr: bytes = DLCI_50,
          control: int = 0x03) -> bytes:
    """A SNAP-encapsulated FRAD frame: pad, 0x80, 3-octet OUI, 2-octet PID."""
    return addr + bytes([control, 0x00, 0x80]) + oui + pid.to_bytes(2, 'big') + payload


class TestFRAD(unittest.TestCase):
    """Pin the FRAD layer, alone."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _assert_rebuilds(self, layer, **kwargs) -> None:  # type: ignore[no-untyped-def]
        """``layer`` rebuilds byte-exactly from its info, and from ``info.to_dict()``."""
        for data in (layer.info, layer.info.to_dict()):
            with self.subTest(layer=type(layer).__name__, data=type(data).__name__):
                self.assertEqual(type(layer).from_data(data, **kwargs).data.hex(), layer.data.hex())

    def test_address_field_decodes_the_rfc_example(self) -> None:
        """RFC 2427 section 3's own example: DLCI 50 packs as ``0x0C21``."""
        from pcapkit.protocols.link.frad import FRAD

        raw = _direct(0xCC, IPV4)
        parsed = FRAD(raw, len(raw))
        self.assertEqual(parsed.info.dlci, 50)
        self.assertEqual((parsed.info.cr, parsed.info.fecn, parsed.info.becn, parsed.info.de),
                         (0, 0, 0, 0))
        self.assertEqual(parsed.info.control, 0x03)
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_direct_nlpid_dispatches_ipv4_and_ipv6(self) -> None:
        from pcapkit.protocols.link.frad import FRAD

        for nlpid, payload, name in ((0xCC, IPV4, 'IPv4'), (0x8E, IPV6, 'IPv6')):
            with self.subTest(nlpid=hex(nlpid)):
                raw = _direct(nlpid, payload)
                parsed = FRAD(raw, len(raw))
                self.assertEqual(parsed.info.nlpid, nlpid)
                self.assertIsNone(parsed.info.snap_oui)
                self.assertIsNone(parsed.info.snap_pid)
                self.assertEqual(parsed.protocol, nlpid)
                self.assertEqual((parsed.name, parsed.alias, parsed.length),
                                 ('Frame Relay Access Device', 'FRAD', 4))
                self.assertEqual(type(parsed.payload).__name__, name)
                self.assertEqual(parsed.protochain.chain, f'FRAD:{name}:UDP')
                self.assertEqual(parsed.data, raw)
                self._assert_rebuilds(parsed)

    def test_snap_with_zero_oui_dispatches_by_ethertype(self) -> None:
        """A SNAP header whose OUI is ``00-00-00`` carries an EtherType in its
        PID -- ARP's own, ``0x0806`` -- resolved through the family registry
        Ethernet/VLAN/LinuxSLL share, not through :attr:`FRAD.__proto__
        <pcapkit.protocols.link.frad.FRAD.__proto__>`.
        """
        from pcapkit.protocols.link.frad import FRAD

        raw = _snap(b'\x00\x00\x00', 0x0806, ARP_REQUEST)
        parsed = FRAD(raw, len(raw))
        self.assertEqual(parsed.info.nlpid, 0x80)
        self.assertEqual(parsed.info.snap_oui, b'\x00\x00\x00')
        self.assertEqual(parsed.info.snap_pid, 0x0806)
        self.assertEqual(parsed.length, 10)
        self.assertEqual(type(parsed.payload).__name__, 'ARP')
        self.assertEqual(parsed.protochain.chain, 'FRAD:ARP')
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_snap_with_nonzero_oui_is_kept_raw(self) -> None:
        """A SNAP header naming a bridged medium (OUI ``00-80-C2``, :rfc:`2427`
        section 4.2) is not a bridging dissector this class implements, so it
        is kept as :class:`~pcapkit.protocols.misc.raw.Raw`, OUI and PID
        intact in :attr:`~pcapkit.protocols.data.link.frad.FRAD.snap_oui` /
        :attr:`~pcapkit.protocols.data.link.frad.FRAD.snap_pid`.
        """
        from pcapkit.protocols.link.frad import FRAD
        from pcapkit.protocols.misc.raw import Raw

        raw = _snap(b'\x00\x80\xc2', 0x0001, IPV4)
        parsed = FRAD(raw, len(raw))
        self.assertEqual(parsed.info.snap_oui, b'\x00\x80\xc2')
        self.assertEqual(parsed.info.snap_pid, 0x0001)
        self.assertIsInstance(parsed.payload, Raw)
        self.assertEqual(parsed.protochain.chain, 'FRAD:Raw')
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_every_other_nlpid_is_kept_raw(self) -> None:
        """Q.933 (``0x08``), ISO CLNP/ES-IS/IS-IS (``0x81``/``0x82``/``0x83``),
        FRF.9/FRF.12 (``0xB0``/``0xB1``) and PPP-in-Frame-Relay (``0xCF``), per
        :rfc:`2427` Appendix A, have no dissector in this package.
        """
        from pcapkit.protocols.link.frad import FRAD
        from pcapkit.protocols.misc.raw import Raw

        for nlpid in (0x08, 0x81, 0x82, 0x83, 0xB0, 0xB1, 0xCF):
            with self.subTest(nlpid=hex(nlpid)):
                raw = _direct(nlpid, IPV4)
                parsed = FRAD(raw, len(raw))
                self.assertEqual(parsed.info.nlpid, nlpid)
                self.assertIsInstance(parsed.payload, Raw)
                self.assertEqual(parsed.protochain.chain, 'FRAD:Raw')
                self.assertEqual(parsed.data, raw)
                self._assert_rebuilds(parsed)

    def test_make_then_parse_direct(self) -> None:
        from pcapkit.protocols.link.frad import FRAD

        made = FRAD(dlci=50, nlpid=0xCC, payload=IPV4).data
        self.assertEqual(made, _direct(0xCC, IPV4))

        parsed = FRAD(made, len(made))
        self.assertEqual(parsed.info.dlci, 50)
        self.assertEqual(type(parsed.payload).__name__, 'IPv4')
        self._assert_rebuilds(parsed)

    def test_make_then_parse_snap(self) -> None:
        from pcapkit.protocols.link.frad import FRAD

        made = FRAD(dlci=50, nlpid=0x80, snap_oui=b'\x00\x00\x00', snap_pid=0x0806,
                   payload=ARP_REQUEST).data
        self.assertEqual(made, _snap(b'\x00\x00\x00', 0x0806, ARP_REQUEST))

        parsed = FRAD(made, len(made))
        self.assertEqual(type(parsed.payload).__name__, 'ARP')
        self._assert_rebuilds(parsed)

    def test_make_defaults(self) -> None:
        from pcapkit.protocols.link.frad import FRAD

        # dlci=0, with ea2=1 per the 2-octet address form: 0x00 0x01.
        self.assertEqual(FRAD().data, b'\x00\x01\x03\xcc')

    def test_make_round_trips_every_bit_of_the_address(self) -> None:
        from pcapkit.protocols.link.frad import FRAD

        made = FRAD(dlci=1023, cr=1, fecn=1, becn=1, de=1, nlpid=0xCC, payload=IPV4)
        parsed = FRAD(made.data, len(made.data))
        self.assertEqual((parsed.info.dlci, parsed.info.cr, parsed.info.fecn,
                         parsed.info.becn, parsed.info.de), (1023, 1, 1, 1, 1))
        self._assert_rebuilds(parsed)

    def test_make_rejects_an_invalid_dlci(self) -> None:
        from pcapkit.protocols.link.frad import FRAD
        from pcapkit.utilities.exceptions import ProtocolError

        for dlci in (-1, 1024, True, '50'):
            with self.subTest(dlci=dlci), self.assertRaises(ProtocolError):
                FRAD(dlci=dlci)

    def test_make_rejects_an_invalid_flag_bit(self) -> None:
        # NOTE: True/False are not cases here -- bool is an int subclass and
        # True == 1, so a bit flag (unlike dlci, a numeric identifier) treats
        # it as a legitimate spelling of 1 rather than rejecting it.
        from pcapkit.protocols.link.frad import FRAD
        from pcapkit.utilities.exceptions import ProtocolError

        for kwargs in ({'cr': 2}, {'fecn': -1}, {'becn': 3}, {'de': 'x'}):
            with self.subTest(**kwargs), self.assertRaises(ProtocolError):
                FRAD(**kwargs)

    def test_make_tolerates_nlpid_zero_for_short_read_replay(self) -> None:
        """``0x00`` is the SNAP pad marker, never a value of its own on the
        wire, but :meth:`make` must not refuse it: see the ``Note`` on
        :meth:`FRAD.make <pcapkit.protocols.link.frad.FRAD.make>`.
        """
        from pcapkit.protocols.link.frad import FRAD

        FRAD(nlpid=0)  # must not raise

    def test_make_rejects_snap_fields_without_snap(self) -> None:
        from pcapkit.protocols.link.frad import FRAD
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError):
            FRAD(nlpid=0xCC, snap_oui=b'\x00\x00\x00')
        with self.assertRaises(ProtocolError):
            FRAD(nlpid=0xCC, snap_pid=0x0806)

    def test_make_rejects_snap_without_snap_fields(self) -> None:
        from pcapkit.protocols.link.frad import FRAD
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError):
            FRAD(nlpid=0x80)
        with self.assertRaises(ProtocolError):
            FRAD(nlpid=0x80, snap_oui=b'\x00\x00')  # wrong width
        with self.assertRaises(ProtocolError):
            FRAD(nlpid=0x80, snap_oui=b'\x00\x00\x00', snap_pid=0x1_0000)  # out of range

    def test_id_and_index(self) -> None:
        """``__index__`` is the ``arphrd_type`` LinuxSLL dispatches here (#2510)."""
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.link.linux_sll import LinuxSLL
        from pcapkit.protocols.link.frad import FRAD

        self.assertEqual(FRAD.id(), ('FRAD',))
        self.assertIs(FRAD.__index__(), ARPHRD.FRAD)
        self.assertEqual(FRAD.__index__(), 770)
        self.assertIs(LinuxSLL._lookup_next_layer(LinuxSLL.__proto__, FRAD.__index__()),
                      FRAD)

    def test_truncated_header_rebuilds_as_captured(self) -> None:
        """A capture ending inside the header must not blow up the parse, and
        rebuilds to exactly the octets captured. See
        ``tests/protocols/test_short_read_roundtrip_unit.py`` for the sweep
        that cuts this (and every other) family at every offset.
        """
        import warnings

        from pcapkit.protocols.link.frad import FRAD

        raw = _direct(0xCC, IPV4)
        for keep in (1, 2, 3):
            with self.subTest(keep=keep):
                cut = raw[:keep]
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    parsed = FRAD(cut, len(cut))
                self.assertEqual(parsed.data, cut)
                self.assertEqual(FRAD.from_data(parsed.info).data, cut)


if __name__ == '__main__':
    unittest.main()
