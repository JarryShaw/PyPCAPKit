# -*- coding: utf-8 -*-
"""L2TPv2 accepts only the version nibble :rfc:`2661` fixes.

GitHub issue #548 reported that IANA protocol number 115 (``TransType.L2TP``)
is registered nowhere, so an L2TP-over-IP capture falls through to
:class:`~pcapkit.protocols.misc.raw.Raw`, and proposed binding
:class:`~pcapkit.protocols.link.l2tpv2.L2TPv2` there. Measurement says that
binding would be wrong, and these tests are what pin that down.

:rfc:`3931` §4.1.1 ("L2TPv3 over IP") is what protocol 115 designates:
*"L2TPv3 over IP (both versions) utilizes the IANA-assigned IP protocol ID
115."* The same section notes the v3 session header over IP is *"free of any
restrictions imposed by coexistence with L2TPv2 and L2F"* -- meaning that over
IP a v3 **data** message opens with the raw Session ID and carries no version
nibble anywhere. So 115 is not a second door onto the :rfc:`2661` framing
:class:`L2TPv2` implements; it is a different header that only an ``L2TPv3``
class can read, and no such class exists in this tree.

What *was* genuinely missing is the guard that makes that reasoning
enforceable.
:attr:`L2TPv2.version <pcapkit.protocols.link.l2tpv2.L2TPv2.version>`
is annotated ``Literal[2]``, returns a hard-coded ``2``, and its
docstring already promises that *"a datagram carrying any other value is a
different protocol reached through a different class"* -- but
:meth:`~pcapkit.protocols.link.l2tpv2.L2TPv2.read` stored the wire nibble
unchecked, so the class reported ``version == 2`` while its own parsed data
reported ``3`` for the same octets. These tests hold the two to the same
answer.

Every case builds its own octets in memory and reads no capture under
:file:`examples/captures/`, so this belongs to the unit tier.

"""
from __future__ import annotations

import importlib.util
import io
import os
import struct
import tempfile
import unittest

from tests._support import close_extractor, purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


def l2tp_data(version: 'int' = 2) -> bytes:
    """An L2TPv2 data message with every optional field absent.

    Matches :func:`tests.protocols.test_dispatch_bindings_unit.l2tp_data` and
    :data:`examples.generators.dispatch._L2TP_DATA` at ``version=2``; the
    parameter exists so a case can put a *different* nibble in bits 12-15
    while holding every other octet identical.

    """
    # bit0=type, bit1=len, bit4=seq, bit6=offset, bit7=prio, bits12-15=version
    return struct.pack('!HHH', version, 0x1234, 0x5678) + b'\xff\x03\x00\x21PPP'


def l2tpv3_over_ip_data() -> bytes:
    """An :rfc:`3931` §4.1.1 L2TPv3-over-IP data message.

    Over IP the v3 session header opens with the 32-bit Session ID -- there is
    no flags word and no version nibble to inspect, which is precisely why a
    v2 parser cannot decline this by reading a version field.

    """
    return struct.pack('!I', 0x12345678) + b'\xff\x03\x00\x21' + b'PPPPAYLOAD'


def ipv4(proto: 'int', payload: bytes) -> bytes:
    """A minimal IPv4 header carrying ``payload`` under protocol ``proto``."""
    total = 20 + len(payload)
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 1, 0, 64, proto, 0,
                       bytes((10, 0, 0, 1)), bytes((10, 0, 0, 2))) + payload


def ethernet(etype: 'int', payload: bytes) -> bytes:
    """A minimal Ethernet II header carrying ``payload`` under ``etype``."""
    return (b'\x00\x11\x22\x33\x44\x55' + b'\x66\x77\x88\x99\xAA\xBB'
            + struct.pack('!H', etype) + payload)


def make_pcap(*frames: bytes) -> str:
    """Write ``frames`` to a little-endian LINKTYPE_ETHERNET PCAP file."""
    path = os.path.join(tempfile.mkdtemp(prefix='pcapkit-l2tp-'), 'l2tp.pcap')
    with open(path, 'wb') as file:
        # little endian, v2.4, LINKTYPE_ETHERNET
        file.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for index, frame in enumerate(frames):
            file.write(struct.pack('<IIII', 1600000000 + index, 0,
                                   len(frame), len(frame)))
            file.write(frame)
    return path


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class L2TPVersionTests(unittest.TestCase):
    """:class:`L2TPv2` parses version 2 and refuses everything else."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def parse(self, data: bytes):
        """Parse ``data`` as :class:`L2TPv2` directly, with no dispatch."""
        from pcapkit.protocols.link.l2tpv2 import L2TPv2

        return L2TPv2(io.BytesIO(data), len(data))

    def extract(self, *frames: bytes):
        """Extract synthesised ``frames`` and return the frame list."""
        import pcapkit

        extraction = pcapkit.extract(fin=make_pcap(*frames), nofile=True,
                                     store=True)
        self.addCleanup(close_extractor, extraction)
        return extraction.frame

    ##########################################################################
    # The version nibble.
    ##########################################################################

    def test_version_two_still_parses(self) -> None:
        """The RFC 2661 framing is unaffected -- this is the regression guard."""
        l2tp = self.parse(l2tp_data(2))

        self.assertEqual(l2tp.version, 2)
        self.assertEqual(l2tp.info.version, 2)
        self.assertEqual(l2tp.info.tunnelid, 0x1234)
        self.assertEqual(l2tp.info.sessionid, 0x5678)

    def test_a_version_nibble_other_than_two_is_refused(self) -> None:
        """:rfc:`2661` §3.1 fixes ``Ver`` at 2, so 0, 1 and 3 are not L2TPv2.

        Version 1 is reserved by :rfc:`2661` §3.1 *"to permit detection of L2F
        packets should they arrive intermixed with L2TP packets"*, and version
        3 is :rfc:`3931`. Neither is this class's protocol, and the nibble is
        the only thing in the header that says so.

        """
        from pcapkit.utilities.exceptions import ProtocolError

        for version in (0, 1, 3, 4, 15):
            with self.subTest(version=version):
                with self.assertRaises(ProtocolError) as caught:
                    self.parse(l2tp_data(version))
                self.assertIn('version', str(caught.exception).lower())

    def test_no_accepted_datagram_disagrees_with_the_version_property(self) -> None:
        """``L2TPv2.version`` and ``info.version`` cannot report different numbers.

        Before this guard the class answered ``version == 2`` from a hard-coded
        ``Literal[2]`` property while ``info.version`` carried whatever the
        wire said, so one datagram had two versions depending on which
        attribute a consumer read.

        """
        from pcapkit.utilities.exceptions import ProtocolError

        for version in range(16):
            with self.subTest(version=version):
                try:
                    l2tp = self.parse(l2tp_data(version))
                except ProtocolError:
                    continue  # refused, so it reports nothing at all
                self.assertEqual(l2tp.version, l2tp.info.version)

    ##########################################################################
    # Issue #548: IP protocol 115.
    ##########################################################################

    def test_ip_protocol_115_has_no_class_to_dispatch_to(self) -> None:
        """115 is :rfc:`3931` L2TPv3 over IP, and no ``L2TPv3`` class exists.

        The companion assertion to
        :meth:`tests.protocols.test_dispatch_bindings_unit.DispatchBindingTests.test_l2tp_over_ip_waits_on_an_l2tpv3_class`,
        kept next to the version guard because the guard is what makes the
        reasoning enforceable rather than merely asserted.

        """
        import pkgutil

        import pcapkit.protocols.link as linkpkg
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.internet import Internet

        self.assertEqual(int(TransType.L2TP), 115)
        self.assertNotIn(TransType.L2TP, Internet.__proto__)

        modules = {info.name for info in pkgutil.iter_modules(linkpkg.__path__)}
        self.assertIn('l2tpv2', modules)
        self.assertNotIn('l2tpv3', modules)

    def test_l2tpv3_over_ip_degrades_to_raw_rather_than_a_fabricated_header(self) -> None:
        """Binding ``L2TPv2`` at 115 must not invent an L2TPv2 header.

        This is the acceptance test for issue #548's actual resolution. It
        performs the registration the issue asked for -- and that
        :func:`~pcapkit.foundation.registry.protocols.register_protocol_code`
        once documented as its worked example -- then feeds it a genuine
        :rfc:`3931` §4.1.1 v3-over-IP data message.

        Measured before the version guard landed, that combination reported
        ``version=4``, ``tunnelid=0x5678`` and ``sessionid=0xff03``: a
        confident header assembled out of the top half of a Session ID and the
        first two octets of a PPP frame. Degrading to
        :class:`~pcapkit.protocols.misc.raw.Raw` is the honest answer, and is
        what the library does for any payload it has no dissector for.

        """
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.link.l2tpv2 import L2TPv2

        snapshot = dict(Internet.__proto__)
        self.addCleanup(lambda: (Internet.__proto__.clear(),
                                 Internet.__proto__.update(snapshot)))
        Internet.register(TransType.L2TP, L2TPv2)

        payload = l2tpv3_over_ip_data()
        frame = self.extract(ethernet(0x0800, ipv4(115, payload)))[0]
        ipv4_info = frame.info.to_dict()['ethernet']['ipv4']

        # No fabricated L2TPv2 header: the payload stays opaque.
        self.assertNotIn('l2tp', ipv4_info)
        self.assertNotIn('L2TPv2', str(frame.protochain))

        # It degrades through :func:`~pcapkit.utilities.decorators.beholder`,
        # which re-parses as ``Raw`` and passes ``alias=proto`` -- so an
        # enumeration key renders under its own name rather than as ``Raw``,
        # per that function's own note. The payload is preserved verbatim and
        # the reason is recorded, which is the whole point of degrading.
        self.assertEqual(str(frame.protochain), 'Ethernet:IPv4:L2TP')
        self.assertEqual(ipv4_info['raw']['protocol'], TransType.L2TP)
        self.assertEqual(ipv4_info['raw']['packet'], payload)
        self.assertIn('invalid version', ipv4_info['raw']['error'])

    def test_l2tpv3_over_udp_1701_no_longer_parses_as_l2tpv2(self) -> None:
        """:rfc:`3931` §4.1.2 puts L2TPv3 on port 1701 too, and that is a live capture.

        This is the part of the change that fixes a real dissection rather than
        guarding a hypothetical registration: port 1701 is bound today, so
        before the version guard a v3 datagram arriving on it was dissected as
        L2TPv2 and reported ``tunnelid=0x1234``/``sessionid=0x5678`` read out
        of v3's Control Connection ID. :rfc:`3931` §3.2.1 requires ``Ver`` to
        be 3, so the nibble is exactly the signal that this is not v2.

        """
        def udp(src: 'int', dst: 'int', payload: bytes) -> bytes:
            return struct.pack('!HHHH', src, dst, 8 + len(payload), 0) + payload

        payload = l2tp_data(3)
        frame = self.extract(ethernet(
            0x0800, ipv4(17, udp(1701, 1701, payload)),
        ))[0]
        udp_info = frame.info.to_dict()['ethernet']['ipv4']['udp']

        self.assertEqual(str(frame.protochain), 'Ethernet:IPv4:UDP:Raw')
        self.assertNotIn('l2tp', udp_info)
        # A bare port is not an enumeration, so this one does render as ``Raw``.
        self.assertEqual(udp_info['raw']['protocol'], 1701)
        self.assertEqual(udp_info['raw']['packet'], payload)

    def test_udp_port_1701_is_unaffected_by_the_guard(self) -> None:
        """The encapsulation that *is* L2TPv2's still dissects end to end.

        :rfc:`2661` puts L2TPv2 on UDP port 1701, which is the binding
        ``UDP.__proto__`` already carries and the one this change must leave
        alone.

        """
        def udp(src: 'int', dst: 'int', payload: bytes) -> bytes:
            return struct.pack('!HHHH', src, dst, 8 + len(payload), 0) + payload

        frame = self.extract(ethernet(
            0x0800, ipv4(17, udp(1701, 1701, l2tp_data(2))),
        ))[0]

        self.assertEqual(str(frame.protochain), 'Ethernet:IPv4:UDP:L2TPv2:Raw')
        l2tp = frame.info.to_dict()['ethernet']['ipv4']['udp']['l2tp']
        self.assertEqual(l2tp['version'], 2)
        self.assertEqual(l2tp['tunnelid'], 0x1234)
        self.assertEqual(l2tp['sessionid'], 0x5678)


if __name__ == '__main__':
    unittest.main()
