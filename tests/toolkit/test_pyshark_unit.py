from __future__ import annotations

import importlib.util
import unittest

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class FakeLayer:
    def __init__(self, layer_name: str, **fields: object) -> None:
        self.layer_name = layer_name
        self.field_names = tuple(fields)
        for name, value in fields.items():
            setattr(self, name, value)


class FakePySharkPacket:
    def __init__(self, *, ipv6: bool = False, tcp: bool = True,
                 ip: bool = True, ether: bool = True,
                 link_layer: str = 'eth') -> None:
        self.number = '12'
        self.frame_info = FakeLayer('frame', time_epoch=70.5, cap_len='54')
        self.layers = [
            # Real PyShark names a layer from the PDML ``<proto name>``
            # attribute, which is Wireshark's protocol *filter* name --
            # ``eth``, not ``ethernet`` -- so the fake has to match that or it
            # is not exercising what the real engine hands ``tcp_traceflow``.
            # That name is not a LinkType *member* name either, but
            # ``pcapkit.toolkit.pyshark.FILTER_NAME_TO_LINKTYPE`` now
            # translates the handful of filter names it can justify (``eth``,
            # ``tr``) before falling back to ``LinkType.get()`` -- see that
            # table's own comment for the evidence and for what was
            # deliberately left out. ``link_layer`` lets a test pick any
            # root-layer name, including one outside that table, without
            # duplicating this whole fake.
            FakeLayer(link_layer, src='aa:aa:aa:aa:aa:aa'),
            FakeLayer('ip', src='192.0.2.1', dst='198.51.100.1'),
            # ``flags_reset`` is PyShark's spelling of Wireshark's
            # ``tcp.flags.reset``, the field the RST flag comes from. ``seq`` and
            # ``ack`` are reported as strings too, like every PyShark field.
            FakeLayer('tcp', srcport='1234', dstport='80',
                      flags_syn='1', flags_fin='0', flags_reset='0',
                      seq='101', ack='202'),
        ]
        self._contains = set()
        if ip:
            if ipv6:
                self._contains.add('IPv6')
                self.ipv6 = FakeLayer('ipv6', src='2001:db8::1', dst='2001:db8::2')
                self.layers[1] = self.ipv6
            else:
                self._contains.add('IP')
                self.ip = FakeLayer('ip', src='192.0.2.1', dst='198.51.100.1')
        if tcp:
            self._contains.add('TCP')
            self.tcp = self.layers[2]
        else:
            self.layers = self.layers[:2]
        if not ether:
            # #775 tier 1 regression coverage: drop the Ethernet layer so
            # ``layers[0]`` -- what ``tcp_traceflow`` feeds the lookup -- is the
            # IP layer, whose ``layer_name`` is ``'ip'``, a name that is neither
            # in ``FILTER_NAME_TO_LINKTYPE`` nor a LinkType member. Note this is
            # a synthetic shape rather than a real capture's: a genuine raw-IP
            # capture roots at ``raw``, not ``ip`` (see that table's comment).
            # What is under test is the unknown-name path, which ``'ip'``
            # exercises regardless of how a capture would reach it.
            self.layers = self.layers[1:]

    def __contains__(self, name: str) -> bool:
        return name in self._contains


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PySharkToolkitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_packet2dict_nests_frame_and_layers(self) -> None:
        from pcapkit.toolkit import pyshark as toolkit

        packet = FakePySharkPacket()
        converted = toolkit.packet2dict(packet)
        self.assertEqual(converted['time_epoch'], 70.5)
        self.assertEqual(converted['ETH']['src'], 'aa:aa:aa:aa:aa:aa')
        self.assertEqual(converted['ETH']['IP']['src'], '192.0.2.1')
        self.assertEqual(converted['ETH']['IP']['TCP']['srcport'], '1234')

    def test_tcp_traceflow_negative_paths(self) -> None:
        """The ``ip=False``/``tcp=False`` short-circuits return ``None``
        before ``tcp_traceflow`` ever resolves a link type, so they are
        unaffected by #775 tier 1 dropping the ``LinkType.NULL`` default
        (see ``test_tcp_traceflow_raises_for_an_ip_rooted_packet`` and the
        ``FILTER_NAME_TO_LINKTYPE``-resolving tests below for that).

        """
        from pcapkit.toolkit import pyshark as toolkit

        self.assertIsNone(toolkit.tcp_traceflow(FakePySharkPacket(ip=False)))
        self.assertIsNone(toolkit.tcp_traceflow(FakePySharkPacket(tcp=False)))

    def test_tcp_traceflow_resolves_ethernet_via_filter_name_mapping(self) -> None:
        """PyShark's PDML filter name for the outermost layer of an ordinary
        Ethernet capture is ``eth``, not ``ETHERNET`` -- not a LinkType
        member name on its own. Per the ruling on #838,
        ``pcapkit.toolkit.pyshark.FILTER_NAME_TO_LINKTYPE`` now translates
        that filter name to :attr:`LinkType.ETHERNET` before
        :func:`tcp_traceflow` ever reaches ``Enum_LinkType.get()``, so this
        no longer raises the way it did prior to that table landing.

        """
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import pyshark as toolkit

        packet = FakePySharkPacket()
        self.assertEqual(packet.layers[0].layer_name, 'eth')

        data = toolkit.tcp_traceflow(packet)
        self.assertIsNotNone(data)
        self.assertEqual(data.protocol, LinkType.ETHERNET)

        # the IPv6-rooted capture hits the very same lookup, since
        # ``layers[0]`` is still the Ethernet layer either way
        data_v6 = toolkit.tcp_traceflow(FakePySharkPacket(ipv6=True))
        self.assertIsNotNone(data_v6)
        self.assertEqual(data_v6.protocol, LinkType.ETHERNET)

    def test_tcp_traceflow_resolves_token_ring_via_filter_name_mapping(self) -> None:
        """Wireshark's Token Ring dissector -- the ``DLT_IEEE802`` root layer
        -- files its PDML node under the filter name ``tr``, per
        ``packet-tr.c``'s ``proto_register_protocol("Token-Ring",
        "Token-Ring", "tr")`` (verified against the Wireshark source, no
        ``tshark``/PyShark binary being available on this host). That name
        is also not a LinkType member on its own, so it needs the same
        ``FILTER_NAME_TO_LINKTYPE`` entry as ``eth`` to resolve to
        :attr:`LinkType.IEEE802_5`.

        """
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import pyshark as toolkit

        packet = FakePySharkPacket(link_layer='tr')
        self.assertEqual(packet.layers[0].layer_name, 'tr')

        data = toolkit.tcp_traceflow(packet)
        self.assertIsNotNone(data)
        self.assertEqual(data.protocol, LinkType.IEEE802_5)

    def test_tcp_traceflow_raises_for_an_ip_rooted_packet(self) -> None:
        """``'ip'`` is absent from ``FILTER_NAME_TO_LINKTYPE`` and is not a
        LinkType member name either, so ``Enum_LinkType.get()`` misses too and
        this raises, exactly as it did before the mapping table landed.

        The double feeds ``'ip'`` as ``layers[0]`` to exercise that path. A real
        raw-IP capture would root at ``raw`` instead -- measured, and recorded in
        the table's own comment -- so this is the unknown-name guard rather than
        a reproduction of any particular capture shape.

        """
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import pyshark as toolkit
        from pcapkit.utilities.exceptions import MissingKeyError

        packet = FakePySharkPacket(ether=False)
        self.assertEqual(packet.layers[0].layer_name, 'ip')

        before = len(LinkType.__members__)
        with self.assertRaises(MissingKeyError) as ctx:
            toolkit.tcp_traceflow(packet)
        after = len(LinkType.__members__)

        self.assertEqual(ctx.exception.args[0], 'IP')
        self.assertEqual(before, after)

    def test_tcp_traceflow_raises_for_a_genuinely_unknown_name(self) -> None:
        """A link-layer filter name that is neither in
        ``FILTER_NAME_TO_LINKTYPE`` nor a LinkType member name under any
        case must still raise :exc:`MissingKeyError` rather than be papered
        over with a stand-in DLT -- the maintainer's ruling from #775 tier 1
        that this mapping does not relax.

        """
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import pyshark as toolkit
        from pcapkit.utilities.exceptions import MissingKeyError

        packet = FakePySharkPacket(link_layer='wobegon')
        self.assertEqual(packet.layers[0].layer_name, 'wobegon')

        before = len(LinkType.__members__)
        with self.assertRaises(MissingKeyError) as ctx:
            toolkit.tcp_traceflow(packet)
        after = len(LinkType.__members__)

        self.assertEqual(ctx.exception.args[0], 'WOBEGON')
        self.assertEqual(before, after)  # the miss must not grow the registry

    def test_tcp_traceflow_end_to_end_for_an_ethernet_capture(self) -> None:
        """With the link-layer name resolved, the rest of
        :func:`tcp_traceflow`'s ``TF_TCP_Packet`` construction is unaffected
        by this change -- check every field it fills in from the fake, not
        just ``protocol``, so a regression there is not masked by the two
        tests above only checking the new mapping.

        """
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import pyshark as toolkit

        packet = FakePySharkPacket()
        data = toolkit.tcp_traceflow(packet)

        self.assertIsNotNone(data)
        self.assertEqual(data.protocol, LinkType.ETHERNET)
        self.assertEqual(data.index, 12)
        self.assertEqual(str(data.src), '192.0.2.1')
        self.assertEqual(str(data.dst), '198.51.100.1')
        self.assertEqual(data.srcport, 1234)
        self.assertEqual(data.dstport, 80)
        self.assertTrue(data.syn)
        self.assertFalse(data.fin)
        self.assertFalse(data.rst)
        self.assertEqual(data.seq, 101)
        self.assertEqual(data.ack, 202)
        self.assertEqual(data.timestamp, 70.5)
        self.assertEqual(data.header, b'')
        self.assertEqual(data.payload, bytearray())


if __name__ == '__main__':
    unittest.main()
