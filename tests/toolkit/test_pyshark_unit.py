from __future__ import annotations

import importlib.util
import unittest

from tests._support import reimport_once_per_class

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
                 link_layer: str = 'eth', encap_type: 'str | None' = None) -> None:
        self.number = '12'
        frame_fields = {'time_epoch': 70.5, 'cap_len': '54'}  # type: dict[str, object]
        if encap_type is not None:
            # Real PyShark hands every PDML field over as a
            # ``LayerFieldsContainer``, which subclasses ``str`` -- so
            # ``frame.encap_type`` arrives as text, never as an ``int``, and the
            # fake has to match that or it would not exercise the ``int()`` the
            # toolkit needs. Left absent by default so the tests below that
            # predate it keep exercising the filter-name fallback: a frame layer
            # without the field is exactly what selects that path.
            frame_fields['encap_type'] = encap_type
        self.frame_info = FakeLayer('frame', **frame_fields)
        self.layers = [
            # Real PyShark names a layer from the PDML ``<proto name>``
            # attribute, which is Wireshark's protocol *filter* name --
            # ``eth``, not ``ethernet`` -- so the fake has to match that or it
            # is not exercising what the real engine hands ``tcp_traceflow``.
            # That name is not a LinkType *member* name either, so
            # ``pcapkit.toolkit.pyshark.FILTER_NAME_TO_LINKTYPE`` translates
            # the ones measured to be unambiguous -- see that table's own
            # comment for the evidence and for what was deliberately left
            # out. Since #843 that table is the *fallback*, reached only when
            # the frame layer carries no ``encap_type``, and there is no
            # ``LinkType.get()`` attempt after it. ``link_layer`` lets a test pick any
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
        reimport_once_per_class(self)

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
        ``pcapkit.toolkit.pyshark.FILTER_NAME_TO_LINKTYPE`` translates that
        filter name to :attr:`LinkType.ETHERNET`, so this no longer raises the
        way it did prior to that table landing. The fake carries no
        ``encap_type``, which is what selects the filter-name path at all
        since #843.

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
        "Token-Ring", "tr")``, and measured since on this host: ``editcap -T
        tr`` writes DLT 6 and ``tshark`` roots the result at ``tr``. That name
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
        """``'ip'`` is absent from ``FILTER_NAME_TO_LINKTYPE``, so the
        fallback path raises. Since #843 the name is reported as PyShark
        gave it rather than upper-cased, there being no upper-case
        ``Enum_LinkType.get()`` attempt left to upper-case it for.

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

        self.assertEqual(ctx.exception.args[0], 'ip')
        self.assertEqual(before, after)

    def test_tcp_traceflow_raises_for_a_genuinely_unknown_name(self) -> None:
        """A link-layer filter name absent from ``FILTER_NAME_TO_LINKTYPE``
        must still raise :exc:`MissingKeyError` rather than be papered over
        with a stand-in DLT -- the maintainer's ruling from #775 tier 1 that
        this mapping does not relax.

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

        self.assertEqual(ctx.exception.args[0], 'wobegon')
        self.assertEqual(before, after)  # the miss must not grow the registry

    def test_tcp_traceflow_disambiguates_the_shared_filter_names(self) -> None:
        """#843: one Wireshark display-filter name serves several DLTs, so
        keying on ``packet.layers[0].layer_name`` answered a *valid but
        wrong* DLT with no error. ``frame.encap_type`` separates them, and
        ``ENCAP_TYPE_TO_LINKTYPE`` turns it into the right member.

        Each ``(encap_type, filter name, expected)`` triple below was
        measured on this host with ``editcap``/``tshark`` 4.6.9 -- the
        encapsulation rewritten with ``editcap -F pcap -T <encap>``, the DLT
        read out of the resulting pcap file header at offset 20, and
        ``frame.encap_type`` read back from ``tshark -T pdml``. The
        ``wrong`` column is what the pre-#843 filter-name path returned.

        """
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import pyshark as toolkit

        cases = [
            # encap, editcap -T, filter name, expected,        pre-#843 answer
            ('174', 'loop',       'null', LinkType.LOOP,         LinkType.NULL),
            ('15',  'null',       'null', LinkType.NULL,         LinkType.NULL),
            ('210', 'linux-sll2', 'sll',  LinkType.LINUX_SLL2,   None),  # raised
            ('25',  'linux-sll',  'sll',  LinkType.LINUX_SLL,    None),  # raised
            ('130', 'rawip6',     'raw',  LinkType.IPV6,         LinkType.RAW),
            ('129', 'rawip4',     'raw',  LinkType.IPV4,         LinkType.RAW),
            ('7',   'rawip',      'raw',  LinkType.RAW,          LinkType.RAW),
            ('19',  'ppp-with-direction', 'ppp', LinkType.PPP_WITH_DIR, LinkType.PPP),
            ('88',  'linux-lapd', 'lapd', LinkType.LINUX_LAPD,   LinkType.LAPD),
            ('2',   'tr',         'tr',   LinkType.IEEE802_5,    LinkType.IEEE802_5),
            ('1',   'ether',      'eth',  LinkType.ETHERNET,     LinkType.ETHERNET),
        ]
        for encap, encap_name, filter_name, expected, _ in cases:
            with self.subTest(encap=encap, editcap=encap_name):
                packet = FakePySharkPacket(link_layer=filter_name, encap_type=encap)
                data = toolkit.tcp_traceflow(packet)
                self.assertIsNotNone(data)
                self.assertEqual(data.protocol, expected)
                self.assertEqual(int(data.protocol), int(expected))

    def test_tcp_traceflow_prefers_encap_type_over_the_filter_name(self) -> None:
        """``frame.encap_type`` is the primary key and the filter name only
        the fallback, so a capture whose root layer *is* in
        ``FILTER_NAME_TO_LINKTYPE`` still resolves from the encapsulation.
        Feeding a mismatched pair -- ``eth`` as the root name with
        ``frame.encap_type`` 174 (``editcap -T loop``) -- is the only way to
        see which of the two the code actually read.

        """
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import pyshark as toolkit

        packet = FakePySharkPacket(link_layer='eth', encap_type='174')
        data = toolkit.tcp_traceflow(packet)
        self.assertIsNotNone(data)
        self.assertEqual(data.protocol, LinkType.LOOP)
        self.assertNotEqual(data.protocol, LinkType.ETHERNET)

    def test_tcp_traceflow_raises_for_an_unmapped_encap_type(self) -> None:
        """An encapsulation ``ENCAP_TYPE_TO_LINKTYPE`` does not cover must
        raise rather than fall through to the filter name or to any
        near-miss DLT -- 69 of the 226 encapsulations ``editcap -T`` accepts
        went unswept, and ``frame.encap_type`` 32 (DLT 121) is deliberately
        absent for want of a :class:`LinkType` member, so this path is
        reachable in practice.

        The root layer is left as ``eth`` on purpose: it *is* in
        ``FILTER_NAME_TO_LINKTYPE``, so a fall-through would quietly answer
        ``ETHERNET`` instead of raising.

        """
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import pyshark as toolkit
        from pcapkit.utilities.exceptions import MissingKeyError

        for encap in ('32', '9999'):
            with self.subTest(encap=encap):
                packet = FakePySharkPacket(link_layer='eth', encap_type=encap)
                self.assertNotIn(int(encap), toolkit.ENCAP_TYPE_TO_LINKTYPE)

                before = len(LinkType.__members__)
                with self.assertRaises(MissingKeyError) as ctx:
                    toolkit.tcp_traceflow(packet)
                after = len(LinkType.__members__)

                self.assertEqual(ctx.exception.args[0], 'frame.encap_type=%s' % encap)
                self.assertEqual(before, after)  # the miss must not grow the registry

    def test_tcp_traceflow_raises_for_a_non_numeric_encap_type(self) -> None:
        """PyShark hands fields over as ``str``, so the value has to be
        parsed; a value that will not parse is a miss like any other and
        must raise :exc:`MissingKeyError` rather than :exc:`ValueError`
        escaping this public function.

        """
        from pcapkit.toolkit import pyshark as toolkit
        from pcapkit.utilities.exceptions import MissingKeyError

        packet = FakePySharkPacket(link_layer='eth', encap_type='Ethernet')
        with self.assertRaises(MissingKeyError) as ctx:
            toolkit.tcp_traceflow(packet)
        self.assertEqual(ctx.exception.args[0], 'frame.encap_type=Ethernet')

    def test_filter_name_fallback_no_longer_upper_cases_onto_a_member(self) -> None:
        """The pre-#843 fallback tried ``Enum_LinkType.get(name.upper())``,
        which is what silently answered ``PPP`` (9) for a
        ``ppp-with-direction`` capture (DLT 204) and ``LAPD`` (203) for a
        ``linux-lapd`` one (DLT 177). Those names are ambiguous, so with no
        ``frame.encap_type`` to key on there is nothing to resolve them to
        and they must raise instead of answering the commoner DLT.

        """
        from pcapkit.toolkit import pyshark as toolkit
        from pcapkit.utilities.exceptions import MissingKeyError

        for name in ('ppp', 'lapd', 'raw', 'null'):
            with self.subTest(filter_name=name):
                self.assertNotIn(name, toolkit.FILTER_NAME_TO_LINKTYPE)
                packet = FakePySharkPacket(link_layer=name)  # no encap_type
                with self.assertRaises(MissingKeyError) as ctx:
                    toolkit.tcp_traceflow(packet)
                self.assertEqual(ctx.exception.args[0], name)

    def test_filter_name_fallback_resolves_the_measured_names(self) -> None:
        """Per the maintainer's ruling on #842, the fallback table covers
        **every** filter name the sweep measured as unambiguous, not only the
        two it started with. The owner's reason on #842 for covering every
        filter name that differs from the one pcapkit uses was that nobody
        should have to come back later to update the table; he also wanted the
        values generated if possible, or at least a comment pointing at the
        source of truth. None of the names below spells a LinkType member, so
        each one raised before the expansion.

        Each pair was measured the same way as the rest of the table: the
        root PDML ``<proto name>`` of an ``editcap -F pcap -T <encap>``
        rewrite, against the DLT in that file's own pcap header.

        """
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import pyshark as toolkit

        cases = [
            # filter name, editcap -T, expected
            ('chdlc', 'chdlc', LinkType.C_HDLC),
            ('radiotap', 'ieee-802-11-radiotap', LinkType.IEEE802_11_RADIOTAP),
            ('fr', 'frelay', LinkType.FRELAY),
            ('llap', 'ltalk', LinkType.LTALK),
            ('mstp', 'bacnet-ms-tp', LinkType.BACNET_MS_TP),
            ('ipfc', 'ip-over-fc', LinkType.IP_OVER_FC),
            ('clip', 'linux-atm-clip', LinkType.ATM_CLIP),
            ('irlap', 'irda', LinkType.LINUX_IRDA),
        ]
        for filter_name, encap_name, expected in cases:
            with self.subTest(filter_name=filter_name, editcap=encap_name):
                self.assertNotIn(filter_name.upper(), LinkType.__members__)
                packet = FakePySharkPacket(link_layer=filter_name)  # no encap_type
                data = toolkit.tcp_traceflow(packet)
                self.assertIsNotNone(data)
                self.assertEqual(data.protocol, expected)

    def test_lookup_table_shapes(self) -> None:
        """Guard both tables: :class:`int` keys keyed the way the lookup
        keys them, lower-case names the way PyShark reports them, and
        :class:`LinkType` values throughout. A stray string key in
        ``ENCAP_TYPE_TO_LINKTYPE`` would never match the ``int()`` the lookup
        does, and would fail silently rather than loudly.

        The counts are the sweep's own: 152 encapsulations and 58 filter
        names, with the encapsulation table necessarily the larger of the two
        because a filter name shared by several DLTs cannot be mapped at all.

        """
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit import pyshark as toolkit

        encaps = toolkit.ENCAP_TYPE_TO_LINKTYPE
        self.assertEqual(len(encaps), 152)
        for key, value in encaps.items():
            with self.subTest(encap=key):
                self.assertIsInstance(key, int)
                self.assertIsInstance(value, LinkType)
                self.assertIs(LinkType(int(value)), value)

        names = toolkit.FILTER_NAME_TO_LINKTYPE
        self.assertEqual(len(names), 58)
        for key, value in names.items():
            with self.subTest(filter_name=key):
                self.assertIsInstance(key, str)
                self.assertEqual(key, key.lower())  # the lookup lower-cases its input
                self.assertIsInstance(value, LinkType)
                self.assertIs(LinkType(int(value)), value)

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
