from __future__ import annotations

import importlib.util
import tempfile
import types
import unittest
import warnings
from unittest import mock

from tests._support import purge_modules, sample_path

#: Packages :mod:`pcapkit` needs before it can parse anything at all; the default
#: engine and therefore every test here depends on them. They are core install
#: dependencies, so this gate only ever skips on a deliberately minimal build.
RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)
#: Whether the optional DPKT / Scapy engines can be selected. Both are optional
#: extras (``pypcapkit[DPKT]`` / ``[Scapy]``), absent from a plain ``[test]``
#: install, so the engine-specific cases skip rather than fail on a fresh clone.
HAS_DPKT = importlib.util.find_spec('dpkt') is not None
HAS_SCAPY = importlib.util.find_spec('scapy') is not None

#: TCP conversations the default (pcapkit-native) engine finds in the committed
#: ``in.pcap`` capture. Measured against ``examples/captures/in.pcap``, and the
#: yardstick every other engine is judged by: every engine reaching this module
#: is expected to agree on it, either by dissecting the capture itself or by being
#: redirected to the default engine.
IN_PCAP_TCP_STREAMS = 3


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class FollowTCPStreamTests(unittest.TestCase):
    """:func:`~pcapkit.interface.misc.follow_tcp_stream` per extraction engine.

    ``examples/captures/in.pcap`` (committed, so unit-tier safe) holds three TCP
    conversations. #399: the reassembly adapter was chosen by comparing the
    engine *instance* to a string -- a comparison that is never true -- so every
    engine silently used the pcapkit adapter regardless of which engine ran. That
    crashed on DPKT frames (``AttributeError: 'dict' object has no attribute
    'packet'``) and returned an empty, misleading result on Scapy frames.

    Both third-party engines that dissect this capture -- DPKT and Scapy -- must
    therefore agree with the default engine on all three streams. Engines that do
    no dissection at all (PyPCAP) or have no reassembly adapter (PyShark) are
    redirected to the default engine instead, and are asserted separately below.

    #406: this class previously expected Scapy to find *zero* streams, on the
    stated rationale that it could not read the capture's link layer -- "a
    documented capability gap". That rationale was wrong. ``in.pcap`` is plain
    Ethernet (link type 1), which Scapy dissects perfectly well; the zero came
    from :class:`~pcapkit.foundation.engines.scapy.Scapy` importing only
    :mod:`scapy.sendrecv`, which populates none of Scapy's layer registries, so
    every frame came back as an undissected ``Raw``. Zero was the polluted
    answer and three is the truthful one.
    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])
        # follow_tcp_stream always drives the flow tracer, whose output root
        # defaults to './tmp' under the working directory when ``fout`` is unset
        # (TraceFlow.__init__). Point it at a scratch directory so a test run
        # writes nothing into the tree.
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-follow-')
        self.addCleanup(tmp.cleanup)
        self.tmp_dir = tmp.name

    def _follow(self, **kwargs: object) -> tuple:
        from pcapkit.interface.misc import follow_tcp_stream

        kwargs.setdefault('fout', self.tmp_dir)
        return follow_tcp_stream(fin=sample_path('in.pcap'), **kwargs)  # type: ignore[arg-type]

    def test_default_engine_finds_every_tcp_stream(self) -> None:
        streams = self._follow()
        self.assertEqual(len(streams), IN_PCAP_TCP_STREAMS)
        # Each detected flow carries the frames traceflow grouped into it, and names
        # the file its trace was written to. in.pcap's three TCP flows are one frame
        # each and single-segment, so there is no multi-segment payload to
        # reassemble -- the empty conversations are a property of this capture, not
        # of the reassembly, which is why the parity test below compares them rather
        # than requiring them non-empty.
        for stream in streams:
            self.assertGreaterEqual(len(stream.packets), 1)
            self.assertIsNotNone(stream.filename)

    @unittest.skipUnless(HAS_DPKT, 'dpkt not installed')
    def test_dpkt_engine_matches_the_default_engine(self) -> None:
        # DPKT dissects in.pcap's Ethernet/IP/TCP in full, so it must agree with the
        # native engine on both the stream count and the reassembled bytes. This is
        # the regression guard for #399: before the fix the DPKT frame reached the
        # pcapkit adapter and raised AttributeError, and the counted-vs-uncounted
        # call convention is what makes the reassembled numbering line up.
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            native = self._follow()
            foreign = self._follow(engine='dpkt')

        self.assertEqual(len(foreign), IN_PCAP_TCP_STREAMS)
        self.assertEqual([len(stream.packets) for stream in foreign],
                         [len(stream.packets) for stream in native])
        self.assertEqual([stream.conversations for stream in foreign],
                         [stream.conversations for stream in native])

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_scapy_engine_matches_the_default_engine(self) -> None:
        # Scapy dissects in.pcap in full -- its two ICMPv6-over-IPv6 frames, its
        # three IPv4/TCP frames and its one UDP frame -- so, exactly like DPKT above,
        # it must agree with the native engine rather than differ from it.
        # This is the regression guard for #406: the engine imported only
        # ``scapy.sendrecv``, so Scapy's ``conf.l2types`` registry was empty,
        # ``PcapReader`` could not map link type 1, and all six frames arrived as
        # ``Raw`` -- turning three streams into zero with nothing raised.
        import pcapkit

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            native = self._follow()
            foreign = self._follow(engine='scapy')
            extractor = pcapkit.extract(fin=sample_path('in.pcap'), engine='scapy',
                                        store=True, nofile=True)

        # Asserted first, and on the frame type rather than on the stream count,
        # because it names the *cause*. A regression of #406 fails here as "frame 0
        # came back Raw", which points straight at the engine's import, instead of
        # surfacing downstream as an unexplained 0 != 3 stream-count mismatch.
        self.assertNotIsInstance(
            extractor.frame[0], self._scapy_raw(),
            'scapy returned frame 0 of in.pcap as an undissected Raw layer, so its '
            'layer registry was not populated -- see #406: the engine must import '
            'scapy.all, which loads the registries, not merely scapy.sendrecv',
        )
        self.assertTrue(
            any(frame.haslayer('TCP') for frame in extractor.frame),
            'scapy dissected no TCP layer from in.pcap, which holds three TCP frames',
        )

        # Full parity with the native engine, on the same three axes the DPKT test
        # above checks: count, per-stream frame counts, and reassembled conversations.
        self.assertEqual(len(foreign), IN_PCAP_TCP_STREAMS)
        self.assertEqual([len(stream.packets) for stream in foreign],
                         [len(stream.packets) for stream in native])
        self.assertEqual([stream.conversations for stream in foreign],
                         [stream.conversations for stream in native])

    @staticmethod
    def _scapy_raw() -> type:
        """Scapy's undissected-payload class, :class:`scapy.packet.Raw`.

        Imported inside a helper rather than at module scope because Scapy is an
        optional extra: this module is collected, and its other cases run, on
        installs where ``import scapy`` would fail outright.

        :mod:`scapy.packet` is also the right submodule to reach ``Raw`` through
        for a test about #406, because it is registry-inert -- measured: importing
        it leaves ``conf.l2types`` empty -- so naming the class cannot itself
        populate the registries and mask the defect being asserted against.

        """
        from scapy.packet import Raw

        return Raw

    def test_pyshark_and_pypcap_fall_back_to_the_default_engine(self) -> None:
        # Neither engine can trace TCP flows (PyShark has no reassembly adapter,
        # PyPCAP does no dissection), so follow_tcp_stream redirects them to the
        # default engine with an EngineWarning rather than raising. No PyShark or
        # PyPCAP install is needed: the redirect happens before extraction begins.
        from pcapkit.utilities.warnings import EngineWarning

        for engine in ('pyshark', 'pypcap'):
            with self.subTest(engine=engine):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    streams = self._follow(engine=engine)
                self.assertTrue(any(issubclass(w.category, EngineWarning) for w in caught))
                self.assertEqual(len(streams), IN_PCAP_TCP_STREAMS)

    @unittest.skipUnless(HAS_DPKT, 'dpkt not installed')
    def test_dpkt_explicit_pcap_trace_format_is_downgraded_with_a_warning(self) -> None:
        # The PCAP trace dumper cannot serialise DPKT's dict frames, so an explicit
        # 'pcap' trace format is replaced with a dict-capable one, with a
        # FormatWarning -- and the stream is still followed rather than crashing the
        # extraction the way it did before #399 was fixed.
        from pcapkit.utilities.warnings import FormatWarning

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            streams = self._follow(engine='dpkt', format='pcap')

        self.assertTrue(any(issubclass(w.category, FormatWarning) for w in caught))
        self.assertEqual(len(streams), IN_PCAP_TCP_STREAMS)

    @unittest.skipUnless(HAS_DPKT, 'dpkt not installed')
    def test_dpkt_unset_trace_format_is_upgraded_quietly(self) -> None:
        # An unset trace format is not a request, so upgrading it to a dict-capable
        # format for DPKT does not warn -- only an explicit, unusable one does.
        from pcapkit.utilities.warnings import FormatWarning

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            streams = self._follow(engine='dpkt')

        self.assertFalse(any(issubclass(w.category, FormatWarning) for w in caught))
        self.assertEqual(len(streams), IN_PCAP_TCP_STREAMS)

    def test_engine_without_a_reassembly_adapter_returns_no_streams(self) -> None:
        # An engine pcapkit ships no reassembly adapter for -- a third-party one, or
        # a built-in that grows dict frames -- must not be silently routed to the
        # pcapkit adapter, which is precisely the #399 failure mode. It warns and
        # returns nothing. Extractor is stubbed so the branch can be reached without
        # registering a real engine.
        from pcapkit.interface import misc
        from pcapkit.utilities.warnings import EngineWarning

        class _FakeExtractor:
            def __init__(self, **kwargs: object) -> None:
                self.engine = types.SimpleNamespace(name='ThirdParty')
                self.frame = ()  # type: tuple
                self.trace = types.SimpleNamespace(tcp=[])

        with mock.patch.object(misc, 'Extractor', _FakeExtractor):
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                streams = misc.follow_tcp_stream(fin='ignored.pcap')

        self.assertEqual(streams, ())
        self.assertTrue(any(issubclass(w.category, EngineWarning) for w in caught))


if __name__ == '__main__':
    unittest.main()
