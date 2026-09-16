"""End-to-end agreement between the new engines and the ``default`` engine.

:class:`~pcapkit.foundation.extraction.Extractor` falls back to its own parser
with an :class:`~pcapkit.utilities.warnings.EngineWarning` when the engine module
is missing, so a naive "does it agree with the default engine?" test passes most
loudly when the engine under test never ran at all. Every test here therefore
proves the engine ran first -- by the recorded engine name, the engine class, and
the absence of any :class:`~pcapkit.utilities.warnings.EngineWarning` -- and only
then compares.

This module is named ``*_runtime.py`` deliberately, which puts it in the
fixture-dependent tier (see :mod:`tests._tiers`). It reads ``arp.pcap``,
``tcp.pcap``, ``ipv4.pcap`` and ``test.pcapng``, none of which git tracks --
:file:`examples/generators/make_samples.py` writes them -- so it cannot be
unit-tier, and it was one only because the guard added in GitHub pull request #393
could not see it: the reads go through ``sample_path(capture)`` with a *variable*,
which only the runtime half of the guard catches, and that half was never reached
on a machine where the engine packages were absent and every test skipped.
Installing an engine made all four reads fail at once.

Note also that the frame objects a stored extraction hands back are not a usable
source of raw bytes: :attr:`Frame.packet
<pcapkit.protocols.protocol.ProtocolBase.packet>` re-reads from the (by then
exhausted) input stream, and ``Frame.info.packet`` holds the *undecoded remainder*
rather than the frame. The comparison below therefore uses the fields that are
recorded verbatim off the wire -- the per-record capture length and timestamp from
the PCAP record header, and the Ethernet header of each frame.

"""
from __future__ import annotations

import importlib
import importlib.util
import unittest
from unittest import mock

from tests._support import close_extractor, purge_modules, sample_path

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


def _importable(*modules: str) -> bool:
    """Test if every named module can actually be imported.

    :func:`importlib.util.find_spec` is not enough for ``pypcapfile``: its released
    0.12.0 imports the :mod:`imp` module, removed in Python 3.12, so it can be
    installed and still unusable.

    """
    for module in modules:
        try:
            importlib.import_module(module)
        except ImportError:
            return False
    return True


#: Whether upstream ``pypcap`` is installed, as opposed to ``pcap-ct``.
#:
#: Both distributions own the top-level :mod:`pcap` name, so ``_importable('pcap')``
#: alone is not the question these tests want to ask: ``pcap-ct`` is driven by
#: :class:`~pcapkit.foundation.engines.pcap_ct.PCAP_CT` and
#: :class:`~pcapkit.foundation.engines.pypcap.PyPCAP` refuses it outright, so
#: letting it satisfy this gate would run the ``pypcap`` tests against an engine
#: that declines to start. ``pcap-ct`` ships :mod:`pcap` as a package whose
#: ``__init__`` does ``from ._pcap import *``; upstream ships a single extension
#: module, which has no such submodule.
HAS_PYPCAP = _importable('pcap') and not _importable('pcap._pcap')
HAS_PYPCAPFILE = _importable('pcapfile.savefile', 'pcapfile.linklayer')

#: Captures the parity comparison runs over. All are Ethernet PCAP savefiles.
CAPTURES = ('in.pcap', 'arp.pcap', 'tcp.pcap', 'ipv4.pcap')


def ethernet_of(frame) -> tuple[str, str, int]:
    """Fetch ``(src, dst, ethertype)`` from a ``default`` engine frame."""
    info = frame['Ethernet'].info
    return str(info.src), str(info.dst), int(info.type)


def mac(raw) -> str:
    """Render six raw bytes as a colon-separated MAC address."""
    return ':'.join(f'{octet:02x}' for octet in bytes(raw))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class NewEngineParityTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def extract(self, engine: str, capture: str, **kwargs):
        """Extract a capture, asserting that the requested engine really ran.

        Returns the extractor, having checked that
        :class:`~pcapkit.foundation.extraction.Extractor` neither rewrote the engine
        name nor warned about the engine being unavailable -- i.e. that the result
        is not the built-in parser wearing the requested engine's label.

        """
        from pcapkit.interface import extract
        from pcapkit.utilities.warnings import EngineWarning

        with mock.patch('pcapkit.foundation.extraction.warn') as warn:
            extractor = extract(fin=sample_path(capture), fout='/tmp/parity-out',
                                format='tree', store=True, nofile=True, engine=engine,
                                **kwargs)
        self.addCleanup(close_extractor, extractor)

        engines = [call.args[0] for call in warn.call_args_list
                   if len(call.args) > 1 and call.args[1] is EngineWarning]
        self.assertEqual(engines, [], f'{engine!r} was replaced by the fallback engine')
        self.assertEqual(extractor._exnam, engine)
        return extractor

    ##########################################################################
    # Proof that the engine ran.
    ##########################################################################

    @unittest.skipUnless(HAS_PYPCAP, 'pypcap not installed')
    def test_pypcap_engine_really_ran(self) -> None:
        from pcapkit.foundation.engines.pypcap import PyPCAP

        extractor = self.extract('pypcap', 'in.pcap')
        self.assertIsInstance(extractor.engine, PyPCAP)
        self.assertEqual(extractor.engine.name, 'PyPCAP')
        self.assertEqual(extractor.engine.module, 'pcap')
        # a fallback would have produced ``Frame`` objects, not bare tuples
        for frame in extractor.frame:
            self.assertIsInstance(frame, tuple)
            self.assertEqual(len(frame), 2)

    @unittest.skipUnless(HAS_PYPCAPFILE, 'pypcapfile not installed')
    def test_pypcapfile_engine_really_ran(self) -> None:
        from pcapfile.structs import pcap_packet

        from pcapkit.foundation.engines.pypcapfile import PyPCAPFile

        extractor = self.extract('pypcapfile', 'in.pcap')
        self.assertIsInstance(extractor.engine, PyPCAPFile)
        self.assertEqual(extractor.engine.name, 'PyPCAPFile')
        self.assertEqual(extractor.engine.module, 'pcapfile')
        for frame in extractor.frame:
            self.assertIsInstance(frame, pcap_packet)

    ##########################################################################
    # Agreement with the default engine.
    ##########################################################################

    @unittest.skipUnless(HAS_PYPCAP, 'pypcap not installed')
    def test_pypcap_agrees_with_the_default_engine(self) -> None:
        from pcapkit.const.reg.linktype import LinkType

        for capture in CAPTURES:
            with self.subTest(capture=capture):
                base = self.extract('default', capture)
                engine = self.extract('pypcap', capture)

                self.assertEqual(engine.length, base.length)
                self.assertEqual(len(engine.frame), base.length)
                self.assertEqual(engine.engine.dlink, LinkType.ETHERNET)

                for index, expected in enumerate(base.frame):
                    timestamp, packet = engine.frame[index]
                    self.assertEqual(len(packet), expected.info.frame_info.incl_len,
                                     f'{capture} frame {index + 1}: capture length')
                    self.assertEqual(timestamp, float(expected.info.time_epoch),
                                     f'{capture} frame {index + 1}: timestamp')

                    src, dst, ethertype = ethernet_of(expected)
                    self.assertEqual(mac(packet[0:6]), dst,
                                     f'{capture} frame {index + 1}: ethernet dst')
                    self.assertEqual(mac(packet[6:12]), src,
                                     f'{capture} frame {index + 1}: ethernet src')
                    self.assertEqual(int.from_bytes(packet[12:14], 'big'), ethertype,
                                     f'{capture} frame {index + 1}: ethertype')

    @unittest.skipUnless(HAS_PYPCAPFILE, 'pypcapfile not installed')
    def test_pypcapfile_agrees_with_the_default_engine(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import packet2timestamp

        for capture in CAPTURES:
            with self.subTest(capture=capture):
                base = self.extract('default', capture)
                engine = self.extract('pypcapfile', capture)

                self.assertEqual(engine.length, base.length)
                self.assertEqual(len(engine.frame), base.length)
                self.assertEqual(engine.engine.dlink, LinkType.ETHERNET)

                for index, expected in enumerate(base.frame):
                    packet = engine.frame[index]
                    self.assertEqual(packet.capture_len, expected.info.frame_info.incl_len,
                                     f'{capture} frame {index + 1}: capture length')
                    self.assertEqual(packet.packet_len, expected.info.frame_info.orig_len,
                                     f'{capture} frame {index + 1}: original length')
                    self.assertEqual(packet2timestamp(packet), float(expected.info.time_epoch),
                                     f'{capture} frame {index + 1}: timestamp')

                    src, dst, ethertype = ethernet_of(expected)
                    ethernet = packet.packet
                    self.assertEqual(type(ethernet).__name__, 'Ethernet')
                    self.assertEqual(mac(ethernet.dst), dst,
                                     f'{capture} frame {index + 1}: ethernet dst')
                    self.assertEqual(mac(ethernet.src), src,
                                     f'{capture} frame {index + 1}: ethernet src')
                    self.assertEqual(ethernet.type, ethertype,
                                     f'{capture} frame {index + 1}: ethertype')

    @unittest.skipUnless(HAS_PYPCAPFILE, 'pypcapfile not installed')
    def test_pypcapfile_ipv4_reassembly_agrees_with_the_default_engine(self) -> None:
        base = self.extract('default', 'ipv4.pcap', reassembly=True, ipv4=True)
        engine = self.extract('pypcapfile', 'ipv4.pcap', reassembly=True, ipv4=True)

        def payloads(datagrams):
            return sorted(bytes(datagram.payload) if isinstance(datagram.payload, (bytes, bytearray))
                          else tuple(bytes(part) for part in datagram.payload)
                          for datagram in datagrams)

        self.assertTrue(base.reassembly.ipv4)
        self.assertEqual(payloads(engine.reassembly.ipv4), payloads(base.reassembly.ipv4))

    ##########################################################################
    # Capability gaps, asserted rather than described.
    ##########################################################################

    @unittest.skipUnless(HAS_PYPCAPFILE, 'pypcapfile not installed')
    def test_pypcapfile_reports_no_ipv6_reassembly(self) -> None:
        engine = self.extract('pypcapfile', 'ipv6.pcap', reassembly=True, ip=True)
        self.assertIsNone(engine.reassembly.ipv6)
        # ...whereas the default engine does reassemble it
        base = self.extract('default', 'ipv6.pcap', reassembly=True, ip=True)
        self.assertTrue(base.reassembly.ipv6)

    @unittest.skipUnless(HAS_PYPCAPFILE, 'pypcapfile not installed')
    def test_pypcapfile_traces_only_the_ipv4_half_of_a_mixed_capture(self) -> None:
        # ``tcp.pcap`` carries four IPv4 and three IPv6 TCP frames; ``pypcapfile``
        # can only see the former, so it finds strictly fewer flows.
        base = self.extract('default', 'tcp.pcap', trace=True, tcp=True,
                            trace_fout='/tmp/parity-trace-default')
        engine = self.extract('pypcapfile', 'tcp.pcap', trace=True, tcp=True,
                              trace_fout='/tmp/parity-trace-pypcapfile')

        def traced(extractor) -> set[int]:
            return {index for stream in extractor.trace.tcp for index in stream.index}

        ipv4_frames = {number for number, frame in enumerate(base.frame, start=1)
                       if 'IPv4' in frame}
        self.assertTrue(ipv4_frames)
        self.assertTrue(traced(engine))
        # every frame it traced is one it could decode ...
        self.assertLessEqual(traced(engine), ipv4_frames)
        # ... and that is a strict subset of what the default engine traced
        self.assertLess(traced(engine), traced(base))

    @unittest.skipUnless(HAS_PYPCAP, 'pypcap not installed')
    def test_pypcap_reports_neither_reassembly_nor_flow_tracing(self) -> None:
        from pcapkit.utilities.exceptions import UnsupportedCall

        engine = self.extract('pypcap', 'tcp.pcap', reassembly=True, ip=True, tcp=True,
                              trace=True)
        with self.assertRaises(UnsupportedCall):
            engine.reassembly  # pylint: disable=pointless-statement
        with self.assertRaises(UnsupportedCall):
            engine.trace  # pylint: disable=pointless-statement

    ##########################################################################
    # PCAP-NG.
    ##########################################################################

    @unittest.skipUnless(HAS_PYPCAP, 'pypcap not installed')
    def test_pypcap_rejects_pcapng_rather_than_reporting_zero_frames(self) -> None:
        from pcapkit.utilities.exceptions import FormatError

        # libpcap opens a PCAP-NG savefile without complaint and then yields no
        # frames at all, which would look like an empty capture; the engine gates
        # on the magic number so that it looks like an error instead.
        with self.assertRaises(FormatError):
            self.extract('pypcap', 'test.pcapng')

    @unittest.skipUnless(HAS_PYPCAPFILE, 'pypcapfile not installed')
    def test_pypcapfile_rejects_pcapng(self) -> None:
        from pcapkit.utilities.exceptions import FormatError

        with self.assertRaises(FormatError):
            self.extract('pypcapfile', 'test.pcapng')


if __name__ == '__main__':
    unittest.main()
