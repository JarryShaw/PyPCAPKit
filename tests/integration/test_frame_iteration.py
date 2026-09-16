# -*- coding: utf-8 -*-
"""End-to-end frame-by-frame iteration and the extraction limits.

Translates :file:`examples/legacy_smoke/test_http.py`, which walked a capture
with ``auto=False`` and printed the frames where ``pcapkit.HTTP in frame`` held,
into assertions about which frames those are. It reads :file:`http6.cap` (26
frames) rather than the :file:`http.pcap` the script used, because the spectrum
is the ``in`` test and the manual walk, not the size of the capture.

The extraction limits -- ``layer`` and ``protocol``, which the command line tool
exposes as ``-L`` and ``-P`` -- belong to the same spectrum: they are what stops
that walk short of the application layer. See :class:`ExtractionLimitTests`,
which asserts where each of them stops it.

"""
from __future__ import annotations

import unittest
from typing import TYPE_CHECKING

from tests._support import sample_path
from tests.integration._helpers import HAS_RUNTIME, EndToEndTestCase

if TYPE_CHECKING:
    from typing import Any

#: Frames of :file:`http6.cap` that carry an HTTP header block: the request and
#: the response of each of the two connections.
HTTP_FRAMES = (4, 6, 19, 21)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class FrameIterationTests(EndToEndTestCase):
    """``auto=False``, i.e. the caller drives the extraction."""

    def test_manual_iteration_yields_every_frame_once_and_in_order(self) -> None:
        extractor = self.extract(fin=sample_path('http6.cap'), nofile=True, store=False,
                                 auto=False)

        numbers = [frame.info.number for frame in extractor]

        self.assertEqual(numbers, list(range(1, 27)))
        self.assertEqual(extractor.length, 26)

    def test_protocol_membership_finds_the_http_frames(self) -> None:
        import pcapkit

        extractor = self.extract(fin=sample_path('http6.cap'), nofile=True, store=False,
                                 auto=False)

        found = {}
        for frame in extractor:
            if pcapkit.HTTP in frame:
                found[frame.info.number] = str(frame.protochain)

        self.assertEqual(tuple(found), HTTP_FRAMES)
        self.assertEqual(set(found.values()), {'Ethernet:IPv6:TCP:HTTP/1.1'})

    def test_membership_is_false_for_a_protocol_the_capture_lacks(self) -> None:
        import pcapkit

        extractor = self.extract(fin=sample_path('http6.cap'), nofile=True, store=True)

        self.assertFalse(any(pcapkit.UDP in frame for frame in extractor.frame))
        self.assertTrue(all(pcapkit.TCP in frame for frame in extractor.frame))

    def test_call_form_walks_the_same_frames_as_the_iterator(self) -> None:
        extractor = self.extract(fin=sample_path('arp.pcap'), nofile=True, store=False,
                                 auto=False)

        first = next(extractor)
        second = extractor()

        self.assertEqual(first.info.number, 1)
        self.assertEqual(second.info.number, 2)
        self.assertEqual(str(first.protochain), 'Ethernet:ARP:Raw')
        # ``no_eof`` is documented as "if not raise EOFError when reach EOF", so
        # raising it here is the contract rather than an accident.
        with self.assertRaises(EOFError):
            extractor()


def stack(frame: 'Any') -> 'list[Any]':
    """The protocol objects of ``frame``, outermost first.

    Walks ``payload`` rather than reading ``protochain``, because the chain is a
    string of *names* and a name does not say what the object is: a
    :class:`~pcapkit.protocols.misc.raw.Raw` standing in for a payload the parse
    declined to enter is labelled with the enumeration it was handed, so
    ``Ethernet:IPv6:TCP`` is what both a fully parsed TCP header and a stopped
    parse holding TCP's octets verbatim look like. Only the objects tell them
    apart, which is what :class:`ExtractionLimitTests` has to assert on.

    """
    from pcapkit.protocols.misc.null import NoPayload

    walked = []  # type: list[Any]
    current = frame.payload
    while current is not None and not isinstance(current, NoPayload):
        walked.append(current)
        current = getattr(current, 'payload', None)
    return walked


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ExtractionLimitTests(EndToEndTestCase):
    """``layer`` and ``protocol``, which stop parsing part way up the stack.

    Both were inert until GH-356. ``ProtocolBase.__init__`` read the limits from
    ``_layer``/``_protocol``, while every producer -- the two engines building
    the outermost protocol, all four ``_import_next_layer`` implementations
    recursing into the next one, and the public
    ``pcapkit.extract(layer=..., protocol=...)`` that the CLI's ``-L``/``-P``
    feed -- passed them without the underscore. They landed in ``**kwargs``, were
    dropped, ``_sigterm`` stayed :data:`False` the whole way up, and the parse
    always ran to the top of the stack whatever the caller asked for.

    So these tests assert on *where the parse stopped*, not on the option being
    stored: a test that only checked ``extractor._exlyr`` would have passed
    throughout the bug's lifetime.

    """

    #: Frame 4 of :file:`http6.cap`, whose unlimited chain is the full four
    #: layers, and what each limit should leave of it. The last entry of each
    #: tuple is the class the parse is expected to stop *at*; everything beyond
    #: it should be one :class:`~pcapkit.protocols.misc.raw.Raw`.
    STOPS = {
        'link': ('Ethernet',),
        'internet': ('Ethernet', 'IPv6'),
        'transport': ('Ethernet', 'IPv6', 'TCP'),
    }

    def test_layer_and_protocol_limits_stop_the_parse(self) -> None:
        """``layer`` and ``protocol`` stop parsing where they name.

        The assertion the issue was filed against: frame 4 of :file:`http6.cap`
        parses as ``Ethernet:IPv6:TCP:HTTP/1.1`` unlimited, and none of these
        limits may leave HTTP in it.

        """
        for limit in ({'layer': 'internet'}, {'layer': 'transport'}, {'protocol': 'TCP'}):
            with self.subTest(**limit):
                extractor = self.extract(fin=sample_path('http6.cap'), nofile=True,
                                         store=True, **limit)
                chain = str(extractor.frame[3].protochain)

                self.assertTrue(chain.startswith('Ethernet:IPv6'))
                self.assertNotIn('HTTP', chain)

    def test_no_limit_parses_to_the_top_of_the_stack(self) -> None:
        """The control: without a limit, frame 4 reaches the application layer.

        Also covers the sentinels ``Extractor.__init__`` substitutes for an
        omitted argument -- ``layer='none'`` and ``protocol='null'`` -- which
        must mean "no limit" rather than naming a layer or a protocol to stop at.

        """
        import pcapkit

        for limit in ({}, {'layer': 'none'}, {'protocol': 'null'},
                      {'layer': None, 'protocol': None}):
            with self.subTest(**limit):
                extractor = self.extract(fin=sample_path('http6.cap'), nofile=True,
                                         store=True, **limit)
                frame = extractor.frame[3]

                self.assertEqual(str(frame.protochain), 'Ethernet:IPv6:TCP:HTTP/1.1')
                self.assertIn(pcapkit.HTTP, frame)
                self.assertEqual(
                    [type(protocol).__name__ for protocol in stack(frame)],
                    ['Ethernet', 'IPv6', 'TCP', 'HTTP'],
                )

    def test_layer_limit_stops_at_the_named_layer_and_leaves_raw_above_it(self) -> None:
        """Each ``layer`` value stops the walk at the protocol of that layer.

        What is above the stop is a single :class:`~pcapkit.protocols.misc.raw.Raw`
        holding the octets the parse declined to enter, and its ``error`` is
        :data:`None` -- the stop is deliberate, not a parse failure that happens
        to look like one.

        """
        from pcapkit.protocols.misc.raw import Raw

        for layer, expected in self.STOPS.items():
            with self.subTest(layer=layer):
                extractor = self.extract(fin=sample_path('http6.cap'), nofile=True,
                                         store=True, layer=layer)
                walked = stack(extractor.frame[3])

                self.assertEqual([type(protocol).__name__ for protocol in walked[:-1]],
                                 list(expected))
                self.assertIsInstance(walked[-1], Raw)
                self.assertIsNone(walked[-1].info.error)
                self.assertEqual(len(walked), len(expected) + 1)

    def test_layer_limit_keeps_the_unparsed_payload_verbatim(self) -> None:
        """Stopping loses nothing: the ``Raw`` holds what the next layer would have.

        ``layer='internet'`` stops above IPv6, so the octets the TCP header and
        everything after it would have been parsed from are still there, byte for
        byte, and they are the same octets the unlimited parse consumed.

        """
        full = self.extract(fin=sample_path('http6.cap'), nofile=True, store=True)
        stopped = self.extract(fin=sample_path('http6.cap'), nofile=True, store=True,
                               layer='internet')

        tcp_onwards = bytes(stack(full.frame[3])[2])
        raw = stack(stopped.frame[3])[-1]

        self.assertEqual(bytes(raw), tcp_onwards)
        self.assertGreater(len(tcp_onwards), 0)

    def test_protocol_limit_accepts_a_name_or_a_protocol_class(self) -> None:
        """``protocol`` takes a name, a class, or an instance of one.

        ``Protocol.expand_comp`` is documented to accept all three, and the
        limit is compared through it, so the three spellings have to agree.

        """
        import pcapkit
        from pcapkit.protocols.misc.raw import Raw

        for protocol in ('TCP', 'tcp', pcapkit.TCP):
            with self.subTest(protocol=protocol):
                extractor = self.extract(fin=sample_path('http6.cap'), nofile=True,
                                         store=True, protocol=protocol)
                walked = stack(extractor.frame[3])

                self.assertEqual([type(item).__name__ for item in walked],
                                 ['Ethernet', 'IPv6', 'TCP', 'Raw'])
                self.assertIsInstance(walked[-1], Raw)
                self.assertNotIn(pcapkit.HTTP, extractor.frame[3])

    def test_protocol_limit_stops_below_the_transport_layer(self) -> None:
        """``protocol='IPv6'`` stops at IPv6, i.e. TCP is never parsed either."""
        import pcapkit
        from pcapkit.protocols.misc.raw import Raw

        extractor = self.extract(fin=sample_path('http6.cap'), nofile=True, store=True,
                                 protocol='IPv6')
        walked = stack(extractor.frame[3])

        self.assertEqual([type(item).__name__ for item in walked],
                         ['Ethernet', 'IPv6', 'Raw'])
        self.assertNotIn(pcapkit.TCP, extractor.frame[3])
        self.assertIsInstance(walked[-1], Raw)

    def test_limits_apply_to_every_frame_not_only_the_first(self) -> None:
        """The limit is honoured for the whole capture.

        The engines build one protocol per frame, so a limit that reached only
        the first frame would still be a bug -- and the four HTTP-carrying frames
        of :file:`http6.cap` are what would show it.

        """
        import pcapkit

        extractor = self.extract(fin=sample_path('http6.cap'), nofile=True, store=True,
                                 layer='internet')

        self.assertEqual(len(extractor.frame), 26)
        self.assertFalse(any(pcapkit.HTTP in frame for frame in extractor.frame))
        self.assertFalse(any(pcapkit.TCP in frame for frame in extractor.frame))

    def test_pcapng_engine_honours_the_limits_too(self) -> None:
        """The PCAP-NG engine is a second, independent producer of the limits.

        It builds its outermost protocol in
        ``pcapkit.foundation.engines.pcapng.PCAPNG.read_frame`` rather than
        through ``PCAP.read_frame``, so it has to be checked separately: the
        protochains for :file:`test.pcapng` were byte-identical to the unlimited
        run while the limits were inert.

        """
        chains = {}
        for limit in ({}, {'layer': 'link'}, {'layer': 'internet'}):
            extractor = self.extract(fin=sample_path('test.pcapng'), nofile=True,
                                     store=True, **limit)
            chains[tuple(sorted(limit.items()))] = [
                str(frame.protochain) for frame in extractor.frame
            ]

        unlimited = chains[()]
        self.assertNotEqual(chains[(('layer', 'link'),)], unlimited)
        self.assertNotEqual(chains[(('layer', 'internet'),)], unlimited)
        # Anything the unlimited run took past the link layer must be shorter now.
        self.assertTrue(any(len(short.split(':')) < len(long.split(':'))
                            for short, long in zip(chains[(('layer', 'link'),)], unlimited)))


if __name__ == '__main__':
    unittest.main()
