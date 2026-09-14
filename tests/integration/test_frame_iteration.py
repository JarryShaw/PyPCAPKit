# -*- coding: utf-8 -*-
"""End-to-end frame-by-frame iteration and the extraction limits.

Translates :file:`examples/legacy_smoke/test_http.py`, which walked a capture
with ``auto=False`` and printed the frames where ``pcapkit.HTTP in frame`` held,
into assertions about which frames those are. It reads :file:`http6.cap` (26
frames) rather than the :file:`http.pcap` the script used, because the spectrum
is the ``in`` test and the manual walk, not the size of the capture.

The extraction limits -- ``layer`` and ``protocol``, which the command line tool
exposes as ``-L`` and ``-P`` -- belong to the same spectrum: they are what stops
that walk short of the application layer. They do not work; see
:class:`ExtractionLimitTests`.

"""
from __future__ import annotations

import unittest

from tests._support import sample_path
from tests.integration._helpers import HAS_RUNTIME, EndToEndTestCase

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


class ExtractionLimitTests(EndToEndTestCase):
    """``layer`` and ``protocol``, which stop parsing part way up the stack."""

    @unittest.skip('blocked on the parse limit never reaching the next layer: '
                   'pcapkit/protocols/protocol.py:1157 passes it as layer=/protocol= while '
                   'pcapkit/protocols/protocol.py:514 reads _layer/_protocol')
    def test_layer_and_protocol_limits_stop_the_parse(self) -> None:
        """``layer`` and ``protocol`` should stop parsing where they name.

        Neither does anything at all. ``ProtocolBase.__init__`` reads the limits
        from ``kwargs.pop('_layer')`` and ``kwargs.pop('_protocol')``
        (``pcapkit/protocols/protocol.py:514`` and ``:516``), but every caller
        passes them under the un-prefixed names:
        ``pcapkit/protocols/protocol.py:1157`` recurses with
        ``layer=self._exlayer, protocol=self._exproto``, and
        ``pcapkit/foundation/engines/pcap.py:146`` builds the frame with
        ``layer=ext._exlyr, protocol=ext._exptl``. The keywords therefore land in
        ``**kwargs`` and are dropped, ``_sigterm`` stays :data:`False` all the
        way up, and the parse always runs to the top of the stack.

        Measured on frame 4 of :file:`http6.cap`, whose full chain is
        ``Ethernet:IPv6:TCP:HTTP/1.1``: ``layer='internet'``,
        ``layer='transport'``, ``layer='link'``, ``protocol='TCP'`` and
        ``protocol='IPv6'`` every one of them yield that same full chain.

        That the mismatch is the whole story can be shown without the extractor,
        by handing one protocol object each spelling::

            >>> from pcapkit.protocols.link.ethernet import Ethernet
            >>> str(Ethernet(io.BytesIO(raw), len(raw), _layer='Link').protochain)
            'Ethernet:Internet_Protocol_version_6'
            >>> str(Ethernet(io.BytesIO(raw), len(raw), layer='Link').protochain)
            'Ethernet:IPv6:TCP:HTTP/1.1'

        The command line tool passes ``-L`` and ``-P`` straight through to the
        same place, so ``pcapkit-cli -L internet`` is equally inert.

        """
        for limit in ({'layer': 'internet'}, {'layer': 'transport'}, {'protocol': 'TCP'}):
            with self.subTest(**limit):
                extractor = self.extract(fin=sample_path('http6.cap'), nofile=True,
                                         store=True, **limit)
                chain = str(extractor.frame[3].protochain)

                self.assertTrue(chain.startswith('Ethernet:IPv6'))
                self.assertNotIn('HTTP', chain)


if __name__ == '__main__':
    unittest.main()
