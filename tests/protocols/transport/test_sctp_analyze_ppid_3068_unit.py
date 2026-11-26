# -*- coding: utf-8 -*-
"""``SCTP.analyze`` dispatches a payload by PPID, as an SCTP frame does (#3068).

``SCTP.__proto__`` is keyed by the payload protocol identifier, but ``SCTP`` inherited
``Transport.analyze``, which looked the port pair up in it. So an NGAP payload on its
port parsed as ``Raw``, and one on port 60 or 66, the NGAP PPIDs, parsed as NGAP
whatever its PPID. Each case compares ``analyze`` with the next layer of an SCTP frame
carrying the same DATA chunk.

Every case builds its own octets, so this belongs to the unit tier.

"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Iterator

HAS_PYCRATE = importlib.util.find_spec('pycrate_asn1dir') is not None

#: An ``NGSetupRequest`` in aligned PER, as in :file:`tests/protocols/application/test_ngap_unit.py`.
NGSETUP_REQUEST = bytes.fromhex(
    '00150036000004001b00080002f839100001020052400d0500706361706b69742d676e62'
    '0066000d00000000010002f839000000080015400140'
)

#: ``(case, source port, destination port, PPID)`` of each frame compared.
CASES = (
    ('NGAP on its port, PPID 60', 9899, 38412, 60),
    ('port 60, PPID 0', 60, 5000, 0),
    ('port 66, PPID 0', 66, 9000, 0),
    ('the Diameter port, unregistered PPID 46', 3868, 3868, 46),
)


@contextlib.contextmanager
def _spy(cls: type) -> 'Iterator[list[dict[str, Any]]]':
    """Record the keywords every ``cls.read`` is given; the read still runs."""
    calls = []  # type: list[dict[str, Any]]
    original = cls.read

    def read(self: 'Any', *args: 'Any', **kwargs: 'Any') -> 'Any':
        calls.append(kwargs)
        return original(self, *args, **kwargs)

    with mock.patch.object(cls, 'read', read):
        yield calls


class SCTPAnalyzeTests(unittest.TestCase):
    """``SCTP.analyze`` takes the PPID an SCTP frame dispatches its next layer on."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _frame(chunk: 'tuple[Any, dict[str, Any]]', src: int = 9899, dst: int = 38412,
               **kwargs: 'Any') -> 'Any':
        """An SCTP packet of the one ``chunk``, parsed with ``kwargs``."""
        from pcapkit.protocols.transport.sctp.protocol import SCTP

        raw = SCTP.make(SCTP.__new__(SCTP), srcport=src, dstport=dst, vtag=0x11223344,
                        chunks=[chunk]).pack()
        return SCTP(io.BytesIO(raw), len(raw), **kwargs)

    @staticmethod
    def _data(ppid: 'Any', data: bytes) -> 'tuple[Any, dict[str, Any]]':
        from pcapkit.const.sctp.chunk import Chunk

        return (Chunk.Payload_Data, dict(I=True, U=True, B=True, E=True, tsn=1, stream_id=0,
                                         stream_seq=0, ppid=ppid, data=data))

    def assertSameLayer(self, packet: 'Any', expected: 'Any') -> None:
        """``packet`` is ``expected``'s class, with its info and protocol chain."""
        self.assertIs(type(packet), type(expected))
        self.assertEqual(packet.info, expected.info)
        self.assertEqual(str(packet.protochain), str(expected.protochain))

    def test_the_payload_is_the_frame_s_next_layer(self) -> None:
        from pcapkit.protocols.transport.sctp.protocol import SCTP

        for case, src, dst, ppid in CASES:
            with self.subTest(case=case):
                frame = self._frame(self._data(ppid, NGSETUP_REQUEST), src, dst)
                self.assertSameLayer(SCTP.analyze(frame.ppid, NGSETUP_REQUEST), frame.payload)

    @unittest.skipUnless(HAS_PYCRATE, 'pycrate not installed')
    def test_only_an_ngap_ppid_decodes_ngap(self) -> None:
        from pcapkit.const.sctp.payload_protocol_identifier import PayloadProtocolIdentifier
        from pcapkit.protocols.application.ngap.protocol import NGAP
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.protocols.transport.sctp.protocol import SCTP

        for ppid in (PayloadProtocolIdentifier.PayloadProtocolIdentifier_3GPP_NG_Application_Protocol, 60):
            with self.subTest(ppid=ppid):
                packet = SCTP.analyze(ppid, NGSETUP_REQUEST)
                self.assertIs(type(packet), NGAP)
                self.assertEqual(packet.info.message, 'NGSetupRequest')
        packet = SCTP.analyze(PayloadProtocolIdentifier.Reserved_by_SCTP, NGSETUP_REQUEST)
        self.assertIs(type(packet), Raw)
        self.assertIs(packet.info.protocol, PayloadProtocolIdentifier.Reserved_by_SCTP)

    def test_no_ppid_is_no_dispatch(self) -> None:
        """An I-DATA later fragment carries no PPID, and a packet with no user data none."""
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.misc.no_payload.protocol import NoPayload
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.protocols.transport.sctp.protocol import SCTP

        later = self._frame((Chunk.Payload_Data_supporting_Interleaving, dict(
            I=True, U=True, B=False, E=True, tsn=1, stream_id=0, mid=0, ppid=None, fsn=1,
            data=b'tail of a message')))
        self.assertIsNone(later.ppid)
        packet = SCTP.analyze(None, b'tail of a message')
        self.assertIs(type(packet), Raw)
        self.assertSameLayer(packet, later.payload)

        empty = self._frame((Chunk.Cookie_Acknowledgement, {}))
        packet = SCTP.analyze(empty.ppid, b'')
        self.assertIs(type(packet), NoPayload)
        self.assertSameLayer(packet, empty.payload)

    def test_a_stop_at_sctp_keeps_the_payload_raw(self) -> None:
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.protocols.transport.sctp.protocol import SCTP

        for stop in ({'protocol': 'SCTP'}, {'layer': 'transport'}):
            with self.subTest(**stop):
                frame = self._frame(self._data(60, NGSETUP_REQUEST), **stop)
                packet = SCTP.analyze(frame.ppid, NGSETUP_REQUEST, **stop)
                self.assertIs(type(packet), Raw)
                self.assertSameLayer(packet, frame.payload)

    def test_the_stops_and_the_context_alone_reach_the_payload(self) -> None:
        """Any other keyword is refused, and state takes the private route, beside the PPID (#2840)."""
        from pcapkit.const.sctp.payload_protocol_identifier import PayloadProtocolIdentifier
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.protocols.transport.sctp.protocol import SCTP

        ppid = PayloadProtocolIdentifier.Diameter_in_a_SCTP_DATA_chunk
        with self.assertRaisesRegex(TypeError, "unexpected keyword argument 'marker'"):
            SCTP.analyze(ppid, b'payload', marker=True)

        registry = ContextRegistry()
        with _spy(Raw) as calls:
            packet = SCTP.analyze(ppid, b'payload', context=registry)
        self.assertIs(type(packet), Raw)
        self.assertIs(packet._exctx, registry)  # pylint: disable=protected-access
        self.assertEqual(calls, [{'alias': ppid}])

        with _spy(Raw) as calls:
            SCTP._analyze_from_parent(ppid, b'payload', packet={'src': 1})  # pylint: disable=protected-access
        self.assertEqual((calls[0]['alias'], calls[0]['packet']), (ppid, {'src': 1}))


if __name__ == '__main__':
    unittest.main()
