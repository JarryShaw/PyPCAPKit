# -*- coding: utf-8 -*-
"""SCTP User-Message Reassembly
==================================

.. module:: pcapkit.foundation.reassembly.sctp.reassembly

:mod:`pcapkit.foundation.reassembly.sctp.reassembly` contains
:class:`~pcapkit.foundation.reassembly.sctp.reassembly.SCTP` only, which reconstructs
an SCTP user message fragmented across DATA chunks (:rfc:`9260#section-6.9`) or
I-DATA chunks (:rfc:`8260#section-2.2.3`) back to origin.

.. versionadded:: 1.9.0

"""
from functools import partial
from typing import TYPE_CHECKING, Generic, cast

from pcapkit.const.sctp.chunk import Chunk as Enum_Chunk
from pcapkit.foundation.analysis.sctp import _analyze_payload
from pcapkit.foundation.reassembly.data import Completion, Deferred
from pcapkit.foundation.reassembly.reassembly import ReassemblyBase
from pcapkit.foundation.reassembly.sctp.data import (_AT, Buffer, BufferID, Datagram, DatagramID,
                                                     Fragment, Packet)
from pcapkit.protocols.transport.sctp.protocol import SCTP as SCTP_Protocol

if TYPE_CHECKING:
    from typing import Optional, Type

__all__ = ['SCTP']


class SCTP(ReassemblyBase[Packet[_AT], Datagram[_AT], BufferID, Buffer], Generic[_AT]):  # pylint: disable=abstract-method
    """Reassembly for SCTP user messages.

    Args:
        strict: if :data:`True`, report a message that is not completely
            reassembled as the tuple of its received runs; otherwise as one
            contiguous payload, the octets received up to its first hole, since
            a missing fragment's length is unknown
        store: if store reassembled datagram in memory, i.e.,
            :attr:`self._dtgram <pcapkit.foundation.reassembly.reassembly.Reassembly._dtgram>`
            (if not, datagram will be discarded after callback)
        timeout: reassembly timeout in seconds, on the capture's own clock;
            :data:`None` selects
            :attr:`~pcapkit.foundation.reassembly.reassembly.Reassembly.__timeout__`,
            which for SCTP disables expiry

    Note:
        A DATA message is a run of consecutive TSNs, from a fragment with the
        ``B`` bit set to one with the ``E`` bit set, all on one stream with one
        ``U`` bit and, when ordered, one stream sequence number
        (:rfc:`9260#section-6.9`). An I-DATA message is found by its stream,
        ``U`` bit and message identifier, and its fragments are ordered by FSN
        rather than TSN (:rfc:`8260#section-2.2.3`). A fragment whose TSN, or
        FSN, is already held is a duplicate, and the one received first is kept
        (:rfc:`9260#section-6.2`).

        The buffer ID is the packet's ports and verification tag, which one
        direction of one association carries on every path, so a fragment
        retransmitted to an alternate destination address
        (:rfc:`9260#section-6.4`) joins its message; a message reports the
        addresses of its lowest fragment held. A fragment retransmitted after
        its message completed is reported as a message of its own. The
        :class:`~pcapkit.foundation.extraction.Extractor` feeds it through
        :func:`pcapkit.toolkit.pcap.sctp_reassembly`, and
        :func:`~pcapkit.foundation.analysis.sctp.sctp_message` parses what it
        reassembles. A message's
        :attr:`~pcapkit.foundation.reassembly.sctp.data.Datagram.packet` holds the
        same parse, run on first read, by the ``analyze`` of
        :attr:`__protocol_type__`.

    Example:
        >>> from pcapkit.foundation.reassembly.sctp.reassembly import SCTP
        # Initialise instance:
        >>> sctp_reassembly = SCTP()
        # Call reassembly:
        >>> sctp_reassembly(packet_dict)
        # Fetch result:
        >>> result = sctp_reassembly.datagram

    """
    if TYPE_CHECKING:
        protocol: 'Type[SCTP_Protocol]'

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol name of current reassembly object.
    __protocol_name__ = 'SCTP'
    #: Protocol of current reassembly object, whose ``analyze`` parses a
    #: message's user data, as :meth:`SCTP.analyze
    #: <pcapkit.protocols.transport.sctp.protocol.SCTP.analyze>` does.
    __protocol_type__ = SCTP_Protocol

    # No ``__timeout__``: RFC 9260 and RFC 8260 give user-message reassembly no
    # timeout, so it inherits the base default, :data:`math.inf`, and by default
    # a buffer is held until its messages complete or the capture ends.

    ##########################################################################
    # Methods.
    ##########################################################################

    def reassembly(self, info: 'Packet[_AT]') -> 'None':
        """Reassembly procedure.

        Arguments:
            info: :term:`info` record of packets to be reassembled

        """
        # clear cache
        self._flag_n = False
        self.__cached__.clear()

        BUFID = info.bufid  # Buffer Identifier

        # NOTE: only ``expire`` abandons a buffer, under a ``timeout`` the caller gave.
        buf = self._buffer.get(BUFID)
        if buf is None:
            buf = Buffer(tsn={}, msg={}, timestamp=info.timestamp)
            self._buffer[BUFID] = buf

        if info.chunk == Enum_Chunk.Payload_Data_supporting_Interleaving:
            frag = self._add_idata(buf, info)
        else:
            frag = self._add_data(buf, info)
        if frag is None:
            return

        if not buf.tsn and not buf.msg:
            self._buffer.pop(BUFID)
        self._notify([self._datagram_from_fragment(frag, BUFID, Completion.COMPLETE)], store=True)

    def submit(self, buf: 'Buffer', *, bufid: 'BufferID', expired: 'bool' = False, store: 'bool' = False) -> 'list[Datagram[_AT]]':  # type: ignore[override] # pylint: disable=arguments-differ,line-too-long
        """Submit reassembled payload.

        Arguments:
            buf: buffer dict of reassembled packets
            bufid: buffer identifier
            expired: whether this buffer is being submitted because
                :meth:`~pcapkit.foundation.reassembly.reassembly.Reassembly.expire`
                abandoned it under the reassembly timeout
            store: whether ``buf`` has left
                :attr:`~pcapkit.foundation.reassembly.reassembly.Reassembly._buffer`
                for good, so its messages join
                :attr:`~pcapkit.foundation.reassembly.reassembly.Reassembly._dtgram`
                before the callbacks run, and one that raises cannot lose them

        Returns:
            Every message still held in ``buf``, DATA runs first, each reported
            :attr:`~pcapkit.foundation.reassembly.data.Completion.TIMEOUT` or
            :attr:`~pcapkit.foundation.reassembly.data.Completion.PARTIAL`, since
            a message is reported as it completes.

        """
        held = [*{id(frag): frag for frag in buf.tsn.values()}.values(), *buf.msg.values()]
        completion = Completion.TIMEOUT if expired else Completion.PARTIAL
        ret = [self._datagram_from_fragment(frag, bufid, completion) for frag in held]
        return self._notify(ret, store=store)

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _add_data(self, buf: 'Buffer', info: 'Packet[_AT]') -> 'Optional[Fragment]':
        """Add a DATA fragment to the run of consecutive TSNs it extends.

        Arguments:
            buf: buffer the fragment is held under
            info: the fragment

        Returns:
            The message the fragment completes, taken out of ``buf``, or
            :data:`None` if it completes none.

        """
        TSN = info.tsn  # Transmission Sequence Number

        held = buf.tsn.get(TSN)
        if held is not None:
            held.ind.append(info.num)
            return None

        frag = Fragment(
            ind=[info.num],
            chunk=info.chunk,
            stream_id=info.stream_id,
            unordered=info.unordered,
            # NOTE: the receiver ignores an unordered chunk's stream sequence number (RFC 9260 3.3.1).
            ssn=None if info.unordered else info.ssn,
            mid=None,
            ppid=info.ppid,
            src=info.src,
            dst=info.dst,
            head=TSN,
            tail=TSN,
            beginning=info.beginning,
            ending=info.ending,
            parts={TSN: (TSN, info.payload)},
        )
        buf.tsn[TSN] = frag

        # NOTE: ``TSN`` was not held, so a run holding a neighbour ends or starts there.
        lower = buf.tsn.get((TSN - 1) % 0x100000000)
        if lower is not None and self._continues(lower, frag):
            frag = self._merge(buf, lower, frag)
        upper = buf.tsn.get((TSN + 1) % 0x100000000)
        if upper is not None and self._continues(frag, upper):
            frag = self._merge(buf, frag, upper)

        if not self._complete(frag):
            return None
        for seq in frag.parts:
            del buf.tsn[seq]
        return frag

    @staticmethod
    def _continues(lower: 'Fragment', upper: 'Fragment') -> 'bool':
        """Whether one run of DATA fragments carries on the message of the run
        just below it in TSN.

        Arguments:
            lower: the run whose last TSN is just below ``upper``'s first
            upper: the run that may carry on ``lower``'s message

        Returns:
            :data:`True` unless ``lower`` ends a message, ``upper`` begins one,
            or the two differ in stream, ``U`` bit or, when ordered, stream
            sequence number, which every fragment of a message shares
            (:rfc:`9260#section-6.9`).

        """
        return (not lower.ending and not upper.beginning
                and lower.stream_id == upper.stream_id
                and lower.unordered == upper.unordered
                and lower.ssn == upper.ssn)

    @staticmethod
    def _merge(buf: 'Buffer', lower: 'Fragment', upper: 'Fragment') -> 'Fragment':
        """Join two adjacent runs of DATA fragments into one.

        Arguments:
            buf: buffer the runs are held under, whose TSNs are re-pointed
            lower: the run whose last TSN is just below ``upper``'s first
            upper: the run carrying on ``lower``'s message

        Returns:
            The joined run: the longer of the two, grown by the other, so only
            the shorter one's TSNs are re-pointed.

        """
        (kept, gone) = (lower, upper) if len(lower.parts) >= len(upper.parts) else (upper, lower)
        kept.parts.update(gone.parts)
        kept.ind.extend(gone.ind)
        kept.__update__(ppid=lower.ppid, src=lower.src, dst=lower.dst, head=lower.head,
                        beginning=lower.beginning, tail=upper.tail, ending=upper.ending)
        for seq in gone.parts:
            buf.tsn[seq] = kept
        return kept

    def _add_idata(self, buf: 'Buffer', info: 'Packet[_AT]') -> 'Optional[Fragment]':
        """Add an I-DATA fragment to the message its message ID names.

        Arguments:
            buf: buffer the fragment is held under
            info: the fragment

        Returns:
            The message the fragment completes, taken out of ``buf``, or
            :data:`None` if it completes none.

        """
        MID = (info.stream_id, info.unordered, cast('int', info.mid))  # Message ID
        FSN = cast('int', info.fsn)                                     # Fragment Sequence Number

        frag = buf.msg.get(MID)
        if frag is None:
            frag = Fragment(
                ind=[],
                chunk=info.chunk,
                stream_id=info.stream_id,
                unordered=info.unordered,
                ssn=None,
                mid=info.mid,
                ppid=None,
                src=info.src,
                dst=info.dst,
                head=FSN,
                tail=FSN,
                beginning=info.beginning,
                ending=info.ending,
                parts={},
            )
            buf.msg[MID] = frag

        frag.ind.append(info.num)
        if FSN in frag.parts:
            return None
        frag.parts[FSN] = (info.tsn, info.payload)

        # NOTE: only the first fragment carries the payload protocol identifier (RFC 8260 2.1).
        if info.beginning:
            frag.__update__(ppid=info.ppid)
        # NOTE: an FSN is compared as a count from 0; wrapping it takes a message of 2**32 fragments.
        if FSN <= frag.head:
            frag.__update__(src=info.src, dst=info.dst, head=FSN, beginning=info.beginning)
        if FSN >= frag.tail:
            frag.__update__(tail=FSN, ending=info.ending)

        if not self._complete(frag):
            return None
        del buf.msg[MID]
        return frag

    @staticmethod
    def _complete(frag: 'Fragment') -> 'bool':
        """Whether a message under construction is whole.

        Arguments:
            frag: the message under construction

        Returns:
            :data:`True` if its lowest fragment has the ``B`` bit set, its
            highest the ``E`` bit, and every sequence number between them is
            held.

        """
        return (frag.beginning and frag.ending
                and len(frag.parts) == (frag.tail - frag.head) % 0x100000000 + 1)

    def _datagram_from_fragment(self, frag: 'Fragment', bufid: 'BufferID',
                                completion: 'Completion') -> 'Datagram[_AT]':
        """Build a :class:`~pcapkit.foundation.reassembly.sctp.data.Datagram`
        from a message's buffered :class:`~pcapkit.foundation.reassembly.sctp.data.Fragment`.

        Arguments:
            frag: message under construction to report
            bufid: buffer identifier it was held under
            completion: how completely it was reassembled

        Returns:
            The reassembled (or partially reassembled) message. Its ``packet``
            is the parse :func:`~pcapkit.foundation.analysis.sctp.sctp_message`
            runs, by this reassembly's own
            :attr:`protocol <pcapkit.foundation.reassembly.reassembly.Reassembly.protocol>`,
            deferred to its first read, for a contiguous payload, and
            :data:`None` for the tuple of runs ``strict=True`` reports.

        """
        order = sorted(frag.parts, key=lambda seq: (seq - frag.head) % 0x100000000)
        runs = []  # type: list[list[bytes]]
        for (pos, seq) in enumerate(order):
            if not pos or (seq - order[pos - 1]) % 0x100000000 != 1:
                runs.append([])
            runs[-1].append(frag.parts[seq][1])
        received = tuple(b''.join(run) for run in runs)

        if completion or not self._flag_s:
            # NOTE: the length of a missing fragment is unknown, so a hole cannot be zero-filled.
            octets = received[0] if frag.beginning else b''
            payload = octets  # type: bytes | tuple[bytes, ...]
            packet = Deferred(partial(_analyze_payload, self.protocol, **self._parse_keywords),
                              frag.ppid, octets)  # type: Optional[Deferred]
        else:
            payload, packet = received, None

        return Datagram(
            completed=completion,
            id=DatagramID(
                src=frag.src,
                sport=bufid[0],
                dst=frag.dst,
                dport=bufid[1],
                vtag=bufid[2],
            ),
            index=tuple(sorted(set(frag.ind))),
            chunk=frag.chunk,
            stream_id=frag.stream_id,
            unordered=frag.unordered,
            ssn=frag.ssn,
            mid=frag.mid,
            tsn=tuple(frag.parts[seq][0] for seq in order),
            ppid=frag.ppid,
            payload=payload,
            packet=packet,
        )
