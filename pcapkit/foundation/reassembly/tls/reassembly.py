# -*- coding: utf-8 -*-
"""TLS Record Reassembly
===========================

.. module:: pcapkit.foundation.reassembly.tls.reassembly

:mod:`pcapkit.foundation.reassembly.tls.reassembly` contains
:class:`~pcapkit.foundation.reassembly.tls.reassembly.TLS` only, which reconstructs
the TLS records of a TCP stream, a record split across segments included
(:rfc:`9846#section-5`).

.. versionadded:: 1.9.0

"""
from typing import TYPE_CHECKING, Generic

from pcapkit.foundation.reassembly.data import Completion, Deferred
from pcapkit.foundation.reassembly.reassembly import ReassemblyBase
from pcapkit.foundation.reassembly.tcp.data import Packet as TCP_Packet
from pcapkit.foundation.reassembly.tls.data import _AT, Buffer, BufferID, Datagram, DatagramID, Run
from pcapkit.protocols.application.tls.protocol import TLS as TLS_Protocol
from pcapkit.utilities.exceptions import CaughtByCaller, ProtocolError
from pcapkit.utilities.seqnum import unwrap

if TYPE_CHECKING:
    from typing import Optional, Type

    from pcapkit.const.tls.content_type import ContentType as Enum_ContentType

__all__ = ['TLS']


class TLS(ReassemblyBase[TCP_Packet, Datagram[_AT], BufferID, Buffer], Generic[_AT]):  # pylint: disable=abstract-method
    """Reassembly for TLS records.

    Args:
        strict: if :data:`True`, report a record that is not completely
            reassembled as the tuple of its fragment's received runs; otherwise
            as one contiguous fragment, its holes zero-filled
        store: if store reassembled datagram in memory, i.e.,
            :attr:`self._dtgram <pcapkit.foundation.reassembly.reassembly.Reassembly._dtgram>`
            (if not, datagram will be discarded after callback)
        timeout: reassembly timeout in seconds, on the capture's own clock;
            :data:`None` selects
            :attr:`~pcapkit.foundation.reassembly.reassembly.Reassembly.__timeout__`,
            which for TLS disables expiry

    Note:
        Over TCP a record is delimited by its header alone (:rfc:`9846#section-5.1`),
        so each direction of a connection is followed as one octet stream, from a
        record boundary, and cut into records by
        :meth:`TLS.record_header <pcapkit.protocols.application.tls.protocol.TLS.record_header>`.
        Every record is reported, the ones a segment holds whole included, since a
        boundary is known only from the record before it.

        The stream is the segments' octets in sequence order (:rfc:`9293#section-3.4`).
        A segment ahead of the octets held waits for those before it, and of
        octets received twice the first are kept (:rfc:`9293#section-3.10`). A
        record is reported once whole. One the stream ends inside -- at its FIN,
        an RST or the end of the capture -- is reported incomplete, and so is
        one a lost segment left a hole in, as the records after it are.

        The :class:`~pcapkit.foundation.extraction.Extractor` feeds it TCP
        reassembly's :term:`reasm.tcp.packet` of every segment on a port
        :attr:`TCP.__proto__ <pcapkit.protocols.transport.tcp.protocol.TCP.__proto__>`
        binds to TLS, through :func:`pcapkit.toolkit.pcap.tls_reassembly` and its
        siblings, and :func:`~pcapkit.foundation.analysis.tls.tls_record` decodes
        what it reassembles. A complete record's
        :attr:`~pcapkit.foundation.reassembly.tls.data.Datagram.packet` holds the
        same decode, run on first read; both call the protocol's
        :meth:`~pcapkit.protocols.application.tls.protocol.TLS.analyze_record`, the
        ``packet`` that of :attr:`__protocol_type__`.

    Warning:
        **Where the stream starts.** With its SYN captured, the stream is followed
        from the octet after it, a record boundary. Without it, and again after
        octets that open no record, the boundary is a guess: the first segment
        arriving whose payload opens a record header, by
        :meth:`TLS.record_header <pcapkit.protocols.application.tls.protocol.TLS.record_header>`,
        is taken to open a record, and the octets before it are not reported.
        Octets past a hole that covers a record header cannot be cut into
        records, and are not reported either.

        **What the guess can get wrong.** The header's length may not exceed
        ``2 ** 14 + 2048`` (:rfc:`5246#section-6.2.3`), so a segment whose first
        octets declare a longer record, as ``17 03 03 ff ff`` would, opens no
        stream. Ciphertext or a record's tail whose first five octets read as a
        header within that bound still does: the records cut from it are false,
        and those of the real stream behind it, up to the next octets that open no
        record, are lost.

        **Where it ends.** A FIN or an RST closes the stream, and a later segment
        on the same endpoints is ignored unless it is a SYN.

    Example:
        >>> from pcapkit.foundation.reassembly.tls.reassembly import TLS
        # Initialise instance:
        >>> tls_reassembly = TLS()
        # Call reassembly:
        >>> tls_reassembly(packet_dict)
        # Fetch result:
        >>> result = tls_reassembly.datagram

    """
    if TYPE_CHECKING:
        protocol: 'Type[TLS_Protocol]'

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol name of current reassembly object.
    __protocol_name__ = 'TLS'
    #: Protocol of current reassembly object. An extension point -- a protocol
    #: named here need only define ``record_header`` and ``analyze_record``, with
    #: the signatures of :meth:`TLS.record_header
    #: <pcapkit.protocols.application.tls.protocol.TLS.record_header>` and
    #: :meth:`TLS.analyze_record
    #: <pcapkit.protocols.application.tls.protocol.TLS.analyze_record>`.
    __protocol_type__ = TLS_Protocol

    # No ``__timeout__``: neither RFC 9846 nor RFC 9293 gives a record a deadline,
    # so it inherits the base default, ``math.inf``, as TCP reassembly does.

    ##########################################################################
    # Methods.
    ##########################################################################

    def reassembly(self, info: 'TCP_Packet') -> 'None':
        """Reassembly procedure.

        Arguments:
            info: :term:`info <reasm.tcp.packet>` record of the segment to be
                reassembled

        Note:
            The records the segment completes are reported before its RST, or
            the FIN it completes the stream to, releases the buffer. So a
            callback raising on one of them leaves the buffer in place, holding
            the octets after them, and nothing is lost.

        """
        # clear cache
        self._flag_n = False
        self.__cached__.clear()

        BUFID = info.bufid   # Buffer Identifier
        TS = info.timestamp  # Capture timestamp, i.e. the only clock we have
        self.expire(TS)

        # NOTE: a SYN occupies a sequence number of its own (RFC 9293, section 3.4).
        PSN = info.dsn + 1 if info.syn else info.dsn

        # A SYN opens a connection, whose first octet a record opens.
        if info.syn:
            old = self._buffer.pop(BUFID, None)
            self._buffer[BUFID] = Buffer(boundary=PSN, runs=[], ind=[], fin=None, closed=False, timestamp=TS)
            if old is not None:
                self._release(old, bufid=BUFID)

        buf = self._buffer.get(BUFID)
        if buf is None:
            if not self._opens_record(info.payload):
                return
            buf = Buffer(boundary=PSN, runs=[], ind=[], fin=None, closed=False, timestamp=TS)
            self._buffer[BUFID] = buf
        elif buf.closed:
            return

        FIRST = unwrap(PSN, buf.boundary)
        # NOTE: a FIN below the boundary contradicts the records already cut, so it is ignored.
        if info.fin and buf.fin is None and FIRST + info.len >= buf.boundary:
            buf.__update__(fin=FIRST + info.len)
            self._close_runs(buf, FIRST + info.len)
        if info.len:
            self._hold_segment(buf, FIRST, bytes(info.payload), info.num)

        records, framed = self._cut_records(buf, BUFID)
        if not framed:
            # NOTE: what follows octets that open no record cannot be cut into records.
            del self._buffer[BUFID]
        if records:
            self._notify(records, store=True)
        if not framed:
            return

        # An RST closes the connection at once (RFC 9293, section 3.10.7.4), and a FIN
        # once every octet before it is held.
        if info.rst or self._stream_whole(buf):
            self._buffer[BUFID] = Buffer(boundary=buf.boundary, runs=[], ind=[], fin=buf.fin,
                                         closed=True, timestamp=TS)
            self._release(buf, bufid=BUFID)

    def submit(self, buf: 'Buffer', *, bufid: 'BufferID', expired: 'bool' = False,  # type: ignore[override] # pylint: disable=arguments-differ
               store: 'bool' = False) -> 'list[Datagram[_AT]]':
        """Submit reassembled payload.

        Arguments:
            buf: :term:`buffer <reasm.tls.buffer>` of the stream
            bufid: buffer identifier
            expired: whether this buffer is being submitted because
                :meth:`~pcapkit.foundation.reassembly.reassembly.Reassembly.expire`
                abandoned it under the reassembly timeout
            store: whether ``buf`` has left
                :attr:`~pcapkit.foundation.reassembly.reassembly.Reassembly._buffer`
                for good, so its records join
                :attr:`~pcapkit.foundation.reassembly.reassembly.Reassembly._dtgram`
                before the callbacks run, and one that raises cannot lose them

        Returns:
            Every record still held in ``buf`` whose header is, in sequence
            order up to the first hole a header lies in, each reported
            :attr:`~pcapkit.foundation.reassembly.data.Completion.COMPLETE` if
            its fragment is whole, otherwise
            :attr:`~pcapkit.foundation.reassembly.data.Completion.TIMEOUT` or
            :attr:`~pcapkit.foundation.reassembly.data.Completion.PARTIAL`.

        """
        ret = []  # type: list[Datagram[_AT]]
        start = buf.boundary
        while True:
            run = next((run for run in buf.runs if run.first <= start < run.first + len(run.raw)), None)
            if run is None:
                break
            try:
                header = self._read_header(run.raw[start - run.first:])
            except ProtocolError:
                break
            if header is None:
                break

            lo = start + header[2]
            hi = lo + header[3]
            pieces = [(max(held.first, lo), bytes(held.raw[max(held.first, lo) - held.first:hi - held.first]))
                      for held in buf.runs if held.first < hi and held.first + len(held.raw) > lo]
            fragment = b''.join(piece for (_, piece) in pieces)  # type: bytes | tuple[bytes, ...]
            if len(fragment) == header[3]:
                completion = Completion.COMPLETE
            else:
                completion = Completion.TIMEOUT if expired else Completion.PARTIAL
                if self._flag_s:
                    fragment = tuple(piece for (_, piece) in pieces)
                else:
                    filled = bytearray(header[3])
                    for (pos, piece) in pieces:
                        filled[pos - lo:pos - lo + len(piece)] = piece
                    fragment = bytes(filled)
            ret.append(self._make_datagram(buf, bufid, start, header, completion, fragment))
            start = hi

        # NOTE: an open stream holding no record, or a closed one, reports none and runs no callback.
        if not ret:
            return ret
        return self._notify(ret, store=store)

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_header(self, data: 'bytes | bytearray') -> 'Optional[tuple[Enum_ContentType, int, int, int]]':
        """Read the header of the record ``data`` opens.

        Arguments:
            data: octets from a record boundary on

        Returns:
            As :meth:`TLS.record_header
            <pcapkit.protocols.application.tls.protocol.TLS.record_header>` of
            :attr:`__protocol_type__` returns it.

        Raises:
            ProtocolError: If the header opens no record, constructed quietly,
                since the caller handles it.

        """
        with CaughtByCaller(ProtocolError):
            return self.protocol.record_header(data)  # type: ignore[arg-type]

    def _opens_record(self, data: 'bytes | bytearray') -> 'bool':
        """Whether a segment's payload opens a record header.

        Arguments:
            data: the segment's payload

        Returns:
            Whether a whole record header opens ``data``.

        """
        try:
            return self._read_header(data) is not None
        except ProtocolError:
            return False

    @staticmethod
    def _close_runs(buf: 'Buffer', end: 'int') -> 'None':
        """Drop the octets held at or past the FIN.

        Arguments:
            buf: :term:`buffer <reasm.tls.buffer>` of the stream
            end: unwrapped sequence number the stream ends at, its
                :attr:`~Buffer.fin`

        """
        runs = []  # type: list[Run]
        for run in buf.runs:
            if run.first < end:
                del run.raw[end - run.first:]
                runs.append(run)
        buf.runs[:] = runs
        buf.ind[:] = [(num, first, min(stop, end)) for (num, first, stop) in buf.ind if first < end]

    @staticmethod
    def _hold_segment(buf: 'Buffer', first: 'int', payload: 'bytes', num: 'int') -> 'None':
        """Hold the octets of a segment that no earlier segment brought.

        Arguments:
            buf: :term:`buffer <reasm.tls.buffer>` of the stream
            first: unwrapped sequence number of the segment's first octet
            payload: the segment's payload
            num: the segment's packet number

        Octets before :attr:`~Buffer.boundary` were cut into records already,
        and octets at or past :attr:`~Buffer.fin` are not the stream's, so
        neither is held. Of octets already held the first received are kept,
        and only the new parts are processed (:rfc:`9293#section-3.10`).

        """
        lo = max(first, buf.boundary)
        hi = first + len(payload)
        if buf.fin is not None:
            hi = min(hi, buf.fin)

        parts = []  # type: list[tuple[int, int]]
        pos = lo
        for run in buf.runs:
            start, stop = run.first, run.first + len(run.raw)
            if pos >= hi or start >= hi:
                break
            if stop <= pos:
                continue
            if start > pos:
                parts.append((pos, start))
            pos = stop
        if pos < hi:
            parts.append((pos, hi))

        for (start, stop) in parts:
            TLS._hold_octets(buf.runs, start, payload[start - first:stop - first])
            buf.ind.append((num, start, stop))

    @staticmethod
    def _hold_octets(runs: 'list[Run]', first: 'int', octets: 'bytes') -> 'None':
        """Add octets no run holds to the runs, merging the runs they adjoin.

        Arguments:
            runs: runs held, in sequence order, mutated in place
            first: unwrapped sequence number of the first octet
            octets: the octets

        """
        index = 0
        while index < len(runs) and runs[index].first < first:
            index += 1
        if index and runs[index - 1].first + len(runs[index - 1].raw) == first:
            run = runs[index - 1]
            run.raw.extend(octets)
        else:
            run = Run(first=first, raw=bytearray(octets))
            runs.insert(index, run)
            index += 1
        if index < len(runs) and run.first + len(run.raw) == runs[index].first:
            run.raw.extend(runs.pop(index).raw)

    def _cut_records(self, buf: 'Buffer', bufid: 'BufferID') -> 'tuple[list[Datagram[_AT]], bool]':
        """Cut the whole records held from :attr:`~Buffer.boundary` on off the stream.

        Arguments:
            buf: :term:`buffer <reasm.tls.buffer>` of the stream, mutated in place
            bufid: buffer identifier

        Returns:
            The records cut, each
            :attr:`~pcapkit.foundation.reassembly.data.Completion.COMPLETE`, and
            whether the octets after them can still be cut: :data:`False` once
            they open no record.

        """
        records = []  # type: list[Datagram[_AT]]
        while buf.runs and buf.runs[0].first == buf.boundary:
            run = buf.runs[0]
            try:
                header = self._read_header(run.raw)
            except ProtocolError:
                return records, False
            if header is None:
                break
            size = header[2] + header[3]
            if len(run.raw) < size:
                break
            records.append(self._make_datagram(buf, bufid, buf.boundary, header, Completion.COMPLETE,
                                               bytes(run.raw[header[2]:size])))

            end = buf.boundary + size
            del run.raw[:size]
            if run.raw:
                run.__update__(first=end)
            else:
                del buf.runs[0]
            buf.__update__(boundary=end)
            buf.ind[:] = [entry for entry in buf.ind if entry[2] > end]
        return records, True

    @staticmethod
    def _stream_whole(buf: 'Buffer') -> 'bool':
        """Whether a stream has seen its FIN and every octet before it.

        Arguments:
            buf: :term:`buffer <reasm.tls.buffer>` of the stream

        Returns:
            :data:`True` once a FIN has been seen and every octet from
            :attr:`~Buffer.boundary` up to it is held.

        """
        if buf.fin is None:
            return False
        if buf.boundary >= buf.fin:
            return True
        return (len(buf.runs) == 1 and buf.runs[0].first == buf.boundary
                and buf.runs[0].first + len(buf.runs[0].raw) == buf.fin)

    def _make_datagram(self, buf: 'Buffer', bufid: 'BufferID', start: 'int',
                       header: 'tuple[Enum_ContentType, int, int, int]', completion: 'Completion',
                       fragment: 'bytes | tuple[bytes, ...]') -> 'Datagram[_AT]':
        """Build a :class:`~pcapkit.foundation.reassembly.tls.data.Datagram` for a record.

        Arguments:
            buf: :term:`buffer <reasm.tls.buffer>` the record was held in
            bufid: buffer identifier it was held under
            start: unwrapped sequence number of the record's first octet
            header: the record's header, as :meth:`_read_header` reads it
            completion: how completely it was reassembled
            fragment: its fragment, as the record reports it

        Returns:
            The record. Its ``packet`` is the decode
            :func:`~pcapkit.foundation.analysis.tls.tls_record` runs, by this
            reassembly's own
            :attr:`protocol <pcapkit.foundation.reassembly.reassembly.Reassembly.protocol>`,
            deferred to its first read, if the record is complete, and
            :data:`None` otherwise, as that function returns.

        """
        content_type, version, header_length, length = header
        stop = start + header_length + length
        index = tuple(dict.fromkeys(num for (num, first, last) in buf.ind if first < stop and last > start))

        packet = None  # type: Optional[Deferred[tuple[Enum_ContentType, int]]]
        if completion:
            packet = Deferred(self.protocol.analyze_record, (content_type, version), fragment)  # type: ignore[arg-type]

        return Datagram(
            completed=completion,
            id=DatagramID(
                src=(bufid[0], bufid[1]),
                dst=(bufid[2], bufid[3]),
                seq=start & 0xFFFFFFFF,
            ),
            index=index,
            content_type=content_type,
            version=version,
            length=length,
            fragment=fragment,
            packet=packet,
        )
