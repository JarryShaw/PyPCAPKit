# -*- coding: utf-8 -*-
"""DTLS Handshake-Message Reassembly
=======================================

.. module:: pcapkit.foundation.reassembly.dtls

:mod:`pcapkit.foundation.reassembly.dtls` contains
:class:`~pcapkit.foundation.reassembly.dtls.DTLS` only, which reconstructs a
DTLS handshake message split across several records back to origin
(:rfc:`6347#section-4.2.3`). A byte range is punched out of the message's
hole list as each fragment arrives, and the message is whole once no hole
remains.

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING, Generic

from pcapkit.foundation.reassembly.data.data import Completion
from pcapkit.foundation.reassembly.data.dtls import (_AT, Buffer, BufferID, Datagram, DatagramID,
                                                     Fragment, HoleDescriptor, Packet)
from pcapkit.foundation.reassembly.reassembly import ReassemblyBase

if TYPE_CHECKING:
    from typing import Optional

__all__ = ['DTLS']


class DTLS(ReassemblyBase[Packet[_AT], Datagram[_AT], BufferID, Buffer], Generic[_AT]):  # pylint: disable=abstract-method
    """Reassembly for DTLS handshake messages.

    Args:
        strict: if :data:`True`, report a message that is not completely
            reassembled as the tuple of its received runs; otherwise as one
            contiguous payload, its holes zero-filled
        store: if store reassembled datagram in memory, i.e.,
            :attr:`self._dtgram <pcapkit.foundation.reassembly.reassembly.Reassembly._dtgram>`
            (if not, datagram will be discarded after callback)
        timeout: reassembly timeout in seconds, on the capture's own clock;
            :data:`None` selects :attr:`__timeout__`

    Note:
        The buffer ID is the UDP 5-tuple plus the DTLS **epoch**: the record
        sequence number resets on each cipher-state change
        (:rfc:`6347#section-4.1`), so a new epoch opens a fresh buffer.
        Overlapping fragments are accepted
        (:rfc:`6347#section-4.2.3`, :rfc:`9147#section-5.5`). Not toolkit-fed:
        a protocol instance never sees the addresses, so a caller supplies the
        5-tuple as ``flow`` to :meth:`DTLS.read
        <pcapkit.protocols.application.dtls.DTLS.read>`.

    Example:
        >>> from pcapkit.foundation.reassembly.dtls import DTLS
        # Initialise instance:
        >>> dtls_reassembly = DTLS()
        # Call reassembly:
        >>> dtls_reassembly(packet_dict)
        # Fetch result:
        >>> result = dtls_reassembly.datagram

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol name of current reassembly object. Not set via
    #: ``__protocol_type__``, which would import
    #: :class:`~pcapkit.protocols.application.dtls.DTLS` at class-definition
    #: time; :class:`~pcapkit.foundation.reassembly.reassembly.ReassemblyMeta`
    #: looks :attr:`name` up in the protocol registry instead.
    __protocol_name__ = 'DTLS'

    #: float: Default reassembly timeout, in seconds, on the capture's clock.
    #: Not :data:`math.inf`: a DTLS handshake is not open-ended.
    #: :rfc:`6347#section-4.2.4.1` gives 60 seconds only as
    #: the floor a retransmission backoff's cap must not go below, so 120
    #: seconds leaves room for a live handshake while still expiring a stale
    #: one. The deadline runs from each buffer's latest fragment; ``timeout``
    #: overrides it.
    __timeout__ = 120.0

    ##########################################################################
    # Methods.
    ##########################################################################

    def __init__(self, *, strict: 'bool' = True, store: 'bool' = True,
                 timeout: 'Optional[float]' = None) -> 'None':
        """Initialise packet reassembly.

        Args:
            strict: if :data:`True`, report a message that is not completely
                reassembled as the tuple of its received runs; otherwise as
                one contiguous payload, its holes zero-filled
            store: if store reassembled datagram in memory
            timeout: reassembly timeout in seconds, on the capture's own
                clock; :data:`None` selects :attr:`__timeout__`

        """
        super().__init__(strict=strict, store=store, timeout=timeout)

        #: Optional[Datagram[_AT]]: The message, if any, that the most recent
        #: call to :meth:`reassembly` completed; see :attr:`last`.
        self._last: 'Optional[Datagram[_AT]]' = None

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def last(self) -> 'Optional[Datagram[_AT]]':
        """The message reassembled by the most recent call to
        :meth:`reassembly`, or :data:`None` if that fragment did not complete
        one.

        This is a synchronous alternative to :attr:`datagram`/:meth:`fetch`
        for a caller -- :meth:`DTLS.read
        <pcapkit.protocols.application.dtls.DTLS.read>` is the one that
        exists -- that wants to know, immediately after feeding one fragment,
        whether *that* fragment was the one that completed its message,
        rather than waiting for the buffer (which may hold several other
        messages still in flight under the same buffer ID) to be flushed.

        """
        return self._last

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
        self._last = None

        BUFID = info.bufid          # Buffer Identifier
        MSN = info.message_seq      # Message Sequence Number
        FO = info.fragment_offset   # Fragment Offset
        FL = info.fragment_length   # Fragment Length
        TS = info.timestamp         # Capture timestamp, i.e. the only clock we have

        # This fragment's arrival is the evidence that capture time has
        # reached ``TS``, so abandon whatever the deadline has passed for,
        # including buffers this fragment does not belong to.
        self._dtgram.extend(self.expire(TS))

        buf = self._buffer.get(BUFID)
        if buf is None:
            buf = Buffer(msg={}, timestamp=TS)
        else:
            # :meth:`expire` abandons a buffer by one ``timestamp``, but a
            # buffer holds several in-flight messages (:attr:`Buffer.msg`)
            # with no shared deadline. Pinning that timestamp to the first
            # fragment lets a stale message expire a live one, so every
            # fragment under this ``BufferID`` refreshes it: an idle timeout.
            # ``max`` tolerates non-monotonic capture timestamps.
            buf = Buffer(msg=buf.msg, timestamp=max(buf.timestamp, TS))
        self._buffer[BUFID] = buf

        frag = buf.msg.get(MSN)
        # A fresh buffer for this MSN, or a disagreement with the one held
        # there: a different ``length`` or ``msg_type`` means this fragment
        # cannot belong to the message under construction. A reused 4-tuple
        # restarts ``message_seq`` at 0 (:rfc:`6347#section-4.2.2`). Restarting
        # prevents merging disagreeing fragments. Known limitation: a late
        # fragment of the displaced message whose length and msg_type match
        # the new one can still splice into it.
        if frag is None or frag.length != info.length or frag.msg_type != info.msg_type:
            if frag is not None:
                # The displaced partial is reported as PARTIAL rather than dropped.
                self._dtgram.extend(self.submit(Buffer(msg={MSN: frag}, timestamp=buf.timestamp),
                                                bufid=BUFID))
            length = info.length
            frag = Fragment(
                ind=[],
                msg_type=info.msg_type,
                length=length,
                raw=bytearray(length),
                hdl=([HoleDescriptor(first=0, last=length - 1)] if length else []),
            )
            buf.msg[MSN] = frag

        frag.ind.append(info.num)

        # The fragment's data length is what its header declares, but only
        # the octets the capture actually holds can be written, and a write
        # past the message's own declared length is clipped.
        held = max(min(len(info.payload), FL, len(frag.raw) - FO), 0)
        if held:
            stop = FO + held
            frag.raw[FO:stop] = info.payload[:held]
            self._update_hole_descriptors(frag.hdl, FO, stop - 1)

        # the message is whole once no hole remains
        if not frag.hdl:
            del buf.msg[MSN]
            if not buf.msg:
                buf = self._buffer.pop(BUFID)

            datagram = self._datagram_from_fragment(frag, BUFID, MSN, Completion.COMPLETE)
            self._dtgram.append(datagram)
            self._last = datagram

            for callback in self.__callback_fn__:
                callback([datagram])

    def submit(self, buf: 'Buffer', *, bufid: 'BufferID', checked: 'bool' = False, timeout: 'bool' = False) -> 'list[Datagram[_AT]]':  # type: ignore[override] # pylint: disable=arguments-differ,unused-argument,line-too-long
        """Submit reassembled payload.

        Arguments:
            buf: buffer dict of reassembled packets
            bufid: buffer identifier
            checked: unused; every message's completeness is decided from its
                own hole list, so there is nothing for a caller to assert
                ahead of time
            timeout: whether this buffer is being submitted because
                :meth:`~pcapkit.foundation.reassembly.reassembly.Reassembly.expire`
                abandoned it under the reassembly timeout

        Returns:
            Every message still held in ``buf``, each reported
            :attr:`~pcapkit.foundation.reassembly.data.data.Completion.COMPLETE`
            if its hole list is empty, otherwise
            :attr:`~pcapkit.foundation.reassembly.data.data.Completion.TIMEOUT`
            or :attr:`~pcapkit.foundation.reassembly.data.data.Completion.PARTIAL`.

        """
        ret = []  # type: list[Datagram[_AT]]
        for (msn, frag) in buf.msg.items():
            if not frag.hdl:
                completion = Completion.COMPLETE
            else:
                completion = Completion.TIMEOUT if timeout else Completion.PARTIAL
            ret.append(self._datagram_from_fragment(frag, bufid, msn, completion))

        for callback in self.__callback_fn__:
            callback(ret)
        return ret

    def _datagram_from_fragment(self, frag: 'Fragment', bufid: 'BufferID', message_seq: 'int',
                                completion: 'Completion') -> 'Datagram[_AT]':
        """Build a :class:`~pcapkit.foundation.reassembly.data.dtls.Datagram`
        from a message's buffered :class:`~pcapkit.foundation.reassembly.data.dtls.Fragment`.

        Arguments:
            frag: message-under-construction to report
            bufid: buffer identifier it was held under
            message_seq: its message sequence number
            completion: how completely it was reassembled

        Returns:
            The reassembled (or partially reassembled) message.

        """
        if completion:
            payload = bytes(frag.raw)  # type: 'bytes | tuple[bytes, ...]'
        elif self._flag_s:
            payload = self._received_runs(frag)
        else:
            payload = bytes(frag.raw)

        return Datagram(
            completed=completion,
            id=DatagramID(
                src=bufid[0],
                sport=bufid[1],
                dst=bufid[2],
                dport=bufid[3],
                epoch=bufid[4],
            ),
            index=tuple(frag.ind),
            message_seq=message_seq,
            msg_type=frag.msg_type,
            length=frag.length,
            body=payload,
        )

    @staticmethod
    def _received_runs(frag: 'Fragment') -> 'tuple[bytes, ...]':
        """Extract the octet runs actually received, for ``strict=True``'s
        report of an incomplete message.

        Arguments:
            frag: message-under-construction to extract runs from

        Returns:
            Received octet runs, in offset order; empty runs (a hole butting
            straight up against the start, the end, or another hole) are left
            out.

        """
        runs = []  # type: list[bytes]
        pos = 0
        for hole in sorted(frag.hdl, key=lambda hole: hole.first):
            if hole.first > pos:
                runs.append(bytes(frag.raw[pos:hole.first]))
            pos = max(pos, hole.last + 1)
        if pos < frag.length:
            runs.append(bytes(frag.raw[pos:frag.length]))
        return tuple(run for run in runs if run)

    @staticmethod
    def _update_hole_descriptors(hdl: 'list[HoleDescriptor]', first: 'int', last: 'int') -> 'None':
        """Punch a received byte range out of a message's hole list.

        Offsets are message-relative and inclusive. They never wrap and need
        no open upper bound, since every fragment of a message declares the
        same total ``length`` (:rfc:`6347#section-4.2.3`).

        Arguments:
            hdl: the message's hole descriptor list, mutated in place
            first: offset of the first octet the arriving fragment actually
                held
            last: offset of the last octet the arriving fragment actually
                held, inclusive

        """
        new_hdl = []  # type: list[HoleDescriptor]
        for hole in hdl:                                    # step one
            if first > hole.last or last < hole.first:      # steps two and three
                new_hdl.append(hole)
                continue
            # step four: this hole is (partly) filled and replaced by what of
            # it survives, on either side of the arriving range
            if first > hole.first:                          # step five
                new_hdl.append(HoleDescriptor(first=hole.first, last=first - 1))
            if last < hole.last:                             # step six
                new_hdl.append(HoleDescriptor(first=last + 1, last=hole.last))
            # step seven: go on to the next hole, since one fragment may span
            # several of them
        hdl[:] = new_hdl
