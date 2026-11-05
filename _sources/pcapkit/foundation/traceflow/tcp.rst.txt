Follow TCP Stream
=================

.. module:: pcapkit.foundation.traceflow.tcp

:mod:`pcapkit.foundation.traceflow.tcp` traces TCP flows from a series of
packets.

.. autoclass:: pcapkit.foundation.traceflow.tcp.TCP
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: protocol

   .. automethod:: dump
   .. automethod:: make_bufid
   .. automethod:: trace
   .. automethod:: finish
   .. automethod:: submit

   .. autoattribute:: __protocol_name__
   .. autoattribute:: __protocol_type__
   .. autoattribute:: __callback_fn__
      :no-value:

   .. automethod:: _make_segment
   .. automethod:: _unique_label
   .. automethod:: _ended

Terminology
-----------

.. glossary::

   trace.tcp.packet
       Data structure for **TCP flow tracing**
       (:meth:`TraceFlow.dump <pcapkit.foundation.traceflow.traceflow.TraceFlow.dump>`)
       is as follows:

       .. code-block:: python

          trace_dict = dict(
              protocol=data_link,                     # data link type from global header
              index=frame.info.number,                # frame number
              frame=frame.info,                       # extracted frame info
              syn=tcp.flags.syn,                      # TCP synchronise (SYN) flag
              fin=tcp.flags.fin,                      # TCP finish (FIN) flag
              rst=tcp.flags.rst,                      # TCP reset (RST) flag
              seq=tcp.seq,                            # TCP sequence number
              ack=tcp.ack,                            # TCP acknowledgement number
              header=tcp.packet.header,               # raw bytes type header
              payload=bytearray(
                  tcp.packet.payload),                # raw bytearray type payload
              src=ip.src,                             # source IP
              dst=ip.dst,                             # destination IP
              srcport=tcp.srcport,                    # TCP source port
              dstport=tcp.dstport,                    # TCP destination port
              timestamp=float(
                  frame.info.time_epoch),             # frame timestamp
          )

       .. seealso:: :class:`pcapkit.foundation.traceflow.data.tcp.Packet`

   trace.tcp.buffer
       Data structure for internal buffering when performing flow tracing algorithms
       (:attr:`TraceFlow._buffer <pcapkit.foundation.traceflow.traceflow.TraceFlow._buffer>`)
       is as follows:

       .. code-block:: text

          (dict) buffer --> memory buffer for reassembly
           |--> (tuple) BUFID : (dict)
           |       |--> ip.src      |
           |       |--> tcp.srcport |
           |       |--> ip.dst      |
           |       |--> tcp.dstport |
           |                        |--> 'fpout' : (dictdumper.dumper.Dumper) output dumper object
           |                        |--> 'index': (list) list of frame index, both directions
           |                        |              |--> (int) frame index
           |                        |--> 'label': (str) flow label generated from the packet
           |                        |                   that opened the flow
           |                        |--> 'origin': (tuple) (address, port) of the endpoint
           |                        |                      that opened the flow
           |                        |--> 'forward': (list) frame index sent by 'origin'
           |                        |--> 'reverse': (list) frame index sent to 'origin'
           |                        |--> 'fin': (set) endpoints seen to have sent a FIN
           |                        |--> 'reset': (bool) whether a RST has been seen
           |                        |--> 'reassembly': (Optional[TCP]) the flow's own
           |                                            reassembler, or None when
           |                                            analyse is off
           |--> (tuple) BUFID ...

       When tracing bidirectionally, the default, ``BUFID`` orders the endpoints
       canonically, so both halves of a conversation share one key;
       :data:`~pcapkit.foundation.traceflow.data.tcp.BufferID` says why it stays a
       plain :obj:`tuple`.

       A teardown -- a FIN from each endpoint, or a RST from either -- is recorded
       in ``fin`` and ``reset`` but does **not** finalise the flow. The ACK that
       completes :rfc:`9293#section-3.6`'s four-way close (FIN, ACK, FIN, ACK)
       arrives after the second FIN, so finalising on that FIN would let the ACK
       open a fresh buffer under the same ``BUFID``, for a later connection reusing
       those endpoints to merge into. Only proof that nothing more can arrive
       finalises it -- a new connection's SYN on the same endpoints, or
       :meth:`TCP.finish <pcapkit.foundation.traceflow.tcp.TCP.finish>` at the end
       of the capture -- and the recorded teardown is what tells that SYN from the
       peer's SYN-ACK.

       .. mermaid::

          stateDiagram-v2
              direction TB
              state "open" as O
              state "torn down" as T
              state "finalised" as F
              O : each packet recorded in index, and in forward or reverse
              O : a FIN adds its sender to fin, a RST sets reset and finalises nothing
              T : not stored, derived by _ended() from fin and reset
              T : the closing ACK and its duplicates still recorded
              [*] --> O : first packet on a BUFID,<br/>buffer created, label and origin from it
              O --> T : bidirectional only,<br/>FIN from both endpoints, or a RST
              T --> F : a new connection's SYN on the same BUFID,<br/>or TCP.finish() at the end of the capture
              O --> F : TCP.finish() at the end of the capture, either mode,<br/>or this direction's FIN, when unidirectional
              F --> [*] : \_finalise pops the buffer, builds its Index,<br/>calls each \_\_callback\_fn\_\_

       .. seealso:: :class:`pcapkit.foundation.traceflow.data.tcp.Buffer`

   trace.tcp.index
       Data structure for **TCP flow tracing** (element from
       :attr:`TraceFlow.index <pcapkit.foundation.traceflow.traceflow.TraceFlow.index>`
       *tuple*) is as follows:

       .. code-block:: text

          (tuple) index
           |--> (Info) data
           |     |--> 'fpout' : (Optional[str]) output filename, or None when
           |     |                              the format writes no file
           |     |--> 'index': (tuple) tuple of frame index, both directions,
           |     |                     in capture order
           |     |              |--> (int) frame index
           |     |--> 'label': (str) flow label generated from the packet that
           |     |                   opened the flow
           |     |--> 'forward': (tuple) frame index in the direction that
           |     |                       opened the flow
           |     |--> 'reverse': (tuple) frame index the other way; empty when
           |     |                      tracing unidirectionally
           |     |--> 'packet': (Optional[tuple]) reassembled datagrams, one per
           |                    direction and acknowledgement number, or None
           |                    when analyse is off
           |--> (Info) data ...

       ``forward`` and ``reverse`` partition ``index``, so
       ``frame_number in flow.forward`` answers which way a packet went without
       taking the label apart.

       ``packet`` is reassembled on its *first read*, and each datagram's own
       :attr:`~pcapkit.foundation.reassembly.data.tcp.Datagram.packet` parsed later
       still, so a caller that wanted only frame numbers pays for none of it. The
       tracer does not reassemble the stream itself: it feeds
       :class:`~pcapkit.foundation.reassembly.tcp.TCP`, whose :rfc:`815` algorithm
       handles the reordering and retransmission that concatenating payloads in
       capture order would corrupt.

       .. seealso:: :class:`pcapkit.foundation.traceflow.data.tcp.Index`

Data Structures
---------------

.. module:: pcapkit.foundation.traceflow.data.tcp
.. currentmodule:: pcapkit.foundation.traceflow.tcp

.. autoclass:: pcapkit.foundation.traceflow.data.tcp.Packet
   :members:
   :show-inheritance:

.. autodata:: pcapkit.foundation.traceflow.data.tcp.BufferID

.. autoclass:: pcapkit.foundation.traceflow.data.tcp.Buffer
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.traceflow.data.tcp.Index
   :members:
   :show-inheritance:

Type Variables
--------------

.. data:: _AT
   :module: pcapkit.foundation.traceflow.data.tcp
   :type: ipaddress.IPv4Address | ipaddress.IPv6Address

   IP address type.
