Follow TCP Stream
=================

.. module:: pcapkit.foundation.traceflow.tcp

:mod:`pcapkit.foundation.traceflow.tcp` is the interface to trace
TCP flows from a series of packets and connections.

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

Terminology
-----------

.. glossary::

   trace.tcp.packet
       Data structure for **TCP flow tracing**
       (:meth:`TraceFlow.dump <pcapkit.foundation.traceflow.traceflow.TraceFlow.dump>`)
       is as following:

       .. code-block:: python

          tract_dict = dict(
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
              timestamp=frame.info.time_epoch,        # frame timestamp
          )

       .. seealso:: :class:`pcapkit.foundation.traceflow.data.tcp.Packet`

   trace.tcp.buffer
       Data structure for internal buffering when performing flow tracing algorithms
       (:attr:`TraceFlow._buffer <pcapkit.foundation.traceflow.traceflow.TraceFlow._buffer>`)
       is as following:

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

       When tracing bidirectionally -- the default -- ``BUFID`` orders the two
       endpoints canonically rather than as (source, destination), so both halves
       of a conversation reduce to the same key. It stays a plain :obj:`tuple`
       either way, because it is a :obj:`dict` key and an
       :class:`~pcapkit.corekit.infoclass.Info` cannot be one --
       :class:`collections.abc.Mapping` sets its ``__hash__`` to :data:`None`.

       A teardown -- a FIN from each endpoint, or a RST from either -- is recorded
       in ``fin`` and ``reset`` but does **not** finalise the flow. The four-way
       close of :rfc:`9293#section-3.6` is FIN, ACK, FIN, ACK, so the
       acknowledgement that completes it arrives after the second FIN; finalising
       on that FIN would drop the ACK from the flow and let it open a fresh buffer
       under the same ``BUFID``, which a later connection reusing those endpoints
       would then merge into. The flow is finalised instead by proof that nothing
       more can arrive -- a new connection's SYN on the same endpoints, or
       :meth:`TCP.finish <pcapkit.foundation.traceflow.tcp.TCP.finish>` at the end
       of the capture. Telling that SYN from the peer's SYN-ACK is what the
       recorded teardown is for.

       .. seealso:: :class:`pcapkit.foundation.traceflow.data.tcp.Buffer`

   trace.tcp.index
       Data structure for **TCP flow tracing** (element from
       :attr:`TraceFlow.index <pcapkit.foundation.traceflow.traceflow.TraceFlow.index>`
       *tuple*) is as following:

       .. code-block:: text

          (tuple) index
           |--> (Info) data
           |     |--> 'fpout' : (Optional[str]) output filename if exists
           |     |--> 'index': (tuple) tuple of frame index, both directions,
           |     |                     in capture order
           |     |              |--> (int) frame index
           |     |--> 'label': (str) flow label generated from the packet that
           |     |                   opened the flow
           |     |--> 'forward': (tuple) frame index in the direction that
           |     |                       opened the flow
           |     |--> 'reverse': (tuple) frame index the other way; empty when
           |     |                      tracing unidirectionally
           |     |--> 'packet': (Optional[tuple]) one reassembled datagram per
           |                    direction, or None when analyse is off
           |--> (Info) data ...

       ``forward`` and ``reverse`` partition ``index``, so
       ``frame_number in flow.forward`` answers which way a packet went without
       taking the label apart. ``forward`` is the direction of the packet that
       opened the flow, whose endpoints the label names first.

       ``packet`` is the conversation's application layer: one reassembled datagram
       per direction, present only when the tracer was constructed with
       ``analyse=True``. It is reassembled on the *first read*, and each datagram's
       own :attr:`~pcapkit.foundation.reassembly.data.tcp.Datagram.packet` is
       parsed later still, so a caller that wanted only frame numbers pays for
       neither. The tracer does not reassemble the stream itself -- it feeds
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

.. autoclass:: pcapkit.foundation.traceflow.data.data.Deferred
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.traceflow.data.data.DeferredPacket
   :members:
   :show-inheritance:

Type Variables
--------------

.. data:: pcapkit.foundation.traceflow.data.tcp._AT
   :type: ipaddress.IPv4Address | ipaddress.IPv6Address
