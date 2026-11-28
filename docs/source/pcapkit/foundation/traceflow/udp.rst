Follow UDP Streams
==================

.. module:: pcapkit.foundation.traceflow.udp
.. module:: pcapkit.foundation.traceflow.udp.traceflow

.. versionadded:: 1.10.0

:mod:`pcapkit.foundation.traceflow.udp.traceflow` traces UDP flows from a series of
packets.

.. autoclass:: pcapkit.foundation.traceflow.udp.traceflow.UDP
   :no-members:
   :show-inheritance:

   .. Hand-written: TraceFlowMeta's class properties shadow TraceFlowBase's,
      so autoproperty finds no property to document (#2910).

   .. property:: name
      :type: str

      Protocol name of current flow tracing object.

      .. note::

         The same value is also available as a class attribute, from the
         property of the same name on
         :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlowMeta`.

   .. property:: protocol
      :type: typing.Type[pcapkit.protocols.protocol.ProtocolBase]

      Protocol of current flow tracing object.

      .. note::

         The same value is also available as a class attribute, from the
         property of the same name on
         :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlowMeta`.

   .. autoattribute:: __callback_fn__
      :no-value:

   .. rubric:: Defaults

   .. autoattribute:: __protocol_name__
   .. autoattribute:: __protocol_type__

   .. rubric:: Methods

   .. automethod:: dump
   .. automethod:: trace
   .. automethod:: finish
   .. automethod:: submit

   .. rubric:: Utilities

   .. automethod:: _make_index

Terminology
-----------

.. glossary::

   trace.udp.packet
       Data structure for **UDP flow tracing**
       (:meth:`TraceFlow.dump <pcapkit.foundation.traceflow.traceflow.TraceFlow.dump>`)
       is as follows:

       .. code-block:: python

          trace_dict = dict(
              protocol=data_link,                     # data link type from global header
              index=frame.info.number,                # frame number
              frame=frame.info,                       # extracted frame info
              src=ip.src,                             # source IP
              dst=ip.dst,                             # destination IP
              srcport=udp.srcport,                    # UDP source port
              dstport=udp.dstport,                    # UDP destination port
              timestamp=float(
                  frame.info.time_epoch),             # frame timestamp
              payload=bytes(udp.packet.payload),      # raw bytes type payload
          )

       .. seealso:: :class:`pcapkit.foundation.traceflow.udp.data.Packet`

   trace.udp.buffer
       Data structure for internal buffering when performing flow tracing algorithms
       (:attr:`TraceFlow._buffer <pcapkit.foundation.traceflow.traceflow.TraceFlow._buffer>`)
       is as follows:

       .. code-block:: text

          (dict) buffer --> memory buffer for flow tracing
           |--> (tuple) BUFID : (dict)
           |       |--> ip.src      |
           |       |--> udp.srcport |
           |       |--> ip.dst      |
           |       |--> udp.dstport |
           |                        |--> 'fpout' : (dictdumper.dumper.Dumper) output dumper object
           |                        |--> 'index': (list) list of frame index, both directions
           |                        |              |--> (int) frame index
           |                        |--> 'label': (str) flow label generated from the packet
           |                        |                   that opened the flow
           |                        |--> 'origin': (tuple) (address, port) of the endpoint
           |                        |                      that opened the flow
           |                        |--> 'forward': (list) frame index sent by 'origin'
           |                        |--> 'reverse': (list) frame index sent to 'origin'
           |                        |--> 'payload': (Optional[list]) each datagram's port pair
           |                                        and payload, or None when analyze is off
           |--> (tuple) BUFID ...

       ``BUFID`` orders the endpoints canonically when tracing bidirectionally, the
       default, as :term:`TCP's <trace.tcp.buffer>` does. Nothing a datagram carries
       ends its flow: :meth:`TraceFlow.finish
       <pcapkit.foundation.traceflow.traceflow.TraceFlow.finish>` finalises it at the
       end of the capture, or :meth:`TraceFlow.advance
       <pcapkit.foundation.traceflow.traceflow.TraceFlow.advance>` once it has been
       idle for the tracer's ``timeout``, after which a datagram on the same endpoints
       opens a new flow.

       .. seealso:: :class:`pcapkit.foundation.traceflow.udp.data.Buffer`

   trace.udp.index
       Data structure for **UDP flow tracing** (element from
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
           |     |--> 'packet': (Optional[tuple]) each datagram's application
           |                    layer, one per frame of 'index', or None when
           |                    analyze is off
           |--> (Info) data ...

       ``packet`` is parsed on its *first read*, each payload by its ports.

       .. seealso:: :class:`pcapkit.foundation.traceflow.udp.data.Index`

Data Structures
---------------

.. module:: pcapkit.foundation.traceflow.udp.data

.. currentmodule:: pcapkit.foundation.traceflow.udp.traceflow

.. autoclass:: pcapkit.foundation.traceflow.udp.data.Packet
   :members:
   :show-inheritance:

.. autodata:: pcapkit.foundation.traceflow.udp.data.BufferID

.. autoclass:: pcapkit.foundation.traceflow.udp.data.Buffer
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.traceflow.udp.data.Index
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.traceflow.udp.data.Deferred
   :members:
   :show-inheritance:

Type Variables
--------------

.. data:: _AT
   :module: pcapkit.foundation.traceflow.udp.data
   :type: ipaddress.IPv4Address | ipaddress.IPv6Address

   IP address type.
