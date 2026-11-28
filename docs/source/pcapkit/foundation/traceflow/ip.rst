Follow IP Conversations
=======================

.. module:: pcapkit.foundation.traceflow.ip
.. module:: pcapkit.foundation.traceflow.ip.traceflow

.. versionadded:: 1.10.0

:mod:`pcapkit.foundation.traceflow.ip.traceflow` traces IP conversations from a
series of packets.

.. autoclass:: pcapkit.foundation.traceflow.ip.traceflow.IP
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

   .. rubric:: Data Models

   .. automethod:: __init__

   .. rubric:: Utilities

   .. automethod:: _endpoints
   .. automethod:: _make_index

Terminology
-----------

.. glossary::

   trace.ip.packet
       Data structure for **IP flow tracing**
       (:meth:`TraceFlow.dump <pcapkit.foundation.traceflow.traceflow.TraceFlow.dump>`)
       is as follows:

       .. code-block:: python

          trace_dict = dict(
              protocol=data_link,                     # data link type from global header
              index=frame.info.number,                # frame number
              frame=frame.info,                       # extracted frame info
              src=ip.src,                             # source IP, outermost header
              dst=ip.dst,                             # destination IP, outermost header
              timestamp=float(
                  frame.info.time_epoch),             # frame timestamp
          )

       .. seealso:: :class:`pcapkit.foundation.traceflow.ip.data.Packet`

   trace.ip.buffer
       Data structure for internal buffering when performing flow tracing algorithms
       (:attr:`TraceFlow._buffer <pcapkit.foundation.traceflow.traceflow.TraceFlow._buffer>`)
       is as follows:

       .. code-block:: text

          (dict) buffer --> memory buffer for flow tracing
           |--> (tuple) BUFID : (dict)
           |       |--> ip.src |
           |       |--> ip.dst |
           |                   |--> 'fpout' : (dictdumper.dumper.Dumper) output dumper object
           |                   |--> 'index': (list) list of frame index, both directions
           |                   |              |--> (int) frame index
           |                   |--> 'label': (str) flow label generated from the packet
           |                   |                   that opened the flow
           |                   |--> 'origin': (tuple) (address,) of the endpoint that
           |                   |                      opened the flow
           |                   |--> 'forward': (list) frame index sent by 'origin'
           |                   |--> 'reverse': (list) frame index sent to 'origin'
           |--> (tuple) BUFID ...

       ``BUFID`` orders the two addresses canonically when tracing bidirectionally,
       the default. A flow ends as a :term:`UDP one <trace.udp.buffer>` does.

       .. seealso:: :class:`pcapkit.foundation.traceflow.ip.data.Buffer`

   trace.ip.index
       Data structure for **IP flow tracing** (element from
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
           |                            tracing unidirectionally
           |--> (Info) data ...

       .. seealso:: :class:`pcapkit.foundation.traceflow.ip.data.Index`

Data Structures
---------------

.. module:: pcapkit.foundation.traceflow.ip.data

.. currentmodule:: pcapkit.foundation.traceflow.ip.traceflow

.. autoclass:: pcapkit.foundation.traceflow.ip.data.Packet
   :members:
   :show-inheritance:

.. autodata:: pcapkit.foundation.traceflow.ip.data.BufferID

.. autoclass:: pcapkit.foundation.traceflow.ip.data.Buffer
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.traceflow.ip.data.Index
   :members:
   :show-inheritance:

Type Variables
--------------

.. data:: _AT
   :module: pcapkit.foundation.traceflow.ip.data
   :type: ipaddress.IPv4Address | ipaddress.IPv6Address

   IP address type.
