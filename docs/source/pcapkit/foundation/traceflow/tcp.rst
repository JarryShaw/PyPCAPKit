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
   .. automethod:: trace
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
           |                        |--> 'index': (list) list of frame index
           |                        |              |--> (int) frame index
           |                        |--> 'label': (str) flow label generated from ``BUFID``
           |--> (tuple) BUFID ...

       .. seealso:: :class:`pcapkit.foundation.traceflow.data.tcp.Buffer`

   trace.tcp.index
       Data structure for **TCP flow tracing** (element from
       :attr:`TraceFlow.index <pcapkit.foundation.traceflow.traceflow.TraceFlow.index>`
       *tuple*) is as following:

       .. code-block:: text

          (tuple) index
           |--> (Info) data
           |     |--> 'fpout' : (Optional[str]) output filename if exists
           |     |--> 'index': (tuple) tuple of frame index
           |     |              |--> (int) frame index
           |     |--> 'label': (str) flow label generated from ``BUFID``
           |--> (Info) data ...

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

.. data:: pcapkit.foundation.traceflow.data.tcp._AT
   :type: ipaddress.IPv4Address | ipaddress.IPv6Address
