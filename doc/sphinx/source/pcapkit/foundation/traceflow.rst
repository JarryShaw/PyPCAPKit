Trace TCP Flows
===============

.. module:: pcapkit.foundation.traceflow

:mod:`pcapkit.foundation.traceflow` is the interface to trace
TCP flows from a series of packets and connections.

.. note::

   This was implemented as the demand of my mate
   `@gousaiyang <https://github.com/gousaiyang>`__

.. autoclass:: pcapkit.foundation.traceflow.TraceFlow
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. automethod:: __init__
   .. automethod:: __call__

   .. autoproperty:: index

   .. automethod:: dump
   .. automethod:: trace
   .. automethod:: submit

   .. automethod:: register
   .. automethod:: make_fout

   .. autoattribute:: __output__
      :no-value:
   .. autoattribute:: _buffer

Terminology
-----------

.. glossary::

   trace.packet
       Data structure for **TCP flow tracing**
       (:meth:`TraceFlow.dump <pcapkit.foundation.traceflow.TraceFlow.dump>`)
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

       .. seealso:: :class:`pcapkit.foundation.traceflow.Packet`

   trace.buffer
       Data structure for internal buffering when performing flow tracing algorithms
       (:attr:`TraceFlow._buffer <pcapkit.foundation.traceflow.TraceFlow._buffer>`)
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

       .. seealso:: :class:`pcapkit.foundation.traceflow.Buffer`

   trace.index
       Data structure for **TCP flow tracing** (element from
       :attr:`TraceFlow.index <pcapkit.foundation.traceflow.TraceFlow.index>`
       *tuple*) is as following:

       .. code-block:: text

          (tuple) index
           |--> (Info) data
           |     |--> 'fpout' : (Optional[str]) output filename if exists
           |     |--> 'index': (tuple) tuple of frame index
           |     |              |--> (int) frame index
           |     |--> 'label': (str) flow label generated from ``BUFID``
           |--> (Info) data ...

       .. seealso:: :class:`pcapkit.foundation.traceflow.Index`

Data Structures
---------------

.. data:: pcapkit.foundation.traceflow.BufferID
   :type: tuple[IPAddress, int, IPAddress, int]

   Buffer ID is a tuple of source IP, source port, destination IP, and
   destination port.

.. autoclass:: pcapkit.foundation.traceflow.Packet(protocol, index, frame, syn, fin, src, dst, srcport, dstport, timestamp)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: protocol
   .. autoattribute:: index
   .. autoattribute:: frame
   .. autoattribute:: syn
   .. autoattribute:: fin
   .. autoattribute:: src
   .. autoattribute:: dst
   .. autoattribute:: srcport
   .. autoattribute:: dstport
   .. autoattribute:: timestamp

.. autoclass:: pcapkit.foundation.traceflow.Buffer(fpout, index, label)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: fpout
   .. autoattribute:: index
   .. autoattribute:: label

.. autoclass:: pcapkit.foundation.traceflow.Index(fpout, index, label)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: fpout
   .. autoattribute:: index
   .. autoattribute:: label
