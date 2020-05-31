Trace TCP Flows
===============

:mod:`pcapkit.foundation.traceflow` is the interface to trace
TCP flows from a series of packets and connections.

.. note::

    This was implemented as the demand of my mate @gousaiyang.

Data Structure
--------------

.. glossary::

   trace.packet
      Data structure for **TCP flow tracing**
      (:meth:`~pcapkit.foundation.traceflow.TraceFlow.dump`)
      is as following:

      .. code:: python

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

   trace.buffer
      Data structure for internal buffering when performing reassembly algorithms
      (:attr:`~pcapkit.foundation.traceflow.TraceFlow._buffer`) is as following:

      .. code:: python

         (dict) buffer --> memory buffer for reassembly
          |--> (tuple) BUFID : (dict)
          |       |--> ip.src      |
          |       |--> ip.dst      |
          |       |--> tcp.srcport |
          |       |--> tcp.dstport |
          |                        |--> 'fpout' : (dictdumper.Dumper) output dumper object
          |                        |--> 'index': (list) list of frame index
          |                        |              |--> (int) frame index
          |                        |--> 'label': (str) flow label generated from ``BUFID``
          |--> (tuple) BUFID ...

   trace.index
      Data structure for **TCP flow tracing** (element from
      :attr:`~pcapkit.foundation.traceflow.TraceFlow.index` *tuple*)
      is as following:

      .. code:: python

         (tuple) index
          |--> (Info) data
          |     |--> 'fpout' : (Optional[str]) output filename if exists
          |     |--> 'index': (tuple) tuple of frame index
          |     |              |--> (int) frame index
          |     |--> 'label': (str) flow label generated from ``BUFID``
          |--> (Info) data ...

Implementation
--------------

.. automodule:: pcapkit.foundation.traceflow
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:
