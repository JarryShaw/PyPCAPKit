Library Foundation
==================

.. module:: pcapkit.foundation

:mod:`pcapkit.foundation` is a collection of foundations for
:mod:`pcapkit`, including PCAP file extraction tool
:class:`~pcapkit.foundation.extraction.Extractor` and the
:mod:`~pcapkit.foundation.engines` it reads through, TCP/IP and DTLS
reassembly implementations and the :mod:`~pcapkit.foundation.analysis` of what
they reassemble, TCP flow tracer
:class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow`, and registry
management APIs for :mod:`pcapkit`.

.. toctree::
   :maxdepth: 3

   extraction
   engines/index
   reassembly/index
   analysis/index
   traceflow/index
   registry
