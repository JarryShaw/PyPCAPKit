Library Foundation
==================

.. module:: pcapkit.foundation

:mod:`pcapkit.foundation` holds the machinery of :mod:`pcapkit`:

* the PCAP file extractor :class:`~pcapkit.foundation.extraction.Extractor`,
  and the :mod:`~pcapkit.foundation.engines` it reads through;
* the IP, TCP and DTLS :mod:`~pcapkit.foundation.reassembly`, and the
  :mod:`~pcapkit.foundation.analysis` of what it reassembles;
* the TCP flow tracer :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow`;
* the :mod:`~pcapkit.foundation.registry` management APIs.

.. toctree::
   :maxdepth: 3

   extraction
   engines/index
   reassembly/index
   analysis/index
   traceflow/index
   registry
