Library Foundation
==================

.. module:: pcapkit.foundation

:mod:`pcapkit.foundation` holds the machinery of :mod:`pcapkit`:

* the PCAP file extractor :class:`~pcapkit.foundation.extraction.Extractor`,
  the :mod:`~pcapkit.foundation.options` it takes, and the
  :mod:`~pcapkit.foundation.engines` it reads through;
* the IP, TCP, DTLS and SCTP :mod:`~pcapkit.foundation.reassembly`, and the
  :mod:`~pcapkit.foundation.analysis` of what it reassembles;
* the TCP flow tracer of :mod:`~pcapkit.foundation.traceflow`, and any other registered one;
* the :mod:`~pcapkit.foundation.registry` management APIs.

.. toctree::
   :maxdepth: 3

   extraction
   options
   engines/index
   reassembly/index
   analysis/index
   traceflow/index
   registry
