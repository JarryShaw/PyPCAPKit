================
Built-in Engines
================

PCAP Support
============

.. module:: pcapkit.foundation.engines.pcap

This module contains the implementation for PCAP file extraction
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. autoclass:: pcapkit.foundation.engines.pcap.PCAP
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: module

   .. automethod:: run
   .. automethod:: read_frame
