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

   .. autoproperty:: header
   .. autoproperty:: version
   .. autoproperty:: dlink

   .. automethod:: run
   .. automethod:: read_frame

PCAP-NG Support
===============

.. module:: pcapkit.foundation.engines.pcapng

This module contains the implementation for PCAP-NG file extraction
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. autoclass:: pcapkit.foundation.engines.pcapng.PCAPNG
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: module

   .. automethod:: run
   .. automethod:: read_frame

File Block Context
------------------

.. autoclass:: pcapkit.foundation.engines.pcapng.Context
   :members:
   :undoc-members:
   :show-inheritance:
   
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.
