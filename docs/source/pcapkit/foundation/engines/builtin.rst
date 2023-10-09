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

   .. autoattribute:: __engine_name__
   .. autoattribute:: __engine_module__

   .. autoproperty:: header
   .. autoproperty:: version
   .. autoproperty:: dlink
   .. autoproperty:: nanosecond

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

   .. autoattribute:: __engine_name__
   .. autoattribute:: __engine_module__

   .. automethod:: run
   .. automethod:: read_frame

Internal Definitions
--------------------

.. autoclass:: pcapkit.foundation.engines.pcapng.Context
   :no-members:
   :show-inheritance:

   .. important::

      We do not store any packet blocks, e.g.,
      :class:`~pcapkit.protocols.data.misc.pcapng.PacketBlock`,
      :class:`~pcapkit.protocols.data.misc.pcapng.SimplePacketBlock`,
      and :class:`~pcapkit.protocols.data.misc.pcapng.EnhancedPacketBlock`,
      in the :class:`Context` object, as they will be directly
      stored in the :class:`~pcapkit.foundation.extraction.Extractor`.

   .. autoattribute:: section
   .. autoattribute:: interfaces
   .. autoattribute:: names
   .. autoattribute:: journals
   .. autoattribute:: secrets
   .. autoattribute:: custom
   .. autoattribute:: statistics
   .. autoattribute:: unknown
