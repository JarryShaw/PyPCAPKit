================
Built-in Engines
================

PCAP Support
============

.. module:: pcapkit.foundation.engines.pcap

:mod:`pcapkit.foundation.engines.pcap` is the PCAP extraction engine used by
:class:`pcapkit.foundation.extraction.Extractor`.

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

   .. autoattribute:: _gbhdr
   .. autoattribute:: _vinfo
   .. autoattribute:: _dlink
   .. autoattribute:: _nnsec

PCAP-NG Support
===============

.. module:: pcapkit.foundation.engines.pcapng

:mod:`pcapkit.foundation.engines.pcapng` is the PCAP-NG extraction engine used
by :class:`pcapkit.foundation.extraction.Extractor`.

.. autoclass:: pcapkit.foundation.engines.pcapng.PCAPNG
   :no-members:
   :show-inheritance:

   .. autoattribute:: __engine_name__
   .. autoattribute:: __engine_module__

   .. automethod:: run
   .. automethod:: read_frame

   .. autoattribute:: _ctx
   .. autoattribute:: _ctx_list

Internal Definitions
--------------------

.. autoclass:: pcapkit.foundation.engines.pcapng.Context
   :no-members:
   :show-inheritance:

   .. important::

      Packet blocks --
      :class:`~pcapkit.protocols.data.misc.pcapng.PacketBlock`,
      :class:`~pcapkit.protocols.data.misc.pcapng.SimplePacketBlock` and
      :class:`~pcapkit.protocols.data.misc.pcapng.EnhancedPacketBlock` -- are
      not stored in :class:`Context`, since the
      :class:`~pcapkit.foundation.extraction.Extractor` stores them directly.

   .. autoattribute:: section
   .. autoattribute:: interfaces
   .. autoattribute:: names
   .. autoattribute:: journals
   .. autoattribute:: secrets
   .. autoattribute:: custom
   .. autoattribute:: statistics
   .. autoattribute:: unknown
