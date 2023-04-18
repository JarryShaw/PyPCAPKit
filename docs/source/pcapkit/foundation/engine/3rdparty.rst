=================
3rd-Party Engines
=================

Scapy Support
=============

.. module:: pcapkit.foundation.engine.scapy

This module contains the implementation for `Scapy`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _Scapy: https://scapy.net

.. autoclass:: pcapkit.foundation.engine.scapy.Scapy
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: module

   .. automethod:: run
   .. automethod:: read_frame

DPKT Support
============

.. module:: pcapkit.foundation.engine.dpkt

This module contains the implementation for `DPKT`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _DPKT: https://dpkt.readthedocs.io

.. autoclass:: pcapkit.foundation.engine.dpkt.DPKT
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: module

   .. automethod:: run
   .. automethod:: read_frame

PyShark Support
===============

.. module:: pcapkit.foundation.engine.pyshark

This module contains the implementation for `PyShark`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _PyShark: https://kiminewt.github.io/pyshark

.. autoclass:: pcapkit.foundation.engine.pyshark.PyShark
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: module

   .. automethod:: run
   .. automethod:: read_frame
   .. automethod:: close
