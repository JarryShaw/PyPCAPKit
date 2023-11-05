=================
3rd-Party Engines
=================

Scapy Support
=============

.. module:: pcapkit.foundation.engines.scapy

This module contains the implementation for `Scapy`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _Scapy: https://scapy.net

.. autoclass:: pcapkit.foundation.engines.scapy.Scapy
   :no-members:
   :show-inheritance:

   .. autoattribute:: __engine_name__
   .. autoattribute:: __engine_module__

   .. automethod:: run
   .. automethod:: read_frame

   .. autoattribute:: _expkg
   .. autoattribute:: _extmp

DPKT Support
============

.. module:: pcapkit.foundation.engines.dpkt

This module contains the implementation for `DPKT`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _DPKT: https://dpkt.readthedocs.io

.. autoclass:: pcapkit.foundation.engines.dpkt.DPKT
   :no-members:
   :show-inheritance:

   .. autoattribute:: __engine_name__
   .. autoattribute:: __engine_module__

   .. automethod:: run
   .. automethod:: read_frame

   .. autoattribute:: _expkg
   .. autoattribute:: _extmp

PyShark Support
===============

.. module:: pcapkit.foundation.engines.pyshark

This module contains the implementation for `PyShark`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _PyShark: https://kiminewt.github.io/pyshark

.. autoclass:: pcapkit.foundation.engines.pyshark.PyShark
   :no-members:
   :show-inheritance:

   .. autoattribute:: __engine_name__
   .. autoattribute:: __engine_module__

   .. automethod:: run
   .. automethod:: read_frame
   .. automethod:: close

   .. autoattribute:: _expkg
   .. autoattribute:: _extmp
