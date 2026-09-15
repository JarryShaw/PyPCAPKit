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

PyPCAP Support
==============

.. module:: pcapkit.foundation.engines.pypcap

This module contains the implementation for `PyPCAP`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _PyPCAP: https://github.com/pynetwork/pypcap

.. important::

   `PyPCAP`_ is a :manpage:`libpcap(3)` binding aimed primarily at live capture.
   Offline it performs **no protocol dissection**: each frame is the
   ``(timestamp, bytes)`` pair that :c:func:`pcap_next_ex` produced. Reassembly
   and flow tracing are therefore unavailable and are disabled -- with an
   :class:`~pcapkit.utilities.warnings.AttributeWarning` -- when requested.

   The engine also reads PCAP savefiles only, and only from a file on disk.
   PCAP-NG is rejected with a
   :exc:`~pcapkit.utilities.exceptions.FormatError`, because
   :manpage:`libpcap(3)` opens such a file without complaint and then yields no
   frames at all; and a non-file input is rejected with an
   :exc:`~pcapkit.utilities.exceptions.UnsupportedCall`, because
   :c:func:`pcap_open_offline` opens a savefile by *name*.

.. autoclass:: pcapkit.foundation.engines.pypcap.PyPCAP
   :no-members:
   :show-inheritance:

   .. autoattribute:: __engine_name__
   .. autoattribute:: __engine_module__

   .. autoproperty:: dlink

   .. automethod:: run
   .. automethod:: read_frame
   .. automethod:: close

   .. autoattribute:: _expkg
   .. autoattribute:: _extmp
   .. autoattribute:: _dlink
   .. autoattribute:: _closed

PyPCAPFile Support
==================

.. module:: pcapkit.foundation.engines.pypcapfile

This module contains the implementation for `PyPCAPFile`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _PyPCAPFile: https://github.com/kisom/pypcapfile

.. important::

   `PyPCAPFile`_ is a pure Python savefile reader that decodes Ethernet, IPv4,
   TCP and UDP and nothing else. IPv6 reassembly is therefore unavailable and is
   disabled -- with an :class:`~pcapkit.utilities.warnings.AttributeWarning` --
   when requested; IPv4 and TCP reassembly and TCP flow tracing remain
   available. PCAP-NG is rejected with a
   :exc:`~pcapkit.utilities.exceptions.FormatError`.

.. autoclass:: pcapkit.foundation.engines.pypcapfile.PyPCAPFile
   :no-members:
   :show-inheritance:

   .. autoattribute:: __engine_name__
   .. autoattribute:: __engine_module__
   .. autoattribute:: LAYERS

   .. autoproperty:: dlink

   .. automethod:: run
   .. automethod:: read_frame

   .. autoattribute:: _expkg
   .. autoattribute:: _extmp
   .. autoattribute:: _dlink
   .. autoattribute:: _declf

Internal Definitions
--------------------

.. autoclass:: pcapkit.foundation.engines.pypcapfile._NamedStream
   :no-members:
   :show-inheritance:

   .. autoattribute:: name
   .. automethod:: read

.. automethod:: pcapkit.foundation.engines.pypcapfile.PyPCAPFile._get_decoder
.. automethod:: pcapkit.foundation.engines.pypcapfile.PyPCAPFile._decode
