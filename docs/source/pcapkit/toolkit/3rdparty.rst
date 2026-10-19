=================
3rd-Party Support
=================

The adapters below are best effort (:issue:`1687`): they need not match the
:doc:`builtin` adapters one to one, since protocol rules belong in the default
engine only, so the same capture can reassemble or trace differently from one
engine to the next. :doc:`../foundation/engines/index` tabulates the gaps.

Scapy Tools
===========

.. module:: pcapkit.toolkit.scapy

:mod:`pcapkit.toolkit.scapy` contains the adapters for the `Scapy`_ engine.
The reassembly and flow tracing adapters return the data their
:mod:`pcapkit.foundation` counterpart consumes, or :data:`None` if the frame
cannot be used for it.

.. warning::

   This module requires `Scapy`_ to be installed.

.. autofunction:: pcapkit.toolkit.scapy.ipv4_reassembly

.. autofunction:: pcapkit.toolkit.scapy.ipv6_reassembly

.. autofunction:: pcapkit.toolkit.scapy.tcp_reassembly

.. autofunction:: pcapkit.toolkit.scapy.tcp_traceflow

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.toolkit.scapy.packet2chain

.. autofunction:: pcapkit.toolkit.scapy.packet2dict

.. autofunction:: pcapkit.toolkit.scapy.packet2frame

.. autofunction:: pcapkit.toolkit.scapy.attach_resolution

.. autofunction:: pcapkit.toolkit.scapy.attach_linktype

DPKT Tools
==========

.. module:: pcapkit.toolkit.dpkt

:mod:`pcapkit.toolkit.dpkt` contains the adapters for the `DPKT`_ engine.
The reassembly and flow tracing adapters return the data their
:mod:`pcapkit.foundation` counterpart consumes, or :data:`None` if the frame
cannot be used for it.

.. autofunction:: pcapkit.toolkit.dpkt.ipv4_reassembly

.. autofunction:: pcapkit.toolkit.dpkt.ipv6_reassembly

.. autofunction:: pcapkit.toolkit.dpkt.tcp_reassembly

.. autofunction:: pcapkit.toolkit.dpkt.tcp_traceflow

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.toolkit.dpkt.attach_timestamp

.. autofunction:: pcapkit.toolkit.dpkt.packet2timestamp

.. autofunction:: pcapkit.toolkit.dpkt.attach_buffer

.. autofunction:: pcapkit.toolkit.dpkt.packet2bytes

.. autofunction:: pcapkit.toolkit.dpkt.packet2frame

.. autofunction:: pcapkit.toolkit.dpkt.ipv6_hdr_len

.. autofunction:: pcapkit.toolkit.dpkt.packet2chain

.. autofunction:: pcapkit.toolkit.dpkt.packet2dict

Auxiliary Data
--------------

.. autoclass:: pcapkit.toolkit.dpkt.RecordTimestamp
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.toolkit.dpkt.Timestamp
   :show-inheritance:

.. autoclass:: pcapkit.toolkit.dpkt.DecimalTimestamp
   :show-inheritance:

PyShark Tools
=============

.. module:: pcapkit.toolkit.pyshark

:mod:`pcapkit.toolkit.pyshark` contains the adapters for the `PyShark`_ engine.
The reassembly and flow tracing adapters return the data their
:mod:`pcapkit.foundation` counterpart consumes, or :data:`None` if the frame
cannot be used for it.

.. note::

   Some :mod:`pcapkit` functions may not be available with the `PyShark`_ engine,
   for lack of the corresponding `PyShark`_ functionality.

.. autofunction:: pcapkit.toolkit.pyshark.tcp_traceflow

.. autodata:: pcapkit.toolkit.pyshark.ENCAP_TYPE_TO_LINKTYPE
   :no-value:

.. autodata:: pcapkit.toolkit.pyshark.FILTER_NAME_TO_LINKTYPE
   :no-value:

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.toolkit.pyshark.packet2dict

PyPCAP Tools
============

.. module:: pcapkit.toolkit.pypcap

:mod:`pcapkit.toolkit.pypcap` contains the adapters for the `PyPCAP`_ engine.

.. note::

   `PyPCAP`_ performs no protocol dissection, so the reassembly and flow tracing
   adapters below cannot be implemented. They are defined anyway, so that
   calling one fails with an explanatory
   :exc:`~pcapkit.utilities.exceptions.UnsupportedCall` rather than an
   :exc:`ImportError`.

.. autofunction:: pcapkit.toolkit.pypcap.ipv4_reassembly

.. autofunction:: pcapkit.toolkit.pypcap.ipv6_reassembly

.. autofunction:: pcapkit.toolkit.pypcap.tcp_reassembly

.. autofunction:: pcapkit.toolkit.pypcap.tcp_traceflow

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.toolkit.pypcap.packet2chain

.. autofunction:: pcapkit.toolkit.pypcap.packet2dict

pcap-ct Tools
=============

.. module:: pcapkit.toolkit.pcap_ct

:mod:`pcapkit.toolkit.pcap_ct` contains the adapters for the `pcap-ct`_ engine.

.. note::

   `pcap-ct`_ is an independent reimplementation of the `PyPCAP`_ interface, so
   this module is deliberately a sibling of :mod:`pcapkit.toolkit.pypcap` rather
   than an alias of it: each engine names its own adapter, so a change made for
   one cannot quietly alter the other.

   Like `PyPCAP`_ it performs no protocol dissection, so the reassembly and flow
   tracing adapters below cannot be implemented. They are defined anyway, so
   that calling one fails with an explanatory
   :exc:`~pcapkit.utilities.exceptions.UnsupportedCall` rather than an
   :exc:`ImportError`.

.. autofunction:: pcapkit.toolkit.pcap_ct.ipv4_reassembly

.. autofunction:: pcapkit.toolkit.pcap_ct.ipv6_reassembly

.. autofunction:: pcapkit.toolkit.pcap_ct.tcp_reassembly

.. autofunction:: pcapkit.toolkit.pcap_ct.tcp_traceflow

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.toolkit.pcap_ct.packet2chain

.. autofunction:: pcapkit.toolkit.pcap_ct.packet2dict

PyPCAPFile Tools
================

.. module:: pcapkit.toolkit.pypcapfile

:mod:`pcapkit.toolkit.pypcapfile` contains the adapters for the `PyPCAPFile`_ engine.
The reassembly and flow tracing adapters return the data their
:mod:`pcapkit.foundation` counterpart consumes, or :data:`None` if the frame
cannot be used for it.

.. note::

   `PyPCAPFile`_ has no IPv6 decoder, so :func:`~pcapkit.toolkit.pypcapfile.ipv6_reassembly`
   raises :exc:`~pcapkit.utilities.exceptions.UnsupportedCall` rather than returning
   :data:`None` -- which would be indistinguishable from "this frame carries no
   IPv6 fragment".

   TCP over IPv6 is therefore left out of
   :func:`~pcapkit.toolkit.pypcapfile.tcp_reassembly` and
   :func:`~pcapkit.toolkit.pypcapfile.tcp_traceflow`, with an
   :class:`~pcapkit.utilities.warnings.AttributeWarning` once per capture when
   the IPv6 packet is straight over Ethernet. `PyPCAPFile`_ decodes no link
   layer but Ethernet, and no VLAN tag or tunnel, so a frame of any other link
   type is left undecoded, with the engine's own warning, and TCP behind a VLAN
   tag, in a tunnel or behind an extension header (an IPv6 one, or AH in IPv4)
   is left out without one.

.. autofunction:: pcapkit.toolkit.pypcapfile.ipv4_reassembly

.. autofunction:: pcapkit.toolkit.pypcapfile.ipv6_reassembly

.. autofunction:: pcapkit.toolkit.pypcapfile.tcp_reassembly

.. autofunction:: pcapkit.toolkit.pypcapfile.tcp_traceflow

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.toolkit.pypcapfile.packet2timestamp

.. autofunction:: pcapkit.toolkit.pypcapfile.ipv4_header

.. autofunction:: pcapkit.toolkit.pypcapfile.packet2chain

.. autofunction:: pcapkit.toolkit.pypcapfile.packet2dict

Internal Definitions
--------------------

.. autodata:: pcapkit.toolkit.pypcapfile.IPV4_FLAG_DF

.. autodata:: pcapkit.toolkit.pypcapfile.IPV4_FLAG_MF
