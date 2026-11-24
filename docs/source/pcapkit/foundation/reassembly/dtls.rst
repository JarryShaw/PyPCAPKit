=================================
DTLS Handshake-Message Reassembly
=================================

.. module:: pcapkit.foundation.reassembly.dtls
.. module:: pcapkit.foundation.reassembly.dtls.reassembly

:mod:`pcapkit.foundation.reassembly.dtls.reassembly` contains
:class:`~pcapkit.foundation.reassembly.dtls.reassembly.DTLS` only, which reconstructs a
DTLS handshake message split across several records back to origin
(:rfc:`6347#section-4.2.3`).

.. versionadded:: 1.6.0

.. autoclass:: pcapkit.foundation.reassembly.dtls.reassembly.DTLS
   :no-members:
   :show-inheritance:

   .. rubric:: Defaults

   .. autoattribute:: __protocol_name__
   .. autoattribute:: __protocol_type__

   .. rubric:: Properties

   .. autoproperty:: last

   .. rubric:: Methods

   .. automethod:: reassembly
   .. automethod:: submit

   .. rubric:: Utilities

   .. automethod:: _datagram_from_fragment
   .. automethod:: _received_runs
   .. automethod:: _update_hole_descriptors

Algorithm
=========

.. seealso::

   Holes are inclusive byte offsets into the message. They never wrap, and
   the upper bound is known from the start: every fragment carries the
   message's total ``length`` (:rfc:`6347#section-4.2.3`).

A DTLS handshake record may carry more than one message fragment --
:rfc:`6347#section-4.2.3` allows several handshake messages (or fragments of
them) to be coalesced into one record, and :meth:`SSL._read_tls_handshake_messages
<pcapkit.protocols.application.ssl.protocol.SSL._read_tls_handshake_messages>`
reads however many fit rather than assuming exactly one. A fragment names the
message it belongs to (``message_seq``), the message's total length
(``length``), and its own byte range within that message (``fragment_offset``,
``fragment_length``). A message is reassembled by punching the arriving
fragment's range out of the message's hole list; it is whole once no hole
remains.

Terminology
===========

.. glossary::

   reasm.dtls.packet
       Data structure for **DTLS handshake-fragment reassembly**
       (:meth:`DTLS.reassembly <pcapkit.foundation.reassembly.dtls.reassembly.DTLS.reassembly>`)
       is :class:`~pcapkit.foundation.reassembly.dtls.data.Packet` -- one
       fragment's own ``bufid``, ``message_seq``, ``fragment_offset``,
       ``fragment_length`` and raw ``payload``, built by
       :func:`pcapkit.toolkit.pcap.dtls_reassembly` or
       :func:`pcapkit.toolkit.pcapng.dtls_reassembly` from a single
       :class:`~pcapkit.protocols.application.dtls.data.DTLSHandshake`.

   reasm.dtls.datagram
       Data structure for **reassembled DTLS handshake message** (element of
       :attr:`DTLS.datagram <pcapkit.foundation.reassembly.reassembly.Reassembly.datagram>`)
       is :class:`~pcapkit.foundation.reassembly.dtls.data.Datagram` --
       ``completed``, the original packet identifier, the packet numbers
       that built it, ``body``, the reassembled payload (a contiguous
       :obj:`bytes`, or -- under ``strict=True`` and an incomplete message --
       a :obj:`tuple` of the octet runs actually received), and ``packet``,
       what :func:`~pcapkit.foundation.analysis.dtls.dtls_handshake` decodes
       ``body`` to. ``packet`` is decoded on first read, as an IP or TCP
       datagram's is, and is :data:`None` for an incomplete message.

   reasm.dtls.buffer
       Data structure for internal buffering
       (:attr:`DTLS._buffer <pcapkit.foundation.reassembly.reassembly.Reassembly._buffer>`)
       is :class:`~pcapkit.foundation.reassembly.dtls.data.Buffer` -- every
       message under reconstruction for one
       :data:`~pcapkit.foundation.reassembly.dtls.data.BufferID` (one UDP
       association at one DTLS epoch), each keyed by its
       :attr:`~pcapkit.foundation.reassembly.dtls.data.Packet.message_seq` and
       held as a :class:`~pcapkit.foundation.reassembly.dtls.data.Fragment` --
       its hole descriptor list
       (:class:`~pcapkit.foundation.reassembly.dtls.data.HoleDescriptor`) and
       its zero-filled payload buffer.

Data Models
===========

.. module:: pcapkit.foundation.reassembly.dtls.data

.. versionremoved:: 1.7.0

   ``pcapkit.foundation.reassembly.data.dtls``, with no alias: the module moved here
   (:issue:`2882`).

.. currentmodule:: pcapkit.foundation.reassembly.dtls.reassembly

.. autoclass:: pcapkit.foundation.reassembly.dtls.data.Packet
   :members:
   :show-inheritance:

.. autodata:: pcapkit.foundation.reassembly.dtls.data.BufferID

.. autoclass:: pcapkit.foundation.reassembly.dtls.data.DatagramID
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.dtls.data.Datagram
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.dtls.data.HoleDescriptor
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.dtls.data.Fragment
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.dtls.data.Buffer
   :members:
   :show-inheritance:

Type Variables
==============

.. data:: _AT
   :module: pcapkit.foundation.reassembly.dtls.data
   :type: ipaddress.IPv4Address | ipaddress.IPv6Address

   IP address type.
