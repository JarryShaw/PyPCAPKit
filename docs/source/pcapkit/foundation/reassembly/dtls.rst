=================================
DTLS Handshake-Message Reassembly
=================================

.. module:: pcapkit.foundation.reassembly.dtls

:mod:`pcapkit.foundation.reassembly.dtls` contains
:class:`~pcapkit.foundation.reassembly.dtls.DTLS` only, which reconstructs a
DTLS handshake message split across several records back to origin
(:rfc:`6347#section-4.2.3`).

.. autoclass:: pcapkit.foundation.reassembly.dtls.DTLS
   :no-members:
   :show-inheritance:

   .. autoproperty:: last

   .. automethod:: reassembly
   .. automethod:: submit
   .. automethod:: _datagram_from_fragment
   .. automethod:: _received_runs
   .. automethod:: _update_hole_descriptors

   .. autoattribute:: __protocol_name__
   .. autoattribute:: __timeout__

Algorithm
=========

.. seealso::

   Holes are inclusive byte offsets into the message. They never wrap, and
   the upper bound is known from the start: every fragment carries the
   message's total ``length`` (:rfc:`6347#section-4.2.3`).

A DTLS handshake record may carry more than one message fragment --
:rfc:`6347#section-4.2.3` allows several handshake messages (or fragments of
them) to be coalesced into one record, and :meth:`SSL._read_tls_handshake_messages
<pcapkit.protocols.application.ssl.SSL._read_tls_handshake_messages>`
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
       (:meth:`DTLS.reassembly <pcapkit.foundation.reassembly.dtls.DTLS.reassembly>`)
       is :class:`~pcapkit.foundation.reassembly.data.dtls.Packet` -- one
       fragment's own ``bufid``, ``message_seq``, ``fragment_offset``,
       ``fragment_length`` and raw ``payload``, built by
       :meth:`DTLS.read <pcapkit.protocols.application.dtls.DTLS.read>` from
       a single :class:`~pcapkit.protocols.data.application.dtls.DTLSHandshake`.

   reasm.dtls.datagram
       Data structure for **reassembled DTLS handshake message** (element of
       :attr:`DTLS.datagram <pcapkit.foundation.reassembly.reassembly.Reassembly.datagram>`)
       is :class:`~pcapkit.foundation.reassembly.data.dtls.Datagram` --
       ``completed``, the original packet identifier, the packet numbers
       that built it, and ``body``, the reassembled payload (a contiguous
       :obj:`bytes`, or -- under ``strict=True`` and an incomplete message --
       a :obj:`tuple` of the octet runs actually received).

   reasm.dtls.buffer
       Data structure for internal buffering
       (:attr:`DTLS._buffer <pcapkit.foundation.reassembly.reassembly.Reassembly._buffer>`)
       is :class:`~pcapkit.foundation.reassembly.data.dtls.Buffer` -- every
       message under reconstruction for one
       :data:`~pcapkit.foundation.reassembly.data.dtls.BufferID` (one UDP
       association at one DTLS epoch), each keyed by its
       :attr:`~pcapkit.foundation.reassembly.data.dtls.Packet.message_seq` and
       held as a :class:`~pcapkit.foundation.reassembly.data.dtls.Fragment` --
       its hole descriptor list
       (:class:`~pcapkit.foundation.reassembly.data.dtls.HoleDescriptor`) and
       its zero-filled payload buffer.

Data Models
===========

.. module:: pcapkit.foundation.reassembly.data.dtls
.. currentmodule:: pcapkit.foundation.reassembly.dtls

.. autoclass:: pcapkit.foundation.reassembly.data.dtls.Packet
   :members:
   :show-inheritance:

.. autodata:: pcapkit.foundation.reassembly.data.dtls.BufferID

.. autoclass:: pcapkit.foundation.reassembly.data.dtls.DatagramID
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.data.dtls.Datagram
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.data.dtls.HoleDescriptor
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.data.dtls.Fragment
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.data.dtls.Buffer
   :members:
   :show-inheritance:

Type Variables
==============

.. data:: _AT
   :module: pcapkit.foundation.reassembly.data.dtls
   :type: ipaddress.IPv4Address | ipaddress.IPv6Address

   IP address type.
