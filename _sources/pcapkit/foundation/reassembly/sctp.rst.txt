============================
SCTP User-Message Reassembly
============================

.. module:: pcapkit.foundation.reassembly.sctp
.. module:: pcapkit.foundation.reassembly.sctp.reassembly

:mod:`pcapkit.foundation.reassembly.sctp.reassembly` contains
:class:`~pcapkit.foundation.reassembly.sctp.reassembly.SCTP` only, which reconstructs
an SCTP user message fragmented across DATA chunks (:rfc:`9260#section-6.9`) or
I-DATA chunks (:rfc:`8260#section-2.2.3`) back to origin.

.. versionadded:: 1.9.0

.. autoclass:: pcapkit.foundation.reassembly.sctp.reassembly.SCTP
   :no-members:
   :show-inheritance:

   .. rubric:: Defaults

   .. autoattribute:: __protocol_name__
   .. autoattribute:: __protocol_type__

   .. rubric:: Methods

   .. automethod:: reassembly
   .. automethod:: submit

   .. rubric:: Utilities

   .. automethod:: _add_data
   .. automethod:: _continues
   .. automethod:: _merge
   .. automethod:: _add_idata
   .. automethod:: _complete
   .. automethod:: _datagram_from_fragment

Algorithm
=========

A fragment names the message it belongs to differently in each chunk:

.. mermaid::

   flowchart TD
       F["a DATA or I-DATA chunk,<br/>B and E not both set"]
       Q{"chunk type?"}
       D["DATA: joins the run of TSNs either side of it,<br/>unless that run ends a message, it begins one,<br/>or stream, U bit or ordered SSN differ"]
       I["I-DATA: held under its stream, U bit and MID,<br/>by its FSN"]
       W{"B at the lowest held,<br/>E at the highest,<br/>none between missing?"}
       C["COMPLETE: the message leaves the buffer"]
       H["held until the buffer is submitted:<br/>PARTIAL, or TIMEOUT under a timeout"]

       F --> Q
       Q -->|DATA| D
       Q -->|I-DATA| I
       D & I --> W
       W -->|yes| C
       W -->|no| H

A DATA message's fragments carry strictly sequential TSNs and one stream sequence
number (:rfc:`9260#section-3.3.1`), so a missing TSN splits what is held into runs,
each reported as a message of its own. An I-DATA message's fragments are numbered by
FSN from 0, and its TSNs say nothing of their order (:rfc:`8260#section-2.2.3`).
Neither chunk says how long a missing fragment is, so a hole is never zero-filled.

The TSN space belongs to the association, and a multi-homed endpoint may retransmit a
chunk to an alternate destination address (:rfc:`9260#section-6.4`). So a buffer is
keyed on the ports and verification tag alone, which one direction of one association
carries on every path, and a message reports the addresses of its lowest fragment held.

Terminology
===========

.. glossary::

   reasm.sctp.packet
       Data structure for **SCTP user-message fragment reassembly**
       (:meth:`SCTP.reassembly <pcapkit.foundation.reassembly.sctp.reassembly.SCTP.reassembly>`)
       is :class:`~pcapkit.foundation.reassembly.sctp.data.Packet` -- one DATA or
       I-DATA chunk's ``bufid``, the addresses of the packet carrying it, chunk
       type, TSN, stream identifier, ``U``, ``B``
       and ``E`` bits, stream sequence number or message identifier and FSN,
       payload protocol identifier and user data, built by
       :func:`pcapkit.toolkit.pcap.sctp_reassembly` or
       :func:`pcapkit.toolkit.pcapng.sctp_reassembly`.

   reasm.sctp.datagram
       Data structure for **reassembled SCTP user message** (element of
       :attr:`SCTP.datagram <pcapkit.foundation.reassembly.reassembly.Reassembly.datagram>`)
       is :class:`~pcapkit.foundation.reassembly.sctp.data.Datagram` --
       ``completed``, the original packet identifier, the packet numbers that
       built it, the message's stream, ordering and TSNs, ``payload``, the
       reassembled user data (a contiguous :obj:`bytes`, or -- under
       ``strict=True`` and an incomplete message -- a :obj:`tuple` of the runs
       actually received), and ``packet``, what
       :func:`~pcapkit.foundation.analysis.sctp.sctp_message` parses ``payload``
       to, on first read, as an IP or TCP datagram's is.

   reasm.sctp.buffer
       Data structure for internal buffering
       (:attr:`SCTP._buffer <pcapkit.foundation.reassembly.reassembly.Reassembly._buffer>`)
       is :class:`~pcapkit.foundation.reassembly.sctp.data.Buffer` -- every
       message under reconstruction for one
       :data:`~pcapkit.foundation.reassembly.sctp.data.BufferID` (one direction
       of one association, over every path), each held as a
       :class:`~pcapkit.foundation.reassembly.sctp.data.Fragment`: the DATA ones
       by each TSN they hold, the I-DATA ones by
       :data:`~pcapkit.foundation.reassembly.sctp.data.MessageID`.

Data Models
===========

.. module:: pcapkit.foundation.reassembly.sctp.data

.. currentmodule:: pcapkit.foundation.reassembly.sctp.reassembly

.. autoclass:: pcapkit.foundation.reassembly.sctp.data.Packet
   :members:
   :show-inheritance:

.. autodata:: pcapkit.foundation.reassembly.sctp.data.BufferID

.. autodata:: pcapkit.foundation.reassembly.sctp.data.MessageID

.. autoclass:: pcapkit.foundation.reassembly.sctp.data.DatagramID
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.sctp.data.Datagram
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.sctp.data.Fragment
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.sctp.data.Buffer
   :members:
   :show-inheritance:

Type Variables
==============

.. data:: _AT
   :module: pcapkit.foundation.reassembly.sctp.data
   :type: ipaddress.IPv4Address | ipaddress.IPv6Address

   IP address type.
