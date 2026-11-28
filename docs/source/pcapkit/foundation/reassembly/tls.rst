=====================
TLS Record Reassembly
=====================

.. module:: pcapkit.foundation.reassembly.tls
.. module:: pcapkit.foundation.reassembly.tls.reassembly

:mod:`pcapkit.foundation.reassembly.tls.reassembly` contains
:class:`~pcapkit.foundation.reassembly.tls.reassembly.TLS` only, which reconstructs
the TLS records of a TCP stream, a record split across segments included
(:rfc:`9846#section-5`).

.. versionadded:: 1.9.0

.. autoclass:: pcapkit.foundation.reassembly.tls.reassembly.TLS
   :no-members:
   :show-inheritance:

   .. rubric:: Defaults

   .. autoattribute:: __protocol_name__
   .. autoattribute:: __protocol_type__

   .. rubric:: Methods

   .. automethod:: reassembly
   .. automethod:: submit

   .. rubric:: Utilities

   .. automethod:: _read_header
   .. automethod:: _opens_record
   .. automethod:: _close_runs
   .. automethod:: _hold_segment
   .. automethod:: _hold_octets
   .. automethod:: _cut_records
   .. automethod:: _stream_whole
   .. automethod:: _make_datagram

Algorithm
=========

.. seealso::

   A record over TCP is delimited by its header alone (:rfc:`9846#section-5.1`), and
   the stream is the segments' octets in sequence order (:rfc:`9293#section-3.4`).

Each direction of a connection is a buffer, which holds the octets past the next
record's boundary as runs in sequence order. A segment's new octets join the runs,
and the records whole from the boundary on are cut off and reported:

.. mermaid::

   flowchart TD
       SEG["a segment, as TCP reassembly records it"]
       SYN{"SYN?"}
       OPEN["a fresh buffer, its boundary<br/>the octet after the SYN"]
       HAS{"a buffer?"}
       SYNC{"its payload opens<br/>a record header?"}
       DROP["ignored"]
       HOLD["hold the octets no earlier<br/>segment brought"]
       HEAD{"a header held<br/>at the boundary?"}
       BAD{"it opens a record?"}
       GONE["the buffer is dropped"]
       WHOLE{"the record whole?"}
       CUT["report it COMPLETE, and<br/>move the boundary past it"]
       END{"an RST, or a FIN with<br/>every octet before it?"}
       CLOSE["submit the buffer, and<br/>close the stream"]
       WAIT["wait for the next segment"]

       SEG --> SYN
       SYN -->|yes| OPEN --> HOLD
       SYN -->|no| HAS
       HAS -->|open| HOLD
       HAS -->|closed| DROP
       HAS -->|none| SYNC
       SYNC -->|no| DROP
       SYNC -->|"yes: a buffer from it"| HOLD
       HOLD --> HEAD
       HEAD -->|no| END
       HEAD -->|yes| BAD
       BAD -->|no| GONE
       BAD -->|yes| WHOLE
       WHOLE -->|yes| CUT --> HEAD
       WHOLE -->|no| END
       END -->|yes| CLOSE
       END -->|no| WAIT

Without the SYN, the boundary a buffer opens at is a guess, which the length bound of
:meth:`TLS.record_header <pcapkit.protocols.application.tls.protocol.TLS.record_header>`
narrows but cannot make safe; the class's warning above says what it rules out.

:meth:`~pcapkit.foundation.reassembly.tls.reassembly.TLS.submit` reports what a buffer
still holds, record by record from the boundary: one whose fragment is whole
:attr:`~pcapkit.foundation.reassembly.data.Completion.COMPLETE`, and one with a hole
:attr:`~pcapkit.foundation.reassembly.data.Completion.PARTIAL`, or
:attr:`~pcapkit.foundation.reassembly.data.Completion.TIMEOUT` once expired. It stops at
the first hole a header lies in.

Terminology
===========

The reassembly is fed :term:`reasm.tcp.packet`, TCP reassembly's record of a segment.

.. glossary::

   reasm.tls.datagram
       Data structure for **reassembled TLS record** (element of
       :attr:`TLS.datagram <pcapkit.foundation.reassembly.reassembly.Reassembly.datagram>`)
       is :class:`~pcapkit.foundation.reassembly.tls.data.Datagram` -- ``completed``,
       the original record identifier, the packet numbers that carried it, the
       record header's ``content_type``, ``version`` and ``length``, ``fragment``,
       the reassembled fragment (a contiguous :obj:`bytes`, or -- under
       ``strict=True`` and an incomplete record -- a :obj:`tuple` of the octet runs
       actually received), and ``packet``, what
       :func:`~pcapkit.foundation.analysis.tls.tls_record` decodes the record to.
       ``packet`` is decoded on first read, as a DTLS message's is, and is
       :data:`None` for an incomplete record.

   reasm.tls.buffer
       Data structure for internal buffering
       (:attr:`TLS._buffer <pcapkit.foundation.reassembly.reassembly.Reassembly._buffer>`)
       is :class:`~pcapkit.foundation.reassembly.tls.data.Buffer` -- one direction of
       a TCP connection, keyed by its
       :data:`~pcapkit.foundation.reassembly.tls.data.BufferID`: the next record's
       boundary, the octets held past it as
       :class:`~pcapkit.foundation.reassembly.tls.data.Run` objects, the octets each
       packet added, and where the stream ends.

Data Models
===========

.. module:: pcapkit.foundation.reassembly.tls.data

.. currentmodule:: pcapkit.foundation.reassembly.tls.reassembly

.. autodata:: pcapkit.foundation.reassembly.tls.data.BufferID

.. autoclass:: pcapkit.foundation.reassembly.tls.data.DatagramID
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.tls.data.Datagram
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.tls.data.Run
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.tls.data.Buffer
   :members:
   :show-inheritance:

Type Variables
==============

.. data:: _AT
   :module: pcapkit.foundation.reassembly.tls.data
   :type: ipaddress.IPv4Address | ipaddress.IPv6Address

   IP address type.
