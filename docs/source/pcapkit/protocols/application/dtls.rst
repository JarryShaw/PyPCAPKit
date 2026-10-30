DTLS - Datagram Transport Layer Security
==============================================

.. module:: pcapkit.protocols.application.dtls

:mod:`pcapkit.protocols.application.dtls` contains
:class:`~pcapkit.protocols.application.dtls.DTLS` only, which implements an
extractor for Datagram Transport Layer Security (DTLS) [*]_ -- DTLS 1.2
(:rfc:`6347`) and DTLS 1.3 (:rfc:`9147`) -- at the record layer, plus the
epoch/sequence-number fields and the handshake-message fragment header that
set DTLS apart from :class:`~pcapkit.protocols.application.tls.TLS`, whose
reliable, ordered transport needs neither.

Known Limitation
-----------------

**A handshake message split across several DTLS records is not reassembled.**
DTLS fragments a handshake message when it does not fit in one datagram
(:rfc:`6347#section-4.2.3`); reassembling that would need
:class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` keyed on the
UDP 5-tuple plus epoch, which is substantial enough that it did not fit
cleanly alongside this dissector in the same PR (:issue:`2440`). A fragment's
:attr:`~pcapkit.protocols.data.application.dtls.DTLSHandshake.is_fragmented`
says whether this is the case; such a message's
:attr:`~pcapkit.protocols.data.application.dtls.DTLSHandshake.body` is kept
as that one fragment's raw octets rather than attempted as a (necessarily
wrong, since only a slice of it is present) decode. An *unfragmented* message
-- ``fragment_offset == 0`` and ``fragment_length == length`` -- decodes
exactly as :class:`~pcapkit.protocols.application.tls.TLS` would, which is
the common case: a ``ClientHello`` or ``ServerHello`` that fits one datagram
never fragments.

.. versionadded:: 1.6.0

   :issue:`2437`.

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.application.dtls.DTLS
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: length

   .. automethod:: read
   .. automethod:: make

   .. automethod:: __length_hint__

   .. automethod:: _make_data

Header Schema
-------------

.. module:: pcapkit.protocols.schema.application.dtls

.. autoclass:: pcapkit.protocols.schema.application.dtls.DTLS
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.data.application.dtls

.. autoclass:: pcapkit.protocols.data.application.dtls.DTLS
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.application.dtls.DTLSHandshake
   :members:
   :show-inheritance:

See :doc:`ssl` for ``ClientHello``, ``ServerHello``, ``Extension``, ``Alert``
and ``ChangeCipherSpec``, shared verbatim with
:class:`~pcapkit.protocols.application.tls.TLS`.

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Datagram_Transport_Layer_Security
