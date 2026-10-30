TLS/SSL - Transport Layer Security
========================================

.. module:: pcapkit.protocols.application.tls

:mod:`pcapkit.protocols.application.tls` contains
:class:`~pcapkit.protocols.application.tls.TLS` only, which implements an
extractor for Transport Layer Security (TLS) [*]_ -- TLS 1.2 (:rfc:`5246`) and
TLS 1.3 (:rfc:`9846`, which obsoletes :rfc:`8446`) -- at the record layer, plus
handshake message TYPE-level framing.

Decoded Fields
--------------

* The record header -- content type, legacy version, length -- in full,
  regardless of encryption: this part is always in the clear.
* For a **cleartext** ``handshake``, ``alert``, or ``change_cipher_spec``
  record -- i.e. one that has not yet started carrying ciphertext, decided
  per-record by
  :meth:`SSL._tls_content_is_cleartext <pcapkit.protocols.application.ssl.SSL._tls_content_is_cleartext>`:

  * ``ClientHello``/``ServerHello`` down to their cipher suite(s),
    compression method(s), and extension list, TYPE+LENGTH framed (extension
    bodies are not decoded).
  * Every other handshake message (``Certificate``, ``ServerKeyExchange``,
    ``ClientKeyExchange``, etc.) at the message-type/length level only: its
    body is kept undecoded. ``Finished`` is always ciphertext -- there is no
    cleartext ``Finished`` -- so it is never decoded even at this level and
    always stays opaque bytes.
  * ``Alert`` and ``ChangeCipherSpec`` records in full.

* An **encrypted** ``handshake``, ``alert``, or ``change_cipher_spec``
  record -- which is the common case for TLS 1.2 traffic once the handshake
  completes -- plus ``application_data`` and every other content type, as
  opaque :obj:`bytes`.

The record header is visible on the wire regardless of encryption, but the
record *content* is not: once the handshake has derived keys, a
``handshake``/``alert``/``change_cipher_spec`` record may carry ciphertext
indistinguishable at the header level from its cleartext counterpart, and
only the content stays undecoded in that case -- see
:meth:`SSL._tls_content_is_cleartext <pcapkit.protocols.application.ssl.SSL._tls_content_is_cleartext>`
for how each case is told apart. Decrypting ``application_data`` is out of
scope.

Known Limitation
-----------------

**A record split across two TCP segments is not reassembled**, and so decodes
as :class:`~pcapkit.protocols.misc.raw.Raw` rather than as the record it is the
start of. A record may be up to 16 KiB against a typical 1460-octet MSS, so
this is routine rather than rare. See
:meth:`SSL._validate_tls_record <pcapkit.protocols.application.ssl.SSL._validate_tls_record>`
for why rejecting such a fragment is the honest answer at this layer.

.. versionadded:: 1.6.0

   :issue:`2437`.

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.application.tls.TLS
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: length

   .. automethod:: read
   .. automethod:: make

   .. automethod:: __length_hint__

   .. automethod:: _make_data

.. autoclass:: pcapkit.protocols.application.tls.SSLv3
   :no-members:
   :show-inheritance:

   .. automethod:: id

Header Schema
-------------

.. module:: pcapkit.protocols.schema.application.tls

.. autoclass:: pcapkit.protocols.schema.application.tls.TLS
   :members:
   :show-inheritance:

Data Model
----------

.. currentmodule:: pcapkit.protocols.data.application.tls

.. autoclass:: pcapkit.protocols.data.application.tls.TLS
   :members:
   :show-inheritance:

See :doc:`ssl` for ``ClientHello``, ``ServerHello``, ``Handshake``, ``Extension``,
``Alert`` and ``ChangeCipherSpec``, shared verbatim with
:class:`~pcapkit.protocols.application.dtls.DTLS`.

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Transport_Layer_Security
