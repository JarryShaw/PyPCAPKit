SSL - Secure Sockets Layer
===============================

.. module:: pcapkit.protocols.application.ssl

:mod:`pcapkit.protocols.application.ssl` contains
:class:`~pcapkit.protocols.application.ssl.SSL` only,
which is a base class for Transport Layer Security (TLS) protocol
family [*]_, e.g.
:class:`~pcapkit.protocols.application.tls.TLS` and
:class:`~pcapkit.protocols.application.dtls.DTLS`.

The record-layer header -- a :class:`~pcapkit.const.tls.content_type.ContentType`,
a legacy record version, and a length -- is byte-identical in shape between
TLS (:rfc:`9846#section-5.1`) and DTLS (:rfc:`9147#section-4`); DTLS's own
divergence (an explicit epoch and sequence number in the record header, and
handshake-message fragmentation that a reliable TLS stream never needs) stays
entirely in :class:`~pcapkit.protocols.application.dtls.DTLS`. This base class
carries the logic the two genuinely share -- content-type dispatch, handshake-
message decoding, and the record-level validation that keeps dispatch from
accepting bytes that cannot be a genuine record.

.. versionadded:: 1.6.0

   :issue:`2437`.

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.application.ssl.SSL
   :no-members:
   :show-inheritance:

   .. automethod:: id

   .. automethod:: _validate_tls_record

   .. automethod:: _tls_content_is_cleartext

   .. automethod:: _read_tls_content
   .. automethod:: _make_tls_content

   .. automethod:: _read_tls_handshake_messages
   .. automethod:: _make_tls_handshake_messages

   .. automethod:: _read_tls_client_hello
   .. automethod:: _make_tls_client_hello

   .. automethod:: _read_tls_server_hello
   .. automethod:: _make_tls_server_hello

   .. automethod:: _read_tls_extensions
   .. automethod:: _make_tls_extensions

Data Models
-----------

.. module:: pcapkit.protocols.data.application.tls

.. autoclass:: pcapkit.protocols.data.application.tls.Handshake
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.application.tls.ClientHello
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.application.tls.ServerHello
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.application.tls.Extension
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.application.tls.Alert
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.application.tls.ChangeCipherSpec
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Transport_Layer_Security
