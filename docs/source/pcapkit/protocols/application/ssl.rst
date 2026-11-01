SSL - Secure Sockets Layer
===============================

.. module:: pcapkit.protocols.application.ssl

:mod:`pcapkit.protocols.application.ssl` contains
:class:`~pcapkit.protocols.application.ssl.SSL` only,
which is the umbrella base class for the Secure Sockets Layer protocol
family [*]_ -- the SSL versions, Transport Layer Security and Datagram TLS:

* :class:`~pcapkit.protocols.application.sslv2.SSLv2` -- SSL 2.0, whose
  record layer shares no wire format with the others;
* :class:`~pcapkit.protocols.application.tls.TLS` -- SSLv3 and TLS 1.0
  through TLS 1.3, with :class:`~pcapkit.protocols.application.tls.SSLv3` as
  its thin subclass for explicit construction;
* :class:`~pcapkit.protocols.application.dtls.DTLS` -- DTLS 1.0, 1.2 and 1.3.

:meth:`SSL.id <pcapkit.protocols.application.ssl.SSL.id>` lists the direct
concrete subclasses, so a lookup keyed on ``SSL`` matches any of them.

The TLS record header (:rfc:`9846#section-5.1`) is a
:class:`~pcapkit.const.tls.content_type.ContentType`, a legacy record version
and a length. The DTLS ``DTLSPlaintext`` header (:rfc:`9147#section-4`) has
the same fields plus an epoch and a 48-bit sequence number *between* the
version and the length, and DTLS adds a fragment header to each handshake
message. Each record header is declared in its subclass's own schema, and
:class:`~pcapkit.protocols.application.dtls.DTLS` reads the epoch and sequence
number. This base class carries the logic the two share -- content-type
dispatch, handshake-message decoding (including the DTLS fragment header), and
the record-level validation that keeps dispatch from accepting bytes that
cannot be a genuine record.

.. versionadded:: 1.6.0

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
